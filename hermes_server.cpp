// Hermes Server — full spec implementation
// Supports: optical-DH key exchange, multiple keys per switch (330-350),
//           8 opcodes (Add/And/Xor/Or/Sub-ab/Sub-ba/Rot-axb/Rot-bxa),
//           LFSR-driven key reuse, replay protection (seq/ts/nonce),
//           and VERIFY that replays the exact accumulator computation.
//
// Wire protocol (newline-delimited text):
//
//   DH_INIT <switch_id> <G> <P> <num_keys> <K_a_0> <K_a_1> ... <K_a_N-1>
//     -> DH_RESP <num_keys> <K_b_0> ... <K_b_N-1> <op_0> ... <op_N-1> <lfsr_seed>
//
//   VERIFY <flow_id> <hop_count> <acc_final> <seq> <timestamp_ms> <nonce>
//     -> RESULT ACCEPT|REJECT
//
//   DH_KEY <switch_id> <G> <P> <num_keys> <K_a_0> ... <K_a_N-1>
//     -> DH_KEY_RESP <num_keys> <K_b_0> ... <K_b_N-1> <op_0> ... <op_N-1> <lfsr_seed>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

static constexpr int    NUM_KEYS_MIN  = 330;
static constexpr int    NUM_KEYS_MAX  = 350;
static constexpr int    NUM_OPS       = 8;
// Replay window: reject any (flow,seq) pair we've already seen
static constexpr std::uint64_t MAX_CLOCK_SKEW_MS = 30000;

enum Opcode : uint8_t {
    OP_ADD    = 0b000,
    OP_ROT_BA = 0b001,
    OP_ROT_AB = 0b010,
    OP_AND    = 0b011,
    OP_OR     = 0b100,
    OP_SUB_BA = 0b101,
    OP_SUB_AB = 0b110,
    OP_XOR    = 0b111,
};

// Rotation:
//   b is split into top-3 bits (rotate amount, max 8 for 32-bit values
//   but we use top-5 for 32-bit: amount = b >> 27, add_val = b & 0x07FFFFFF)
//   a rotated left by amount, then add add_val mod 2^32
static std::uint32_t rot_left(std::uint32_t a, std::uint32_t b) {
    std::uint32_t amount  = (b >> 27) & 0x1f;   // top 5 bits → 0..31
    std::uint32_t add_val = b & 0x07FFFFFFu;
    std::uint32_t rotated = (amount == 0) ? a : ((a << amount) | (a >> (32 - amount)));
    return (rotated + add_val) & 0xffffffffu;
}

static std::uint32_t apply_op(Opcode op, std::uint32_t key, std::uint32_t acc) {
    switch (op) {
        case OP_ADD:    return (acc + key) & 0xffffffffu;
        case OP_AND:    return acc & key;
        case OP_XOR:    return acc ^ key;
        case OP_OR:     return acc | key;
        case OP_SUB_AB: return (acc - key) & 0xffffffffu;   // a - b
        case OP_SUB_BA: return (key - acc) & 0xffffffffu;   // b - a
        case OP_ROT_AB: return rot_left(acc, key);           // a rot b
        case OP_ROT_BA: return rot_left(key, acc);           // b rot a
    }
    return acc;
}

// ─────────────────────────────────────────────────────────────────────────────
// LFSR (32-bit Galois LFSR, taps 32,22,2,1)
// Generates the sequence of key indices for reuse phase.
// ─────────────────────────────────────────────────────────────────────────────
static std::uint32_t lfsr_next(std::uint32_t state) {
    // Galois LFSR with primitive polynomial x^32+x^22+x^2+x+1
    if (state & 1u) {
        state = (state >> 1) ^ 0xB4BCD35Cu;
    } else {
        state >>= 1;
    }
    return state;
}

// Return the next key index (0..num_keys-1) from the LFSR state.
static std::uint16_t lfsr_key_index(std::uint32_t state, std::uint16_t num_keys) {
    return static_cast<std::uint16_t>(state % num_keys);
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-switch state
// ─────────────────────────────────────────────────────────────────────────────
struct SwitchState {
    std::string  id;
    std::uint16_t num_keys = 0;
    std::vector<std::uint32_t> shared_keys; // derived shared keys S[i]
    std::vector<Opcode>        opcodes;     // one per key
    std::uint32_t lfsr_seed = 0;
    std::uint32_t lfsr_state = 0;          // current LFSR state for reuse
    std::uint16_t key_index  = 0;          // current index into shared_keys
    bool initial_phase = true;             // true while iterating 0..num_keys-1
};

// ─────────────────────────────────────────────────────────────────────────────
// Global state (protected by mutex for multi-connection support)
// ─────────────────────────────────────────────────────────────────────────────
static std::map<std::string, SwitchState> g_switches;
static std::mutex g_mu;

// Replay protection: track (flow_id, seq) pairs we've already verified
static std::map<std::uint32_t, std::uint64_t> g_last_seq;  // flow_id -> highest seen seq
// Per-flow registered paths: flow_id -> ordered list of switch ids
static std::map<std::uint32_t, std::vector<std::string>> g_flow_paths;

// ─────────────────────────────────────────────────────────────────────────────
// DH helpers (optical method from DiffieHellman.pdf §2.2)
// ─────────────────────────────────────────────────────────────────────────────
//   Public key: K_B = (G ^ P) & B     (switch sends to Hermes)
//               K_A = (G ^ P) & A     (Hermes sends back)
//   Shared key: S   = (K_B & A) ^ P   (same as (K_A & B) ^ P)
static std::uint32_t dh_shared(std::uint32_t K_B, std::uint32_t A, std::uint32_t P) {
    return (K_B & A) ^ P;
}
static std::uint32_t dh_public(std::uint32_t G, std::uint32_t P, std::uint32_t A) {
    return ((G ^ P) & A);
}

// ─────────────────────────────────────────────────────────────────────────────
// Process DH_INIT or DH_KEY:
//   Reads G, P, num_keys, Ka[num_keys] from the switch.
//   Generates Hermes' secrets A[i] for each key.
//   Computes shared S[i] and Hermes public K_A[i] for each key.
//   Assigns random opcodes and a random LFSR seed.
//   Stores state; returns the response string.
// ─────────────────────────────────────────────────────────────────────────────
static std::string handle_dh(const std::string& switch_id,
                              std::istringstream& iss,
                              std::mt19937& rng,
                              bool is_regen) {
    std::uint32_t G, P;
    iss >> G >> P;

    std::uniform_int_distribution<int> dist_num_keys(NUM_KEYS_MIN, NUM_KEYS_MAX);
    std::uint16_t num_keys = static_cast<std::uint16_t>(dist_num_keys(rng));

    std::vector<std::uint32_t> Ka(NUM_KEYS_MAX);
    for (int i = 0; i < NUM_KEYS_MAX; ++i) {
        if (!(iss >> Ka[i])) {
            return "ERR missing padded Ka values\n";
        }
    }

    std::uniform_int_distribution<std::uint32_t> dist32(1, 0xfffffffeU);
    std::uniform_int_distribution<int>           dist_op(0, NUM_OPS - 1);

    // Map int → Opcode
    static const Opcode OP_TABLE[NUM_OPS] = {
        OP_ADD, OP_ROT_BA, OP_ROT_AB, OP_AND,
        OP_OR,  OP_SUB_BA, OP_SUB_AB, OP_XOR
    };

    SwitchState st;
    st.id = switch_id;
    st.shared_keys.resize(NUM_KEYS_MAX);
    st.opcodes.resize(NUM_KEYS_MAX);
    st.num_keys = num_keys;

    std::vector<std::uint32_t> Kb(NUM_KEYS_MAX, 0);
    for (int i = 0; i < num_keys; ++i) {
        std::uint32_t A_i = dist32(rng);
        st.shared_keys[i] = dh_shared(Ka[i], A_i, P);
        Kb[i]             = dh_public(G, P, A_i);
        st.opcodes[i]     = OP_TABLE[dist_op(rng)];
    }

    // LFSR seed: non-zero random
    do { st.lfsr_seed = dist32(rng); } while (st.lfsr_seed == 0);
    st.lfsr_state   = st.lfsr_seed;
    st.key_index    = 0;
    st.initial_phase = true;

    // Log
    std::cout << "[Hermes] " << (is_regen ? "DH_KEY" : "DH_INIT") << " from " << switch_id
              << ": num_keys=" << num_keys << " G=0x" << std::hex << G
              << " P=0x" << P << std::dec << "\n";
    for (int i = 0; i < num_keys; ++i) {
        std::cout << "  key[" << i << "]: Ka=0x" << std::hex << Ka[i]
                  << " Kb=0x" << Kb[i]
                  << " S=0x" << st.shared_keys[i]
                  << " op=" << (int)st.opcodes[i] << std::dec << "\n";
    }
    std::cout << "  lfsr_seed=0x" << std::hex << st.lfsr_seed << std::dec << "\n";

    {
        std::lock_guard<std::mutex> lk(g_mu);
        g_switches[switch_id] = st;
    }

    std::ostringstream oss;
    oss << (is_regen ? "DH_KEY_RESP" : "DH_RESP") << " " << num_keys;

    for (int i = 0; i < NUM_KEYS_MAX; ++i) {
        oss << " " << Kb[i];
    }

    for (int i = 0; i < NUM_KEYS_MAX; ++i) {
        int op = (i < num_keys) ? static_cast<int>(st.opcodes[i]) : 0;
        oss << " " << op;
    }

    oss << " " << st.lfsr_seed << "\n";
    return oss.str();
    }

// ─────────────────────────────────────────────────────────────────────────────
// VERIFY handler
//   VERIFY <flow_id> <hop_count> <acc_final> <seq> <timestamp_ms> <nonce>
//   Path is always s1→s2→s3 for this 3-switch topology.
//   Hermes replays the exact accumulator computation using its stored keys+ops.
// ─────────────────────────────────────────────────────────────────────────────
static std::string handle_verify(std::istringstream& iss) {
    std::uint32_t flow_id, hop_count, acc_final;
    std::uint64_t seq, timestamp_ms, nonce;
    iss >> flow_id >> hop_count >> acc_final >> seq >> timestamp_ms >> nonce;

    // ── Replay protection ────────────────────────────────────────────────────
    auto now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    if (timestamp_ms + MAX_CLOCK_SKEW_MS < now_ms ||
        timestamp_ms > now_ms + MAX_CLOCK_SKEW_MS) {
        std::cout << "[Hermes] VERIFY flow=" << flow_id
                  << " REJECT (timestamp out of window)\n";
        return "RESULT REJECT\n";
    }

    {
        std::lock_guard<std::mutex> lk(g_mu);
        auto it = g_last_seq.find(flow_id);
        if (it != g_last_seq.end() && seq <= it->second) {
            std::cout << "[Hermes] VERIFY flow=" << flow_id
                      << " REJECT (replay: seq=" << seq
                      << " last_seen=" << it->second << ")\n";
            return "RESULT REJECT\n";
        }
        g_last_seq[flow_id] = seq;
    }

    // ── Accumulator replay ───────────────────────────────────────────────────
    std::lock_guard<std::mutex> lk(g_mu);
    // Look up the registered path for this flow
    auto path_it = g_flow_paths.find(flow_id);
    if (path_it == g_flow_paths.end()) {
        std::cout << "[Hermes] VERIFY flow=" << flow_id
                  << " REJECT (no path registered)\n";
        return "RESULT REJECT\n";
    }
    const std::vector<std::string>& PATH = path_it->second;

    std::uint32_t expected = 0; // initial acc = 0


    for (std::uint32_t hop = 0; hop < hop_count && hop < PATH.size(); ++hop) {
        const std::string& sw_id = PATH[hop];
        auto it = g_switches.find(sw_id);
        if (it == g_switches.end()) {
            std::cout << "[Hermes] VERIFY: no state for " << sw_id << " → REJECT\n";
            return "RESULT REJECT\n";
        }
        SwitchState& st = it->second;

        // Determine which key index this switch is using right now
        std::uint16_t idx = st.key_index;
        Opcode        op  = st.opcodes[idx];
        std::uint32_t key = st.shared_keys[idx];

        expected = apply_op(op, key, expected);

        // Advance key index (mirror what the switch does)
        if (st.initial_phase) {
            st.key_index++;
            if (st.key_index >= st.num_keys) {
                st.initial_phase = false;
                st.lfsr_state    = st.lfsr_seed;
                st.key_index     = lfsr_key_index(st.lfsr_state, st.num_keys);
            }
        } else {
            st.lfsr_state = lfsr_next(st.lfsr_state);
            st.key_index  = lfsr_key_index(st.lfsr_state, st.num_keys);
        }
    }

    bool ok = (expected == acc_final);
    std::cout << "[Hermes] VERIFY flow=" << flow_id
              << " hops=" << hop_count
              << " acc=" << acc_final
              << " expected=" << expected
              << " seq=" << seq
              << " nonce=0x" << std::hex << nonce << std::dec
              << " -> " << (ok ? "ACCEPT" : "REJECT") << "\n";

    return ok ? "RESULT ACCEPT\n" : "RESULT REJECT\n";
}
static SSL_CTX* create_server_tls_context(const char* cert_file,
                                          const char* key_file,
                                          const char* ca_file) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        std::exit(1);
    }

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        std::exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        std::exit(1);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "[Hermes] Server private key does not match certificate\n";
        std::exit(1);
    }

    if (SSL_CTX_load_verify_locations(ctx, ca_file, nullptr) <= 0) {
        ERR_print_errors_fp(stderr);
        std::exit(1);
    }

    SSL_CTX_set_verify(ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       nullptr);

    SSL_CTX_set_verify_depth(ctx, 2);

    return ctx;
}

static void handle_connection(SSL* ssl, int fd, std::mt19937& rng) {
    char tmp[4096];

    auto read_line = [&](std::string& out) -> bool {
        out.clear();

        while (true) {
            int n = SSL_read(ssl, tmp, sizeof(tmp));

            if (n <= 0) {
                int err = SSL_get_error(ssl, n);

                if (err != SSL_ERROR_ZERO_RETURN) {
                    ERR_print_errors_fp(stderr);
                }

                return false;
            }

            for (int i = 0; i < n; ++i) {
                char c = tmp[i];

                if (c == '\n') {
                    return true;
                }

                out.push_back(c);
            }
        }
    };

    auto send_str = [&](const std::string& s) {
        int written = SSL_write(ssl, s.data(), static_cast<int>(s.size()));

        if (written <= 0) {
            ERR_print_errors_fp(stderr);
        }
    };

    while (true) {
        std::string line;

        if (!read_line(line)) {
            break;
        }

        if (line.empty()) {
            continue;
        }

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "PATH_REGISTER") {
            uint32_t flow_id, hop_count;
            iss >> flow_id >> hop_count;

            std::vector<std::string> path(hop_count);

            for (uint32_t i = 0; i < hop_count; ++i) {
                iss >> path[i];
            }

            {
                std::lock_guard<std::mutex> lk(g_mu);
                g_flow_paths[flow_id] = path;
            }

            std::cout << "[Hermes] PATH_REGISTER flow=" << flow_id << " path=";

            for (const auto& sw : path) {
                std::cout << sw << " ";
            }

            std::cout << "\n";

            std::ostringstream oss;
            oss << "PATH_ACK " << flow_id << "\n";
            send_str(oss.str());

        } else if (cmd == "DH_INIT") {
            std::string sw_id;
            iss >> sw_id;

            send_str(handle_dh(sw_id, iss, rng, false));

        } else if (cmd == "DH_KEY") {
            std::string sw_id;
            iss >> sw_id;

            send_str(handle_dh(sw_id, iss, rng, true));

        } else if (cmd == "VERIFY") {
            send_str(handle_verify(iss));

        } else if (cmd == "QUIT") {
            break;

        } else {
            send_str("ERR unknown command\n");
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    ::close(fd);

    std::cout << "[Hermes] TLS connection closed\n";
}

int main(int argc, char** argv) {
    int port = 5555;

    const char* server_cert = "certs/server.crt";
    const char* server_key  = "certs/server.key";
    const char* ca_cert     = "certs/ca.crt";

    if (argc > 1) {
        port = std::atoi(argv[1]);
    }

    if (argc > 2) {
        server_cert = argv[2];
    }

    if (argc > 3) {
        server_key = argv[3];
    }

    if (argc > 4) {
        ca_cert = argv[4];
    }

    SSL_CTX* tls_ctx = create_server_tls_context(server_cert, server_key, ca_cert);

    int srv = ::socket(AF_INET, SOCK_STREAM, 0);

    if (srv < 0) {
        perror("socket");
        SSL_CTX_free(tls_ctx);
        return 1;
    }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (::bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind");
        SSL_CTX_free(tls_ctx);
        return 1;
    }

    if (::listen(srv, 16) < 0) {
        perror("listen");
        SSL_CTX_free(tls_ctx);
        return 1;
    }

    std::cout << "[Hermes] mTLS server listening on port " << port << "\n";
    std::cout << "[Hermes] Server cert: " << server_cert << "\n";
    std::cout << "[Hermes] Server key:  " << server_key << "\n";
    std::cout << "[Hermes] CA cert:     " << ca_cert << "\n";

    std::mt19937 rng(std::random_device{}());

    while (true) {
        sockaddr_in cli{};
        socklen_t clilen = sizeof(cli);

        int fd = ::accept(srv, reinterpret_cast<sockaddr*>(&cli), &clilen);

        if (fd < 0) {
            perror("accept");
            continue;
        }

        std::cout << "[Hermes] New TCP connection from "
                  << inet_ntoa(cli.sin_addr) << "\n";

        SSL* ssl = SSL_new(tls_ctx);

        if (!ssl) {
            ERR_print_errors_fp(stderr);
            ::close(fd);
            continue;
        }

        SSL_set_fd(ssl, fd);

        if (SSL_accept(ssl) <= 0) {
            std::cerr << "[Hermes] TLS handshake failed\n";
            ERR_print_errors_fp(stderr);

            SSL_free(ssl);
            ::close(fd);
            continue;
        }

        X509* client_cert = SSL_get_peer_certificate(ssl);

        if (!client_cert) {
            std::cerr << "[Hermes] No client certificate presented\n";

            SSL_shutdown(ssl);
            SSL_free(ssl);
            ::close(fd);
            continue;
        }

        char* subject = X509_NAME_oneline(X509_get_subject_name(client_cert), nullptr, 0);

        std::cout << "[Hermes] Client certificate subject: "
                  << (subject ? subject : "(unknown)") << "\n";

        OPENSSL_free(subject);
        X509_free(client_cert);

        handle_connection(ssl, fd, rng);
    }

    ::close(srv);
    SSL_CTX_free(tls_ctx);
    EVP_cleanup();

    return 0;
}