// hermes_line.p4
// v.12.02
//
// Message types:
//   0 = MSG_DATA    : normal data packet with accumulator
//   1 = MSG_VERIFY  : sent by h2 to Hermes (handled in controller)
//   2 = MSG_RESPONSE: Hermes reply (handled in controller)
//   3 = MSG_DH_REQ  : DH key-generation request (switch → Hermes via digest)
//   4 = MSG_DH_RESP : DH response (controller installs result into tables)
//
// Accumulator update (8 opcodes, 3-bit):
//   000 Add    001 Rot(b rot a)    010 Rot(a rot b)    011 And
//   100 Or     101 Sub(b-a)        110 Sub(a-b)         111 Xor
//
// Rotation:  a rotl (b>>27)  then  + (b & 0x07FFFFFF)
//
// Key lifecycle:
//   - Switches iterate key_index 0..num_keys-1 on the first pass
//   - Once exhausted, LFSR(lfsr_seed) drives the next index
//   - key_index and lfsr_state are stored in registers
//
// Replay protection fields embedded in hermes_data_t:
//   seq (32-bit), timestamp_ms (48-bit), nonce (32-bit)

#include <v1model.p4>

// ─────────────────────────────────────────────────────────────────────────────
// EtherTypes
// ─────────────────────────────────────────────────────────────────────────────
const bit<16> ETHERTYPE_HERMES = 0xD1F1;

// ─────────────────────────────────────────────────────────────────────────────
// Message-type constants
// ─────────────────────────────────────────────────────────────────────────────
const bit<8> MSG_DATA     = 0;
const bit<8> MSG_VERIFY   = 1;
const bit<8> MSG_RESPONSE = 2;
const bit<8> MSG_DH_REQ   = 3;
const bit<8> MSG_DH_RESP  = 4;

// ─────────────────────────────────────────────────────────────────────────────
// Opcode constants (3-bit values, stored as bit<8> in tables)
// ─────────────────────────────────────────────────────────────────────────────
const bit<8> OP_ADD    = 0;   // 000
const bit<8> OP_ROT_BA = 1;   // 001
const bit<8> OP_ROT_AB = 2;   // 010
const bit<8> OP_AND    = 3;   // 011
const bit<8> OP_OR     = 4;   // 100
const bit<8> OP_SUB_BA = 5;   // 101
const bit<8> OP_SUB_AB = 6;   // 110
const bit<8> OP_XOR    = 7;   // 111

// ─────────────────────────────────────────────────────────────────────────────
// Headers
// ─────────────────────────────────────────────────────────────────────────────

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// Standard base header — present on every Hermes packet
header hermes_base_t {
    bit<8>  msg_type;   // MSG_DATA / MSG_VERIFY / MSG_RESPONSE / MSG_DH_REQ / MSG_DH_RESP
    bit<8>  version;    // protocol version = 1
    bit<16> length;     // total packet length (informational)
}

// Data packet — forwarded hop-by-hop, accumulator updated at each switch
header hermes_data_t {
    bit<32> accumulator;    // updated at each hop by apply_op(opcode, key, acc)
    bit<16> hop_count;      // counts hops for debugging / verification
    bit<32> flow_id;        // identifies path/session
    bit<32> seq;            // monotonically increasing sequence number
    bit<48> timestamp_ms;   // sender timestamp in milliseconds since epoch
    bit<32> nonce;          // random per-packet nonce
}

// Verify packet — emitted by h2 toward Hermes (handled by controller digest)
header hermes_verify_t {
    bit<32> accumulator_final;
    bit<32> flow_id;
    bit<16> hop_count;
    bit<32> seq;
    bit<48> timestamp_ms;
    bit<32> nonce;
}

header hermes_response_t {
    bit<8>  result;     // 0 = REJECT, 1 = ACCEPT
    bit<32> flow_id;
}

struct headers_t {
    ethernet_t      eth;
    hermes_base_t   base;
    hermes_data_t   data;
    hermes_verify_t verify;
    hermes_response_t response;
}

// ─────────────────────────────────────────────────────────────────────────────
// Metadata
// ─────────────────────────────────────────────────────────────────────────────
struct metadata_t {
    bit<32> current_key;       // key loaded from share_table for this hop
    bit<8>  current_opcode;    // opcode for this key (from opcode_table)
    bit<32> acc_after;         // accumulator value after applying this hop's operation
    bit<1>  trigger_dh;        // 1 if key pool exhausted → trigger DH regen digest
    bit<32> lfsr_state;        // loaded from register
    bit<16> key_index_meta;
    bit<16> next_key_index;    // computed next index
}

// ─────────────────────────────────────────────────────────────────────────────
// Digest sent to the control plane at the final hop (or on DH regen trigger)
// ─────────────────────────────────────────────────────────────────────────────
struct hermes_digest_t {
    bit<32> flow_id;
    bit<16> hop_count;
    bit<32> accumulator;
    bit<32> seq;
    bit<48> timestamp_ms;
    bit<32> nonce;
    bit<1>  trigger_dh;   // 1 → controller should do DH_KEY with Hermes
    bit<32> hop_idx;      // which switch triggered DH regen (0=s1,1=s2,2=s3)
}

// ─────────────────────────────────────────────────────────────────────────────
// Registers (indexed by hop_idx: 0=s1, 1=s2, 2=s3)
// ─────────────────────────────────────────────────────────────────────────────

// Current key index for each switch
register<bit<32>>(3) reg_key_index;

// LFSR state for each switch (0 = still in initial sequential phase)
register<bit<32>>(3) reg_lfsr_state;

// Packet counter for refresh triggering
register<bit<32>>(3) reg_pkt_counter;

// ─────────────────────────────────────────────────────────────────────────────
// Parser
// ─────────────────────────────────────────────────────────────────────────────
parser MyParser(packet_in pkt,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t smeta)
{
    state start {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
            ETHERTYPE_HERMES: parse_base;
            default: accept;
        }
    }

    state parse_base {
        pkt.extract(hdr.base);
        transition select(hdr.base.msg_type) {
            MSG_DATA:     parse_data;
            MSG_VERIFY:   parse_verify;
            MSG_RESPONSE: parse_response;
            default:      accept;
        }
    }

    state parse_data {
        pkt.extract(hdr.data);
        transition accept;
    }

    state parse_verify {
        pkt.extract(hdr.verify);
        transition accept;
    }

    state parse_response {
        pkt.extract(hdr.response);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) { apply { } }
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) { apply { } }

// ─────────────────────────────────────────────────────────────────────────────
// Ingress
// ─────────────────────────────────────────────────────────────────────────────
control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t smeta)
{
    // ── Forwarding ──────────────────────────────────────────────────────────
    action set_egress(bit<9> port) {
        smeta.egress_spec = port;
    }

    table forward {
        key = {
            hdr.data.flow_id:  exact;
            hdr.data.hop_count: exact;
        }
        actions = { set_egress; NoAction; }
        size = 16;
        default_action = NoAction();
    }

    // ── Key + opcode loading ────────────────────────────────────────────────
    // share_table: (flow_id, hop_idx, key_index) → key value
    // The controller installs one entry per (flow_id, hop, key_index) triple.
    action set_key(bit<32> key_val) {
        meta.current_key = key_val;
    }

    table share_table {
        key = {
            hdr.data.flow_id:  exact;
            hdr.data.hop_count: exact;   // hop_count == hop_idx at time of processing
            meta.key_index_meta: exact;
        }
        actions = { set_key; NoAction; }
        size = 4096;   // 3 switches × 350 keys × multiple flows
        default_action = NoAction();
    }

    // opcode_table: (flow_id, hop_idx, key_index) → opcode (3-bit stored as bit<8>)
    action set_opcode(bit<8> opcode) {
        meta.current_opcode = opcode;
    }

    table opcode_table {
        key = {
            hdr.data.flow_id:  exact;
            hdr.data.hop_count: exact;
            meta.key_index_meta: exact;
        }
        actions = { set_opcode; NoAction; }
        size = 4096;
        default_action = NoAction();
    }

    // num_keys_table: (flow_id, hop_idx) → num_keys, lfsr_seed
    // Used to determine when the initial sequential phase ends and LFSR begins.
    action set_key_params(bit<16> num_keys, bit<32> lfsr_seed) {
        hdr.data.key_index = hdr.data.key_index; // no-op placeholder; logic below uses registers
    }

    // num_keys per (flow_id, hop_idx): stored in a register indexed by hop_idx
    // Controller writes this after each DH exchange.
    register<bit<32>>(3) reg_num_keys;
    register<bit<32>>(3) reg_lfsr_seed;

    // refresh_table: (flow_id, hop_idx) → packets_per_key_rotation
    // When the packet counter mod refresh_rate == 0, advance key_index.
    action set_refresh(bit<32> rate) {
        // stored in a register indexed by hop_idx; rate loaded by controller.
        // Actual counter logic happens inline below.
    }

    register<bit<32>>(3) reg_refresh_rate;

    // ── Accumulator operations ──────────────────────────────────────────────
    // Rotation helper: rotl(a, b) = (a rotl (b>>27)) + (b & 0x07FFFFFF)
    // P4 has no barrel-shifter, so we implement rotation via a lookup table
    // with the shift amount (0..31) as key.
    //
    // Inline rotation using if-chain (BMv2 supports this in actions).
    action apply_rot_ab() {
        // a rot b: rotate acc left by (key >> 27), then add (key & 0x07FFFFFF)
        bit<32> amount  = (meta.current_key >> 27) & 0x1f;
        bit<32> add_val = meta.current_key & 0x07FFFFFF;
        bit<32> a       = hdr.data.accumulator;
        bit<32> rotated;
        if      (amount == 0)  { rotated = a; }
        else if (amount == 1)  { rotated = (a << 1)  | (a >> 31); }
        else if (amount == 2)  { rotated = (a << 2)  | (a >> 30); }
        else if (amount == 3)  { rotated = (a << 3)  | (a >> 29); }
        else if (amount == 4)  { rotated = (a << 4)  | (a >> 28); }
        else if (amount == 5)  { rotated = (a << 5)  | (a >> 27); }
        else if (amount == 6)  { rotated = (a << 6)  | (a >> 26); }
        else if (amount == 7)  { rotated = (a << 7)  | (a >> 25); }
        else if (amount == 8)  { rotated = (a << 8)  | (a >> 24); }
        else if (amount == 9)  { rotated = (a << 9)  | (a >> 23); }
        else if (amount == 10) { rotated = (a << 10) | (a >> 22); }
        else if (amount == 11) { rotated = (a << 11) | (a >> 21); }
        else if (amount == 12) { rotated = (a << 12) | (a >> 20); }
        else if (amount == 13) { rotated = (a << 13) | (a >> 19); }
        else if (amount == 14) { rotated = (a << 14) | (a >> 18); }
        else if (amount == 15) { rotated = (a << 15) | (a >> 17); }
        else if (amount == 16) { rotated = (a << 16) | (a >> 16); }
        else if (amount == 17) { rotated = (a << 17) | (a >> 15); }
        else if (amount == 18) { rotated = (a << 18) | (a >> 14); }
        else if (amount == 19) { rotated = (a << 19) | (a >> 13); }
        else if (amount == 20) { rotated = (a << 20) | (a >> 12); }
        else if (amount == 21) { rotated = (a << 21) | (a >> 11); }
        else if (amount == 22) { rotated = (a << 22) | (a >> 10); }
        else if (amount == 23) { rotated = (a << 23) | (a >> 9);  }
        else if (amount == 24) { rotated = (a << 24) | (a >> 8);  }
        else if (amount == 25) { rotated = (a << 25) | (a >> 7);  }
        else if (amount == 26) { rotated = (a << 26) | (a >> 6);  }
        else if (amount == 27) { rotated = (a << 27) | (a >> 5);  }
        else if (amount == 28) { rotated = (a << 28) | (a >> 4);  }
        else if (amount == 29) { rotated = (a << 29) | (a >> 3);  }
        else if (amount == 30) { rotated = (a << 30) | (a >> 2);  }
        else                   { rotated = (a << 31) | (a >> 1);  }
        meta.acc_after = rotated + add_val;
    }

    action apply_rot_ba() {
        // b rot a: rotate key left by (acc >> 27), then add (acc & 0x07FFFFFF)
        bit<32> amount  = (hdr.data.accumulator >> 27) & 0x1f;
        bit<32> add_val = hdr.data.accumulator & 0x07FFFFFF;
        bit<32> a       = meta.current_key;
        bit<32> rotated;
        if      (amount == 0)  { rotated = a; }
        else if (amount == 1)  { rotated = (a << 1)  | (a >> 31); }
        else if (amount == 2)  { rotated = (a << 2)  | (a >> 30); }
        else if (amount == 3)  { rotated = (a << 3)  | (a >> 29); }
        else if (amount == 4)  { rotated = (a << 4)  | (a >> 28); }
        else if (amount == 5)  { rotated = (a << 5)  | (a >> 27); }
        else if (amount == 6)  { rotated = (a << 6)  | (a >> 26); }
        else if (amount == 7)  { rotated = (a << 7)  | (a >> 25); }
        else if (amount == 8)  { rotated = (a << 8)  | (a >> 24); }
        else if (amount == 9)  { rotated = (a << 9)  | (a >> 23); }
        else if (amount == 10) { rotated = (a << 10) | (a >> 22); }
        else if (amount == 11) { rotated = (a << 11) | (a >> 21); }
        else if (amount == 12) { rotated = (a << 12) | (a >> 20); }
        else if (amount == 13) { rotated = (a << 13) | (a >> 19); }
        else if (amount == 14) { rotated = (a << 14) | (a >> 18); }
        else if (amount == 15) { rotated = (a << 15) | (a >> 17); }
        else if (amount == 16) { rotated = (a << 16) | (a >> 16); }
        else if (amount == 17) { rotated = (a << 17) | (a >> 15); }
        else if (amount == 18) { rotated = (a << 18) | (a >> 14); }
        else if (amount == 19) { rotated = (a << 19) | (a >> 13); }
        else if (amount == 20) { rotated = (a << 20) | (a >> 12); }
        else if (amount == 21) { rotated = (a << 21) | (a >> 11); }
        else if (amount == 22) { rotated = (a << 22) | (a >> 10); }
        else if (amount == 23) { rotated = (a << 23) | (a >> 9);  }
        else if (amount == 24) { rotated = (a << 24) | (a >> 8);  }
        else if (amount == 25) { rotated = (a << 25) | (a >> 7);  }
        else if (amount == 26) { rotated = (a << 26) | (a >> 6);  }
        else if (amount == 27) { rotated = (a << 27) | (a >> 5);  }
        else if (amount == 28) { rotated = (a << 28) | (a >> 4);  }
        else if (amount == 29) { rotated = (a << 29) | (a >> 3);  }
        else if (amount == 30) { rotated = (a << 30) | (a >> 2);  }
        else                   { rotated = (a << 31) | (a >> 1);  }
        meta.acc_after = rotated + add_val;
    }

    // Apply the accumulator operation based on opcode
    action do_accumulate() {
        if (meta.current_opcode == OP_ADD) {
            meta.acc_after = hdr.data.accumulator + meta.current_key;
        } else if (meta.current_opcode == OP_AND) {
            meta.acc_after = hdr.data.accumulator & meta.current_key;
        } else if (meta.current_opcode == OP_XOR) {
            meta.acc_after = hdr.data.accumulator ^ meta.current_key;
        } else if (meta.current_opcode == OP_OR) {
            meta.acc_after = hdr.data.accumulator | meta.current_key;
        } else if (meta.current_opcode == OP_SUB_AB) {
            meta.acc_after = hdr.data.accumulator - meta.current_key;
        } else if (meta.current_opcode == OP_SUB_BA) {
            meta.acc_after = meta.current_key - hdr.data.accumulator;
        } else if (meta.current_opcode == OP_ROT_AB) {
            apply_rot_ab();
        } else { // OP_ROT_BA
            apply_rot_ba();
        }
        hdr.data.accumulator = meta.acc_after;
    }

    // ── Final-hop digest ────────────────────────────────────────────────────
    action send_digest() {
        hermes_digest_t d;
        d.flow_id      = hdr.data.flow_id;
        d.hop_count    = hdr.data.hop_count;
        d.accumulator  = hdr.data.accumulator;
        d.seq          = hdr.data.seq;
        d.timestamp_ms = hdr.data.timestamp_ms;
        d.nonce        = hdr.data.nonce;
        d.trigger_dh   = meta.trigger_dh;
        d.hop_idx      = (bit<32>)hdr.data.hop_count - 1; // 0-based switch id
        digest(1, d);
    }

    // ── LFSR step (Galois 32-bit, taps 32,22,2,1) ──────────────────────────
    // Returns next LFSR state given current state.
    action lfsr_step(in bit<32> state_in, out bit<32> state_out) {
        if ((state_in & 1) == 1) {
            state_out = (state_in >> 1) ^ 0xB4BCD35C;
        } else {
            state_out = state_in >> 1;
        }
    }

    // Map a 32-bit LFSR state to an index in [0, num_keys).
    // Uses multiply-high to avoid division/modulo (which BMv2 may not support
    // with runtime divisors).
    action lfsr_to_index(in bit<32> lfsr_state, in bit<32> num_keys, out bit<32> idx) {
        if (num_keys == 0) {
            idx = 0;
        } else {
            bit<64> prod;
            prod = (bit<64>) lfsr_state * (bit<64>) num_keys;
            idx = (bit<32>) (prod >> 32);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // apply block
    // ─────────────────────────────────────────────────────────────────────────
    apply {
        if (!hdr.data.isValid()) {
            // Non-data packets: just forward based on ethertype/dest (drop for now)
            return;
        }

        // hop_count in the packet = number of hops completed SO FAR when it enters this switch.
        // s1 enters with hop_count=0, s2 with 1, s3 with 2.
        bit<32> hop_idx = (bit<32>)hdr.data.hop_count;  // 0, 1, or 2

        // ── 1. Load key index and LFSR state from registers ─────────────────
        bit<32> key_idx_reg;
        bit<32> lfsr_reg;
        bit<32> num_keys_reg;
        bit<32> lfsr_seed_reg;
        bit<32> refresh_rate_reg;
        bit<32> pkt_cnt;

        reg_key_index.read(key_idx_reg,    hop_idx);
        reg_lfsr_state.read(lfsr_reg,      hop_idx);
        reg_num_keys.read(num_keys_reg,    hop_idx);
        reg_lfsr_seed.read(lfsr_seed_reg,  hop_idx);
        reg_refresh_rate.read(refresh_rate_reg, hop_idx);
        reg_pkt_counter.read(pkt_cnt,      hop_idx);

        // Expose key_index in packet header so table lookups can use it
        meta.key_index_meta = (bit<16>)key_idx_reg;

        // ── 2. Load key and opcode for this hop ─────────────────────────────
        meta.current_key    = 0;
        meta.current_opcode = OP_ADD;
        share_table.apply();
        opcode_table.apply();

        // ── 3. Apply the accumulator operation ──────────────────────────────
        meta.acc_after = hdr.data.accumulator;
        do_accumulate();
        forward.apply();
        // ── 4. Advance hop_count ────────────────────────────────────────────
        hdr.data.hop_count = hdr.data.hop_count + 1;

        // ── 5. Advance key index (LFSR or sequential) ───────────────────────
        pkt_cnt = pkt_cnt + 1;
        meta.trigger_dh = 0;

        bit<32> next_idx;
        bit<32> next_lfsr;
        bit<32> next_pkt_cnt;

        if (refresh_rate_reg > 0 && pkt_cnt >= refresh_rate_reg) {
            // Time to advance to the next key
            next_pkt_cnt = 0;

            if (lfsr_reg == 0) {
                // Still in initial sequential phase
                next_idx = key_idx_reg + 1;
                if (next_idx >= num_keys_reg) {
                    // Exhausted initial key pool — switch to LFSR phase
                    // Signal controller to do DH regen for fresh keys
                    meta.trigger_dh = 1;
                    // Seed LFSR for the reuse phase
                    next_lfsr = lfsr_seed_reg;
                    // Advance LFSR once to get first reuse index
                    bit<32> tmp_lfsr;
                    lfsr_step(next_lfsr, tmp_lfsr);
                    next_lfsr = tmp_lfsr;
                    lfsr_to_index(next_lfsr, num_keys_reg, next_idx);
                } else {
                    next_lfsr = 0;  // stay in sequential phase
                }
            } else {
                // LFSR phase: advance LFSR
                bit<32> tmp_lfsr;
                lfsr_step(lfsr_reg, tmp_lfsr);
                next_lfsr = tmp_lfsr;
                lfsr_to_index(next_lfsr, num_keys_reg, next_idx);
            }
        } else {
            next_idx      = key_idx_reg;
            next_lfsr     = lfsr_reg;
            next_pkt_cnt  = pkt_cnt;
        }

        reg_key_index.write(hop_idx,    next_idx);
        reg_lfsr_state.write(hop_idx,   next_lfsr);
        reg_pkt_counter.write(hop_idx,  next_pkt_cnt);

        // ── 6. Forward ───────────────────────────────────────────────────────


        // ── 7. Emit digest at final hop (hop_count==3 after increment) ──────
        if (hdr.data.hop_count == 3) {
            send_digest();
        }
    }
}

control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t smeta)
{ apply { } }

// ─────────────────────────────────────────────────────────────────────────────
// Deparser
// ─────────────────────────────────────────────────────────────────────────────
control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.base);
        pkt.emit(hdr.data);
        pkt.emit(hdr.verify);
        pkt.emit(hdr.response);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
