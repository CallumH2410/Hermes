import socket
import random
import sys

HOST = "127.0.0.1"
PORT = 5555

NUM_KEYS_MIN = 330
NUM_KEYS_MAX = 350


def dh_public(g, p, secret):
    return (g ^ p) & secret


def dh_shared(public_other, secret_own, p):
    return (public_other & secret_own) ^ p


def send_line(msg):
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        sock.sendall((msg + "\n").encode())

        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break

            chunks.append(data)

            if b"\n" in data:
                break

        return b"".join(chunks).decode()


def parse_dh_resp(resp):
    parts = resp.strip().split()

    if not parts:
        raise ValueError("Empty response from server")

    if parts[0] not in ("DH_RESP", "DH_KEY_RESP"):
        raise ValueError(f"Unexpected response: {resp}")

    num_keys = int(parts[1])

    if not (NUM_KEYS_MIN <= num_keys <= NUM_KEYS_MAX):
        raise ValueError(f"num_keys out of range: {num_keys}")

    kb_start = 2
    kb_end = kb_start + NUM_KEYS_MAX

    op_start = kb_end
    op_end = op_start + NUM_KEYS_MAX

    expected_parts = 2 + NUM_KEYS_MAX + NUM_KEYS_MAX + 1
    if len(parts) != expected_parts:
        raise ValueError(
            f"Unexpected response length. Got {len(parts)} parts, expected {expected_parts}. "
            "This probably means Hermes is not yet returning padded 350-key responses."
        )

    kb_values = list(map(int, parts[kb_start:kb_end]))
    opcodes = list(map(int, parts[op_start:op_end]))
    lfsr_seed = int(parts[op_end])

    return num_keys, kb_values, opcodes, lfsr_seed


def run_dh_init(switch_id="s1"):
    g = random.randint(1, 2**32 - 1)
    p = random.randint(1, 2**32 - 1)

    b_values = [random.randint(1, 2**32 - 1) for _ in range(NUM_KEYS_MAX)]
    ka_values = [dh_public(g, p, b) for b in b_values]

    # New padded format:
    # DH_INIT <switch_id> <G> <P> <Ka_0> ... <Ka_349>
    msg = f"DH_INIT {switch_id} {g} {p} " + " ".join(map(str, ka_values))

    print(f">>> Sending DH_INIT for {switch_id}")
    print(f"G=0x{g:08x}, P=0x{p:08x}")
    print(f"Sending {NUM_KEYS_MAX} padded Ka values")
    print()

    resp = send_line(msg)

    print("<<< Raw server response preview:")
    print(resp[:1000] + ("..." if len(resp) > 1000 else ""))
    print()

    num_keys, kb_values, opcodes, lfsr_seed = parse_dh_resp(resp)

    print(f"Hermes selected num_keys: {num_keys}")
    print(f"LFSR seed: 0x{lfsr_seed:08x}")
    print()

    print("Checking padding...")
    padding_ok = True

    for i in range(num_keys, NUM_KEYS_MAX):
        if kb_values[i] != 0 or opcodes[i] != 0:
            print(
                f"Padding error at index {i}: "
                f"Kb={kb_values[i]}, opcode={opcodes[i]}"
            )
            padding_ok = False

    if padding_ok:
        print("Padding OK: all unused Kb/opcode slots are zero")
    print()

    print("Checking valid keys/opcodes...")
    valid_ok = True

    for i in range(num_keys):
        if not (0 <= opcodes[i] <= 7):
            print(f"Invalid opcode at index {i}: {opcodes[i]}")
            valid_ok = False

        if kb_values[i] == 0:
            print(f"Warning: Kb at valid index {i} is zero")
            valid_ok = False

    if valid_ok:
        print("Valid key area OK")
    print()

    shared_secrets = [
        dh_shared(kb_values[i], b_values[i], p)
        for i in range(num_keys)
    ]

    print("First 10 client-side derived shared secrets:")
    for i in range(min(10, num_keys)):
        print(
            f"key[{i}] "
            f"Ka=0x{ka_values[i]:08x} "
            f"Kb=0x{kb_values[i]:08x} "
            f"B=0x{b_values[i]:08x} "
            f"S=0x{shared_secrets[i]:08x} "
            f"op={opcodes[i]}"
        )

    print()
    print("Compare these S values with the Hermes server log.")
    print("They should match for the same key indexes.")

    return {
        "switch_id": switch_id,
        "G": g,
        "P": p,
        "num_keys": num_keys,
        "Ka": ka_values,
        "Kb": kb_values,
        "B": b_values,
        "opcodes": opcodes,
        "lfsr_seed": lfsr_seed,
        "shared_secrets": shared_secrets,
    }


def main():
    switch_id = sys.argv[1] if len(sys.argv) > 1 else "s1"

    try:
        run_dh_init(switch_id)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()