import socket
import random
import time

HOST = "127.0.0.1"
PORT = 5555

NUM_KEYS_MIN = 330
NUM_KEYS_MAX = 350
PATH = ["s1", "s2", "s3"]


def dh_public(g, p, secret):
    return (g ^ p) & secret


def dh_shared(public_other, secret_own, p):
    return (public_other & secret_own) ^ p


def rot_left(a, b):
    a &= 0xFFFFFFFF
    b &= 0xFFFFFFFF

    amount = (b >> 27) & 0x1F
    add_val = b & 0x07FFFFFF

    if amount == 0:
        rotated = a
    else:
        rotated = ((a << amount) | (a >> (32 - amount))) & 0xFFFFFFFF

    return (rotated + add_val) & 0xFFFFFFFF


def apply_op(op, key, acc):
    key &= 0xFFFFFFFF
    acc &= 0xFFFFFFFF

    if op == 0:      # ADD
        return (acc + key) & 0xFFFFFFFF
    if op == 1:      # ROT_BA
        return rot_left(key, acc)
    if op == 2:      # ROT_AB
        return rot_left(acc, key)
    if op == 3:      # AND
        return acc & key
    if op == 4:      # OR
        return acc | key
    if op == 5:      # SUB_BA
        return (key - acc) & 0xFFFFFFFF
    if op == 6:      # SUB_AB
        return (acc - key) & 0xFFFFFFFF
    if op == 7:      # XOR
        return acc ^ key

    raise ValueError(f"Unknown opcode: {op}")


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

        return b"".join(chunks).decode().strip()


def parse_dh_response(resp):
    parts = resp.split()

    if parts[0] not in ("DH_RESP", "DH_KEY_RESP"):
        raise ValueError(f"Unexpected DH response: {resp}")

    num_keys = int(parts[1])

    kb_start = 2
    kb_end = kb_start + NUM_KEYS_MAX

    op_start = kb_end
    op_end = op_start + NUM_KEYS_MAX

    expected_parts = 2 + NUM_KEYS_MAX + NUM_KEYS_MAX + 1
    if len(parts) != expected_parts:
        raise ValueError(
            f"Expected padded DH response with {expected_parts} fields, got {len(parts)}. "
            "Your Hermes server may still be using non-padded responses."
        )

    kb_values = list(map(int, parts[kb_start:kb_end]))
    opcodes = list(map(int, parts[op_start:op_end]))
    lfsr_seed = int(parts[op_end])

    return num_keys, kb_values, opcodes, lfsr_seed


def dh_init_switch(switch_id):
    g = random.randint(1, 2**32 - 1)
    p = random.randint(1, 2**32 - 1)

    # Client-side private values B for the switch.
    b_values = [random.randint(1, 2**32 - 1) for _ in range(NUM_KEYS_MAX)]

    # Public values sent to Hermes.
    ka_values = [dh_public(g, p, b) for b in b_values]

    # Padded format:
    # DH_INIT <switch_id> <G> <P> <Ka_0> ... <Ka_349>
    msg = f"DH_INIT {switch_id} {g} {p} " + " ".join(map(str, ka_values))

    print(f"\n>>> Loading keys onto {switch_id}")
    resp = send_line(msg)
    print(f"<<< {resp[:200]}...")

    num_keys, kb_values, opcodes, lfsr_seed = parse_dh_response(resp)

    shared_keys = [
        dh_shared(kb_values[i], b_values[i], p)
        for i in range(num_keys)
    ]

    print(f"{switch_id}: num_keys={num_keys}, lfsr_seed=0x{lfsr_seed:08x}")
    print("First 3 derived keys:")
    for i in range(min(3, num_keys)):
        print(
            f"  key[{i}] S=0x{shared_keys[i]:08x}, "
            f"op={opcodes[i]}"
        )

    return {
        "switch_id": switch_id,
        "G": g,
        "P": p,
        "num_keys": num_keys,
        "B": b_values,
        "Ka": ka_values,
        "Kb": kb_values,
        "shared_keys": shared_keys,
        "opcodes": opcodes,
        "lfsr_seed": lfsr_seed,
        "key_index": 0,
    }


def simulate_packet_through_path(switch_states):
    acc = 0

    print("\nSimulating packet path:")
    print(f"Initial accumulator: 0x{acc:08x}")

    for switch_id in PATH:
        st = switch_states[switch_id]

        idx = st["key_index"]
        key = st["shared_keys"][idx]
        op = st["opcodes"][idx]

        before = acc
        acc = apply_op(op, key, acc)

        print(
            f"{switch_id}: idx={idx}, op={op}, "
            f"key=0x{key:08x}, "
            f"acc_before=0x{before:08x}, "
            f"acc_after=0x{acc:08x}"
        )

        # For first packet, server also uses key_index 0.
        st["key_index"] += 1

    return acc


def send_verify(acc_final, flow_id=1, hop_count=3, seq=1):
    timestamp_ms = int(time.time() * 1000)
    nonce = random.randint(1, 2**63 - 1)

    msg = (
        f"VERIFY {flow_id} {hop_count} {acc_final} "
        f"{seq} {timestamp_ms} {nonce}"
    )

    print("\n>>> Sending VERIFY")
    print(msg)

    resp = send_line(msg)
    print(f"<<< {resp}")

    return resp


def main():
    switch_states = {}

    for switch_id in PATH:
        switch_states[switch_id] = dh_init_switch(switch_id)

    acc_final = simulate_packet_through_path(switch_states)

    print(f"\nFinal accumulator to verify: 0x{acc_final:08x} ({acc_final})")

    result = send_verify(
        acc_final=acc_final,
        flow_id=random.randint(1, 2**31 - 1),
        hop_count=3,
        seq=1,
    )

    if "ACCEPT" in result:
        print("\n✅ Flow verification succeeded")
    else:
        print("\n❌ Flow verification failed")


if __name__ == "__main__":
    main()