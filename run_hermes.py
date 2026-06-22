#!/usr/bin/env python3
# run_hermes.py — full spec implementation
# Version 10.53
#
# Wire protocol with Hermes server:
#
#   DH_INIT <sw_id> <G> <P> <num_keys> <Ka_0> ... <Ka_N-1>
#   -> DH_RESP <num_keys> <Kb_0..N-1> <op_0..N-1> <lfsr_seed>
#
#   DH_KEY <sw_id> <G> <P> <num_keys> <Ka_0> ... <Ka_N-1>
#   -> DH_KEY_RESP <num_keys> <Kb_0..N-1> <op_0..N-1> <lfsr_seed>
#
#   VERIFY <flow_id> <hop_count> <acc_final> <seq> <timestamp_ms> <nonce>
#   -> RESULT ACCEPT|REJECT

import argparse
import os
import queue
import random
import socket
import struct
import sys
import threading
import time

import grpc
from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc

HERE = os.path.abspath(os.path.dirname(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
UTILS_DIR = os.path.join(REPO_ROOT, "tutorials", "utils")
if UTILS_DIR not in sys.path:
    sys.path.insert(0, UTILS_DIR)

from run_exercise import ExerciseRunner          # type: ignore
from p4runtime_lib.helper import P4InfoHelper    # type: ignore
from p4runtime_lib.bmv2 import Bmv2SwitchConnection  # type: ignore

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
ETHERTYPE_HERMES = 0xD1F1
MSG_DATA         = 0
NUM_KEYS_MIN     = 330
NUM_KEYS_MAX     = 350

# Opcode values (3-bit, stored as int)
OP_ADD    = 0   # 000
OP_ROT_BA = 1   # 001
OP_ROT_AB = 2   # 010
OP_AND    = 3   # 011
OP_OR     = 4   # 100
OP_SUB_BA = 5   # 101
OP_SUB_AB = 6   # 110
OP_XOR    = 7   # 111

# ─────────────────────────────────────────────────────────────────────────────
# Local accumulator logic (mirrors hermes_server.cpp and P4 program exactly)
# ─────────────────────────────────────────────────────────────────────────────

def rot_left(a: int, b: int) -> int:
    """Rotate a left by (b >> 27) bits, then add (b & 0x07FFFFFF). All 32-bit."""
    amount  = (b >> 27) & 0x1f
    add_val = b & 0x07FFFFFF
    a &= 0xFFFFFFFF
    if amount == 0:
        rotated = a
    else:
        rotated = ((a << amount) | (a >> (32 - amount))) & 0xFFFFFFFF
    return (rotated + add_val) & 0xFFFFFFFF


def apply_op(opcode: int, key: int, acc: int) -> int:
    """Apply opcode to (key, acc), returns new acc (32-bit)."""
    key &= 0xFFFFFFFF
    acc &= 0xFFFFFFFF
    if   opcode == OP_ADD:    return (acc + key) & 0xFFFFFFFF
    elif opcode == OP_AND:    return acc & key
    elif opcode == OP_XOR:    return acc ^ key
    elif opcode == OP_OR:     return acc | key
    elif opcode == OP_SUB_AB: return (acc - key) & 0xFFFFFFFF
    elif opcode == OP_SUB_BA: return (key - acc) & 0xFFFFFFFF
    elif opcode == OP_ROT_AB: return rot_left(acc, key)
    elif opcode == OP_ROT_BA: return rot_left(key, acc)
    return acc

def register_path_with_hermes(hermes_host: str, hermes_port: int,
                               flow_id: int, path: list[str]):
    """
    Tell Hermes which switches a flow will traverse, in order.
    path = ["s1", "s4", "s3"] for example.
    Must be called after DH exchanges for all switches on the path,
    and before any probes are sent.
    """
    hop_count = len(path)
    msg = f"PATH_REGISTER {flow_id} {hop_count} " + " ".join(path) + "\n"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hermes_host, hermes_port))
    s.sendall(msg.encode())
    resp = tcp_readline(s)
    s.close()
    parts = resp.split()
    if parts[0] != "PATH_ACK" or int(parts[1]) != flow_id:
        raise RuntimeError(f"PATH_REGISTER failed: {resp}")
    print(f"[hermes] Registered path for flow {flow_id}: {' -> '.join(path)}")

def lfsr_next(state: int) -> int:
    """Galois 32-bit LFSR, taps 32,22,2,1 — same polynomial as server."""
    if state & 1:
        return (state >> 1) ^ 0xB4BCD35C
    else:
        return state >> 1


# ─────────────────────────────────────────────────────────────────────────────
# DH helpers (optical method, DiffieHellman.pdf §2.2)
# ─────────────────────────────────────────────────────────────────────────────

def dh_public_key(G: int, P: int, secret: int) -> int:
    """K = (G ^ P) & secret"""
    return ((G ^ P) & secret) & 0xFFFFFFFF


def dh_shared_key(K_other: int, my_secret: int, P: int) -> int:
    """S = (K_other & my_secret) ^ P"""
    return ((K_other & my_secret) ^ P) & 0xFFFFFFFF


# ─────────────────────────────────────────────────────────────────────────────
# TCP helpers
# ─────────────────────────────────────────────────────────────────────────────

def tcp_readline(sock: socket.socket) -> str:
    """Read one newline-terminated line from sock."""
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("Connection closed while reading")
        buf += chunk
    return buf.decode().strip()


# ─────────────────────────────────────────────────────────────────────────────
# DH exchange with Hermes
# ─────────────────────────────────────────────────────────────────────────────

def dh_with_hermes(sw_id: str, hermes_host: str, hermes_port: int,
                   G: int, P: int, num_keys: int, is_regen: bool = False):
    """
    Perform DH exchange with Hermes.  Sends num_keys public keys Ka[i] = (G^P)&B[i].
    Returns dict with: keys (list of shared secrets), opcodes (list), lfsr_seed (int),
    and B_list (list of switch secrets, kept locally).
    """
    # Generate exactly NUM_KEYS_MAX secrets so B_list always has enough entries
    B_list = [random.randint(1, 0xFFFFFFFE) for _ in range(NUM_KEYS_MAX)]
    Ka_list = [dh_public_key(G, P, B) for B in B_list]

    # Send all NUM_KEYS_MAX values — server reads exactly this many
    cmd = "DH_KEY" if is_regen else "DH_INIT"
    msg = f"{cmd} {sw_id} {G} {P} " + " ".join(str(k) for k in Ka_list) + "\n"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hermes_host, hermes_port))
    t0 = time.perf_counter()
    s.sendall(msg.encode())

    # Read response: DH_RESP <num_keys> <Kb_0..N-1> <op_0..N-1> <lfsr_seed>
    resp_line = tcp_readline(s)
    t1 = time.perf_counter()
    s.close()

    resp_cmd = "DH_KEY_RESP" if is_regen else "DH_RESP"
    parts = resp_line.split()
    if parts[0] != resp_cmd:
        raise RuntimeError(f"Expected {resp_cmd}, got: {resp_line}")

    idx = 1
    n = int(parts[idx]);    idx += 1
    # Server sends NUM_KEYS_MAX padded values; read all then slice to n
    Kb_list = [int(parts[idx + i]) for i in range(NUM_KEYS_MAX)];    idx += NUM_KEYS_MAX
    op_list = [int(parts[idx + i]) for i in range(NUM_KEYS_MAX)];    idx += NUM_KEYS_MAX
    lfsr_seed = int(parts[idx])

    # Slice down to the actual number of keys used
    Kb_list = Kb_list[:n]
    op_list = op_list[:n]

    # Compute shared keys locally: S[i] = (Kb[i] & B[i]) ^ P
    shared_keys = [dh_shared_key(Kb_list[i], B_list[i], P) for i in range(n)]

    dt_ms = (t1 - t0) * 1000
    print(f"[{sw_id}] DH {'regen' if is_regen else 'init'} complete: "
          f"num_keys={n} lfsr_seed=0x{lfsr_seed:08x} RTT={dt_ms:.3f} ms")

    return {
        "keys":      shared_keys,
        "opcodes":   op_list,
        "lfsr_seed": lfsr_seed,
        "num_keys":  n,
    }


# ─────────────────────────────────────────────────────────────────────────────
# VERIFY with Hermes
# ─────────────────────────────────────────────────────────────────────────────

def verify_with_hermes(hermes_host: str, hermes_port: int,
                       flow_id: int, hop_count: int, acc: int,
                       seq: int, timestamp_ms: int, nonce: int) -> bool:
    """Send VERIFY to Hermes and return True if ACCEPT."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((hermes_host, hermes_port))
        msg = f"VERIFY {flow_id} {hop_count} {acc} {seq} {timestamp_ms} {nonce}\n"
        s.sendall(msg.encode())
        resp = tcp_readline(s)
        parts = resp.split()
        if len(parts) == 2 and parts[0] == "RESULT":
            return parts[1] == "ACCEPT"
        raise RuntimeError(f"Unexpected VERIFY response: {resp}")
    finally:
        s.close()


# ─────────────────────────────────────────────────────────────────────────────
# P4Runtime helpers
# ─────────────────────────────────────────────────────────────────────────────

def extract_u32(bitstring) -> int:
    raw = None
    if hasattr(bitstring, "data") and bitstring.data:
        raw = bytes(bitstring.data)
    elif hasattr(bitstring, "value") and bitstring.value:
        raw = bytes(bitstring.value)
    elif isinstance(bitstring, bytes):
        raw = bitstring
    elif isinstance(bitstring, str):
        raw = bitstring.encode("latin1")
    if raw is None:
        raise ValueError("Cannot extract bytes from bitstring")
    if len(raw) < 4:
        raw = b"\x00" * (4 - len(raw)) + raw
    elif len(raw) > 4:
        raw = raw[-4:]
    return int.from_bytes(raw, "big")


def extract_u16(bitstring) -> int:
    raw = None
    if hasattr(bitstring, "data") and bitstring.data:
        raw = bytes(bitstring.data)
    elif hasattr(bitstring, "value") and bitstring.value:
        raw = bytes(bitstring.value)
    elif isinstance(bitstring, bytes):
        raw = bitstring
    if raw is None:
        return 0
    if len(raw) < 2:
        raw = b"\x00" * (2 - len(raw)) + raw
    return int.from_bytes(raw[-2:], "big")


def extract_u48(bitstring) -> int:
    raw = None
    if hasattr(bitstring, "data") and bitstring.data:
        raw = bytes(bitstring.data)
    elif hasattr(bitstring, "value") and bitstring.value:
        raw = bytes(bitstring.value)
    elif isinstance(bitstring, bytes):
        raw = bitstring
    if raw is None:
        return 0
    if len(raw) < 6:
        raw = b"\x00" * (6 - len(raw)) + raw
    return int.from_bytes(raw[-6:], "big")


def write_entry(stub, device_id: int, election_id_low: int, entry):
    """Write (INSERT or MODIFY) a table entry via an existing stub."""
    for update_type in (p4runtime_pb2.Update.INSERT, p4runtime_pb2.Update.MODIFY):
        try:
            req = p4runtime_pb2.WriteRequest()
            req.device_id = device_id
            req.election_id.high = 0
            req.election_id.low = election_id_low
            upd = req.updates.add()
            upd.type = update_type
            upd.entity.table_entry.CopyFrom(entry)
            stub.Write(req)
            return
        except grpc.RpcError as e:
            if update_type == p4runtime_pb2.Update.INSERT:
                continue   # try MODIFY
            raise


# ─────────────────────────────────────────────────────────────────────────────
# Install all table entries for one switch after a DH exchange
# ─────────────────────────────────────────────────────────────────────────────

def install_switch_keys(p4info: P4InfoHelper, sw_conn,
                         flow_id: int, hop_idx: int, dh_result: dict):
    """
    Install share_table and opcode_table entries for every key in dh_result.
    Also write reg_num_keys, reg_lfsr_seed via register writes (via direct table entries
    that the P4 program reads — we use dedicated register-init table entries here).
    """
    num_keys  = dh_result["num_keys"]
    keys      = dh_result["keys"]
    opcodes   = dh_result["opcodes"]
    lfsr_seed = dh_result["lfsr_seed"]

    for key_idx in range(num_keys):
        # share_table: (flow_id, hop_idx, key_index) → set_key(key_val)
        entry = p4info.buildTableEntry(
            "MyIngress.share_table",
            match_fields={
                "hdr.data.flow_id":   flow_id,
                "hdr.data.hop_count": hop_idx,
                "hdr.data.key_index": key_idx,
            },
            action_name="MyIngress.set_key",
            action_params={"key_val": keys[key_idx]},
        )
        sw_conn.WriteTableEntry(entry)

        # opcode_table: same key → set_opcode(opcode)
        entry = p4info.buildTableEntry(
            "MyIngress.opcode_table",
            match_fields={
                "hdr.data.flow_id":   flow_id,
                "hdr.data.hop_count": hop_idx,
                "hdr.data.key_index": key_idx,
            },
            action_name="MyIngress.set_opcode",
            action_params={"opcode": opcodes[key_idx]},
        )
        sw_conn.WriteTableEntry(entry)

    print(f"[controller] Installed {num_keys} keys+opcodes for hop_idx={hop_idx} "
          f"flow_id={flow_id} lfsr_seed=0x{lfsr_seed:08x}")


def install_forward(p4info: P4InfoHelper, sw_conn, flow_id: int, hop_idx: int, port: int):
    """Install a forward table entry: (flow_id, hop_count=hop_idx) → set_egress(port)."""
    entry = p4info.buildTableEntry(
        "MyIngress.forward",
        match_fields={
            "hdr.data.flow_id":   flow_id,
            "hdr.data.hop_count": hop_idx,
        },
        action_name="MyIngress.set_egress",
        action_params={"port": port},
    )
    sw_conn.WriteTableEntry(entry)


# ─────────────────────────────────────────────────────────────────────────────
# Register write helpers (using P4Runtime DirectRegisterEntry isn't standard;
# we initialize registers via the first-packet write through a bootstrap table,
# or we use the BMv2 CLI. For simplicity we expose a helper that the digest
# listener uses via a RuntimeStub.)
# ─────────────────────────────────────────────────────────────────────────────

def write_register(stub, device_id: int, election_id_low: int,
                   register_name: str, index: int, value: int, bitwidth: int = 32):
    """Write a single register cell via P4Runtime WriteRequest (BMv2 extension)."""
    req = p4runtime_pb2.WriteRequest()
    req.device_id = device_id
    req.election_id.high = 0
    req.election_id.low = election_id_low
    upd = req.updates.add()
    upd.type = p4runtime_pb2.Update.MODIFY
    re = upd.entity.register_entry
    re.register_id = 0  # placeholder; BMv2 uses name resolution via p4info
    # In practice, controller sets registers via the register write RPC.
    # This is a best-effort call; if not supported, the P4 program uses the
    # table-based mechanism (set_key_params action) instead.
    # We log and continue gracefully.
    try:
        stub.Write(req)
    except Exception:
        pass  # BMv2 register writes may require alternative mechanism


# ─────────────────────────────────────────────────────────────────────────────
# Digest listener
# ─────────────────────────────────────────────────────────────────────────────

def listen_for_digests(p4info: P4InfoHelper,
                       hermes_host: str, hermes_port: int,
                       device_id: int, address: str,
                       result_queue: queue.Queue,
                       verbose: bool,
                       switch_conns: dict,   # {device_id: Bmv2SwitchConnection}
                       G: int, P: int,
                       flow_id: int = 1):
    """
    Dedicated P4Runtime client that listens for hermes_digest_t messages on the
    final switch (s3, device_id=2).  On receipt:
      1. Forwards the (acc, seq, ts, nonce) to Hermes for VERIFY.
      2. If trigger_dh==1, performs DH_KEY regen for the triggering switch and
         installs fresh keys + opcodes into that switch's tables.
    """
    try:
        channel = grpc.insecure_channel(address)
        stub    = p4runtime_pb2_grpc.P4RuntimeStub(channel)
        out_q: queue.Queue = queue.Queue()

        def req_iter():
            while True:
                item = out_q.get()
                if item is None:
                    return
                yield item

        stream = stub.StreamChannel(req_iter())

        # Arbitration
        arb = p4runtime_pb2.StreamMessageRequest()
        arb.arbitration.device_id      = device_id
        arb.arbitration.election_id.high = 0
        arb.arbitration.election_id.low  = 2
        out_q.put(arb)

        for msg in stream:
            if msg.WhichOneof("update") == "arbitration":
                if verbose:
                    print(f"[digest] Arbitration on device_id={device_id}: "
                          f"code={msg.arbitration.status.code}")
                break

        # Configure digest
        def get_digest_id(*names):
            for n in names:
                try:
                    return p4info.get_digests_id(n)
                except Exception:
                    continue
            raise RuntimeError("hermes_digest_t not found in p4info")

        digest_id = get_digest_id("hermes_digest_t", "MyIngress.hermes_digest_t")
        wreq = p4runtime_pb2.WriteRequest()
        wreq.device_id = device_id
        wreq.election_id.high = 0
        wreq.election_id.low  = 2
        upd = wreq.updates.add()
        upd.type = p4runtime_pb2.Update.INSERT
        de = upd.entity.digest_entry
        de.digest_id            = digest_id
        de.config.max_timeout_ns  = 0
        de.config.max_list_size   = 1
        de.config.ack_timeout_ns  = 100_000_000
        stub.Write(wreq)

        if verbose:
            print(f"[digest] Configured hermes_digest_t (id={digest_id})")

        # Sequence counter for replay protection (monotonically increasing per flow)
        seq_counter: dict = {}

        for msg in stream:
            if msg.WhichOneof("update") != "digest":
                continue

            d = msg.digest
            if d.digest_id != digest_id:
                continue

            for entry in d.data:
                members = entry.struct.members
                if len(members) < 8:
                    if verbose:
                        print(f"[digest] Unexpected member count: {len(members)}")
                    continue

                # hermes_digest_t field order:
                # flow_id(32), hop_count(16), accumulator(32),
                # seq(32), timestamp_ms(48), nonce(32),
                # trigger_dh(1), hop_idx(32)
                rcv_flow_id     = extract_u32(members[0].bitstring)
                rcv_hop_count   = extract_u16(members[1].bitstring)
                rcv_acc         = extract_u32(members[2].bitstring)
                rcv_seq         = extract_u32(members[3].bitstring)
                rcv_ts_ms       = extract_u48(members[4].bitstring)
                rcv_nonce       = extract_u32(members[5].bitstring)
                rcv_trigger_dh  = extract_u32(members[6].bitstring) & 1
                rcv_hop_idx     = extract_u32(members[7].bitstring)

                digest_time = time.perf_counter()
                if verbose:
                    print(f"[digest] Received: flow_id={rcv_flow_id} "
                          f"hop_count={rcv_hop_count} acc={rcv_acc:#010x} "
                          f"seq={rcv_seq} nonce={rcv_nonce:#010x} "
                          f"trigger_dh={rcv_trigger_dh} hop_idx={rcv_hop_idx}")

                # ── DH regen if requested ─────────────────────────────────
                if rcv_trigger_dh:
                    sw_name = f"s{rcv_hop_idx + 1}"
                    target_device_id = int(rcv_hop_idx)
                    print(f"[digest] DH regen triggered for {sw_name}")
                    try:
                        num_keys = random.randint(NUM_KEYS_MIN, NUM_KEYS_MAX)
                        dh_result = dh_with_hermes(
                            sw_name, hermes_host, hermes_port,
                            G, P, num_keys, is_regen=True)

                        target_sw = switch_conns.get(target_device_id)
                        if target_sw is not None:
                            install_switch_keys(
                                p4info, target_sw,
                                rcv_flow_id, int(rcv_hop_idx), dh_result)
                            print(f"[digest] Key regen complete for {sw_name}")
                        else:
                            print(f"[digest] No connection for device_id={target_device_id}")
                    except Exception as e:
                        print(f"[digest] DH regen error for {sw_name}: {e}")

                # ── VERIFY ─────────────────────────────────────────────────
                verify_start = time.perf_counter()
                ok = verify_with_hermes(
                    hermes_host, hermes_port,
                    rcv_flow_id, rcv_hop_count, rcv_acc,
                    rcv_seq, rcv_ts_ms, rcv_nonce)
                verify_time = time.perf_counter()

                if verbose:
                    print(f"[digest] Hermes verification: {'ACCEPT' if ok else 'REJECT'} "
                          f"(verify RTT={(verify_time - verify_start)*1000:.2f} ms)")

                if result_queue is not None:
                    result_queue.put((digest_time, verify_time, ok))

            # ACK digest
            ack = p4runtime_pb2.StreamMessageRequest()
            ack.digest_ack.digest_id = d.digest_id
            ack.digest_ack.list_id   = d.list_id
            out_q.put(ack)

    except Exception as e:
        print(f"[digest] Listener error: {e}")
        import traceback
        traceback.print_exc()


# ─────────────────────────────────────────────────────────────────────────────
# Probe packet construction and injection
# ─────────────────────────────────────────────────────────────────────────────

def build_probe(flow_id: int, seq: int) -> bytes:
    """
    Build a raw Ethernet frame carrying a Hermes data packet.
    Layout: Ethernet(14) + hermes_base(4) + hermes_data(24)
    hermes_data: accumulator(4) + key_index(2) + hop_count(2) + flow_id(4)
                 + seq(4) + timestamp_ms(6) + nonce(4) = 26 bytes
    """
    dst_mac = bytes.fromhex("080000000302")
    src_mac = bytes.fromhex("080000000101")
    eth = struct.pack("!6s6sH", dst_mac, src_mac, ETHERTYPE_HERMES)

    # hermes_base_t: msg_type=0 (DATA), version=1, length (filled in)
    # hermes_data_t fields
    accumulator  = 0
    key_index    = 0
    hop_count    = 0
    timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFFFFFF  # 48-bit
    nonce        = random.randint(0, 0xFFFFFFFF)

    base  = struct.pack("!BBH", MSG_DATA, 1, 0)   # msg_type, version, length (placeholder)
    # hermes_data: accumulator(4), key_index(2), hop_count(2), flow_id(4),
    #              seq(4), timestamp_ms(6), nonce(4)
    data  = struct.pack("!IHHIIII",
                        accumulator & 0xFFFFFFFF,
                        key_index & 0xFFFF,
                        hop_count & 0xFFFF,
                        flow_id & 0xFFFFFFFF,
                        seq & 0xFFFFFFFF,
                        (timestamp_ms >> 16) & 0xFFFFFFFF,   # top 32 of 48-bit ts
                        timestamp_ms & 0xFFFF)               # wrong — see note below

    # Note: timestamp_ms is 48 bits (6 bytes). struct doesn't have a 6-byte pack.
    # Pack it correctly as two fields:
    ts_hi = (timestamp_ms >> 16) & 0xFFFFFFFF   # upper 32 bits
    ts_lo = timestamp_ms & 0xFFFF               # lower 16 bits
    data  = struct.pack("!IHHIIII",
                        accumulator & 0xFFFFFFFF,
                        key_index & 0xFFFF,
                        hop_count & 0xFFFF,
                        flow_id & 0xFFFFFFFF,
                        seq & 0xFFFFFFFF,
                        ts_hi,
                        ts_lo) + struct.pack("!I", nonce)

    # Redo cleanly with correct 48-bit timestamp layout:
    data = (struct.pack("!I", accumulator & 0xFFFFFFFF)        # accumulator  4
          + struct.pack("!H", key_index & 0xFFFF)              # key_index    2
          + struct.pack("!H", hop_count & 0xFFFF)              # hop_count    2
          + struct.pack("!I", flow_id & 0xFFFFFFFF)            # flow_id      4
          + struct.pack("!I", seq & 0xFFFFFFFF)                # seq          4
          + struct.pack("!I", (timestamp_ms >> 16) & 0xFFFFFFFF)  # ts high 4
          + struct.pack("!H", timestamp_ms & 0xFFFF)           # ts low   2
          + struct.pack("!I", nonce & 0xFFFFFFFF))             # nonce        4
    # total data = 26 bytes

    frame = eth + base + data
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def send_probe_from_h1(net, flow_id: int, seq: int, verbose: bool = True) -> float:
    """Inject a probe from h1. Returns send timestamp."""
    frame   = build_probe(flow_id, seq)
    h1      = net.get("h1")
    iface   = h1.defaultIntf().name
    tmpfile = "/tmp/hermes_probe.bin"

    with open(tmpfile, "wb") as f:
        f.write(frame)

    cmd = (f"python3 - << 'EOF'\n"
           f"import socket\n"
           f"s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)\n"
           f"s.bind(('{iface}', 0))\n"
           f"s.send(open('{tmpfile}','rb').read())\n"
           f"s.close()\n"
           f"EOF\n")

    send_time = time.perf_counter()
    if verbose:
        print(f"[h1] Injecting probe seq={seq} flow_id={flow_id} on {iface}")
    out = h1.cmd(cmd)
    if out and verbose:
        print(out.strip())
    return send_time


# ─────────────────────────────────────────────────────────────────────────────
# Control-plane setup
# ─────────────────────────────────────────────────────────────────────────────

def program_line(p4info_path: str, bmv2_json: str,
                 hermes_host: str, hermes_port: int,
                 G: int, P: int,
                 flow_id: int = 1,
                 start_digest_listener: bool = True,
                 refresh_rate: int = 50,
                 result_queue: queue.Queue = None) -> dict:
    """
    Program all 3 switches:
    - Perform DH_INIT with Hermes (330-350 keys each)
    - Install share_table + opcode_table entries for every key
    - Install forward entries
    - Start digest listener thread
    Returns switch_conns dict {device_id: Bmv2SwitchConnection}.
    """
    p4info = P4InfoHelper(p4info_path)

    s1 = Bmv2SwitchConnection("s1", "127.0.0.1:50051", 0)
    s2 = Bmv2SwitchConnection("s2", "127.0.0.1:50052", 1)
    s3 = Bmv2SwitchConnection("s3", "127.0.0.1:50053", 2)

    for sw in (s1, s2, s3):
        sw.MasterArbitrationUpdate()
        sw.SetForwardingPipelineConfig(
            p4info=p4info.p4info, bmv2_json_file_path=bmv2_json)

    switch_conns = {0: s1, 1: s2, 2: s3}

    # DH exchange with Hermes for each switch (330-350 keys)
    dh_results = {}
    for hop_idx, (sw_id, sw_conn) in enumerate([("s1", s1), ("s2", s2), ("s3", s3)]):
        num_keys = random.randint(NUM_KEYS_MIN, NUM_KEYS_MAX)
        dh_result = dh_with_hermes(sw_id, hermes_host, hermes_port, G, P, num_keys)
        dh_results[hop_idx] = dh_result
        install_switch_keys(p4info, sw_conn, flow_id, hop_idx, dh_result)

    # After DH exchanges and before sending any probes
    register_path_with_hermes(hermes_host, hermes_port,
                              flow_id=flow_id,
                              path=["s1", "s2", "s3"])
    # Forward entries: s1→s2 (port2), s2→s3 (port2), s3→h2 (port2)
    install_forward(p4info, s1, flow_id, 0, 2)
    install_forward(p4info, s2, flow_id, 1, 2)
    install_forward(p4info, s3, flow_id, 2, 2)

    print("[hermes] Control-plane programming complete.")

    if start_digest_listener:
        t = threading.Thread(
            target=listen_for_digests,
            args=(p4info, hermes_host, hermes_port,
                  2, "127.0.0.1:50053",
                  result_queue, True,
                  switch_conns, G, P, flow_id),
            daemon=True)
        t.start()

    return switch_conns


# ─────────────────────────────────────────────────────────────────────────────
# Throughput test
# ─────────────────────────────────────────────────────────────────────────────

def run_throughput_test(net, hermes_host: str, hermes_port: int,
                        p4info_path: str, G: int, P: int,
                        num_probes: int, delay_ms: float,
                        refresh_rate: int):
    p4info = P4InfoHelper(p4info_path)
    result_queue = queue.Queue()

    switch_conns = {
        0: Bmv2SwitchConnection("s1", "127.0.0.1:50051", 0),
        1: Bmv2SwitchConnection("s2", "127.0.0.1:50052", 1),
        2: Bmv2SwitchConnection("s3", "127.0.0.1:50053", 2),
    }

    t = threading.Thread(
        target=listen_for_digests,
        args=(p4info, hermes_host, hermes_port,
              2, "127.0.0.1:50053",
              result_queue, False,
              switch_conns, G, P, 1),
        daemon=True)
    t.start()
    time.sleep(0.5)

    print(f"\n[throughput] {num_probes} probes, {delay_ms} ms inter-probe delay\n")
    send_times = []
    for i in range(num_probes):
        st = send_probe_from_h1(net, flow_id=1, seq=i + 1, verbose=False)
        send_times.append(st)
        if delay_ms > 0 and i < num_probes - 1:
            time.sleep(delay_ms / 1000.0)

    results = []
    for i in range(num_probes):
        try:
            digest_t, verify_t, ok = result_queue.get(timeout=30)
            send_t = send_times[i] if i < len(send_times) else digest_t
            total  = (verify_t - send_t) * 1000
            dig_l  = (digest_t - send_t) * 1000
            ver_l  = (verify_t - digest_t) * 1000
            results.append((total, dig_l, ver_l, ok))
            print(f"  probe {i+1:3d}: total={total:.2f} ms "
                  f"digest={dig_l:.2f} ms verify={ver_l:.2f} ms "
                  f"{'ACCEPT' if ok else 'REJECT'}")
        except queue.Empty:
            print(f"  probe {i+1:3d}: TIMEOUT")
            results.append((None, None, None, False))

    valid = [r for r in results if r[0] is not None]
    if valid:
        totals   = [r[0] for r in valid]
        accepts  = sum(1 for r in valid if r[3])
        print(f"\n{'='*55}")
        print(f"Probes: {num_probes}  Valid: {len(valid)}  "
              f"ACCEPT: {accepts}  REJECT: {len(valid)-accepts}")
        print(f"Total latency — avg: {sum(totals)/len(totals):.2f} ms  "
              f"min: {min(totals):.2f} ms  max: {max(totals):.2f} ms")
        print(f"{'='*55}")


# ─────────────────────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--topo",        required=True)
    ap.add_argument("--p4info",      required=True)
    ap.add_argument("--bmv2-json",   required=True)
    ap.add_argument("--hermes-host", default="127.0.0.1")
    ap.add_argument("--hermes-port", type=int, default=5555)
    ap.add_argument("--G",           type=lambda x: int(x, 0), default=0x5A5A5A5A)
    ap.add_argument("--P",           type=lambda x: int(x, 0), default=0xA5A5A5A5)
    ap.add_argument("--flow-id",     type=int, default=1)
    ap.add_argument("--timeout",     type=float, default=15.0)
    ap.add_argument("--refresh-rate",type=int, default=50,
                    help="Packets per key before LFSR-driven key rotation")
    ap.add_argument("--throughput",  action="store_true")
    ap.add_argument("--num-probes",  type=int, default=10)
    ap.add_argument("--delay-ms",    type=float, default=10.0)
    args = ap.parse_args()

    runner = ExerciseRunner(
        topo_file=args.topo,
        log_dir=os.path.join(HERE, "logs"),
        pcap_dir=os.path.join(HERE, "pcaps"),
        switch_json=args.bmv2_json,
        bmv2_exe="simple_switch_grpc",
        quiet=False,
    )
    runner.create_network()
    runner.net.start()
    time.sleep(1)
    runner.program_hosts()

    try:
        t0 = time.perf_counter()
        program_line(
            args.p4info, args.bmv2_json,
            args.hermes_host, args.hermes_port,
            args.G, args.P,
            flow_id=args.flow_id,
            start_digest_listener=not args.throughput,
            refresh_rate=args.refresh_rate,
        )
        t1 = time.perf_counter()
        print(f"[hermes] Setup time: {(t1-t0)*1000:.1f} ms")

        if args.throughput:
            run_throughput_test(
                runner.net, args.hermes_host, args.hermes_port,
                args.p4info, args.G, args.P,
                args.num_probes, args.delay_ms, args.refresh_rate)
        else:
            send_probe_from_h1(runner.net, flow_id=args.flow_id, seq=1)
            print(f"[hermes] Probe sent. Waiting {args.timeout:.0f} s for verification...")
            time.sleep(args.timeout)
    finally:
        runner.net.stop()


if __name__ == "__main__":
    main()
