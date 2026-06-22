#!/usr/bin/env python3
# run_hermes_tna3switch.py — TNA port of run_hermes.py
# Version 12.05
#
# Changes from the V1Model version (run_hermes.py):
#
#   1. accumulate_table replaces share_table + opcode_table
#      install_switch_keys now writes one entry per key using OPCODE_ACTION
#      to map opcode int → action name.  SUB_AB and both ROT ops use "prep"
#      variant action names (do_sub_ab_prep, do_rot_ab_prep, do_rot_ba_prep).
#
#   2. Only two registers: reg_key_index and reg_countdown.
#      init_switch_registers() replaces the old 6-register init.
#      Registers are written after each DH exchange and after each key advance.
#
#   3. LFSR / key-advance logic moved entirely to this controller.
#      advance_key() mirrors what the old P4 dataplane did.
#      ctrl_state dict tracks per-hop LFSR state, key_index, etc.
#
#   4. trigger_dh is now bit<8> (was bit<1>).
#      Digest extraction uses plain extract_u32; no & 1 masking needed
#      (though harmless if kept).
#
#   5. After DH regen, reg_key_index and reg_countdown are reset in the
#      dataplane via write_register().
#
# Wire protocol with Hermes server (unchanged):
#   DH_INIT <sw_id> <G> <P> <Ka_0> ... <Ka_N-1>
#   -> DH_RESP <num_keys> <Kb_0..N-1> <op_0..N-1> <lfsr_seed>
#
#   DH_KEY <sw_id> <G> <P> <Ka_0> ... <Ka_N-1>
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

# Opcode values (3-bit, stored as int) — unchanged
OP_ADD    = 0   # 000
OP_ROT_BA = 1   # 001
OP_ROT_AB = 2   # 010
OP_AND    = 3   # 011
OP_OR     = 4   # 100
OP_SUB_BA = 5   # 101
OP_SUB_AB = 6   # 110
OP_XOR    = 7   # 111

# ── NEW: opcode int → accumulate_table action name ───────────────────────────
# SUB_AB and both ROT variants use "prep" actions because the P4 ALU cannot
# use action data as the subtrahend / shift source directly.
OPCODE_ACTION = {
    OP_ADD:    "do_add",
    OP_ROT_BA: "do_rot_ba_prep",
    OP_ROT_AB: "do_rot_ab_prep",
    OP_AND:    "do_and",
    OP_OR:     "do_or",
    OP_SUB_BA: "do_sub_ba",
    OP_SUB_AB: "do_sub_ab_prep",
    OP_XOR:    "do_xor",
}

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
                               flow_id: int, path: list):
    """Tell Hermes which switches a flow will traverse, in order."""
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
# DH helpers
# ─────────────────────────────────────────────────────────────────────────────

def dh_public_key(G: int, P: int, secret: int) -> int:
    return ((G ^ P) & secret) & 0xFFFFFFFF


def dh_shared_key(K_other: int, my_secret: int, P: int) -> int:
    return ((K_other & my_secret) ^ P) & 0xFFFFFFFF


# ─────────────────────────────────────────────────────────────────────────────
# TCP helpers
# ─────────────────────────────────────────────────────────────────────────────

def tcp_readline(sock: socket.socket) -> str:
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
    B_list  = [random.randint(1, 0xFFFFFFFE) for _ in range(NUM_KEYS_MAX)]
    Ka_list = [dh_public_key(G, P, B) for B in B_list]

    cmd = "DH_KEY" if is_regen else "DH_INIT"
    msg = f"{cmd} {sw_id} {G} {P} " + " ".join(str(k) for k in Ka_list) + "\n"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hermes_host, hermes_port))
    t0 = time.perf_counter()
    s.sendall(msg.encode())

    resp_line = tcp_readline(s)
    t1 = time.perf_counter()
    s.close()

    resp_cmd = "DH_KEY_RESP" if is_regen else "DH_RESP"
    parts = resp_line.split()
    if parts[0] != resp_cmd:
        raise RuntimeError(f"Expected {resp_cmd}, got: {resp_line}")

    idx = 1
    n = int(parts[idx]);    idx += 1
    Kb_list = [int(parts[idx + i]) for i in range(NUM_KEYS_MAX)];    idx += NUM_KEYS_MAX
    op_list = [int(parts[idx + i]) for i in range(NUM_KEYS_MAX)];    idx += NUM_KEYS_MAX
    lfsr_seed = int(parts[idx])

    Kb_list = Kb_list[:n]
    op_list = op_list[:n]

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
        except grpc.RpcError:
            if update_type == p4runtime_pb2.Update.INSERT:
                continue
            raise


def write_register(stub, device_id: int, election_id_low: int,
                   register_name: str, index: int, value: int):
    """Write a single register cell via P4Runtime WriteRequest."""
    req = p4runtime_pb2.WriteRequest()
    req.device_id = device_id
    req.election_id.high = 0
    req.election_id.low = election_id_low
    upd = req.updates.add()
    upd.type = p4runtime_pb2.Update.MODIFY
    re = upd.entity.register_entry
    re.register_id = 0   # resolved by name via p4info at runtime
    try:
        stub.Write(req)
    except Exception:
        pass  # non-fatal; log if needed


# ─────────────────────────────────────────────────────────────────────────────
# Install all table entries for one switch after a DH exchange
#
# CHANGED: writes accumulate_table (not share_table + opcode_table).
# One entry per key; action name encodes the opcode via OPCODE_ACTION map.
# ─────────────────────────────────────────────────────────────────────────────

def install_switch_keys(p4info: P4InfoHelper, sw_conn,
                        flow_id: int, hop_idx: int, dh_result: dict):
    num_keys = dh_result["num_keys"]
    keys     = dh_result["keys"]
    opcodes  = dh_result["opcodes"]

    for key_idx in range(num_keys):
        opcode      = opcodes[key_idx]
        action_name = OPCODE_ACTION.get(opcode, "do_add")

        # accumulate_table: (flow_id, hop_count, key_index) → action(kv=key)
        entry = p4info.buildTableEntry(
            "MyIngress.accumulate_table",
            match_fields={
                "hdr.data.flow_id":   flow_id,
                "hdr.data.hop_count": hop_idx,
                "hdr.data.key_index": key_idx,
            },
            action_name=f"MyIngress.{action_name}",
            action_params={"kv": keys[key_idx]},
        )
        sw_conn.WriteTableEntry(entry)

    print(f"[controller] Installed {num_keys} keys into accumulate_table "
          f"hop_idx={hop_idx} flow_id={flow_id} "
          f"lfsr_seed=0x{dh_result['lfsr_seed']:08x}")


# ─────────────────────────────────────────────────────────────────────────────
# NEW: Initialise the two TNA registers for one switch.
#
# reg_key_index[hop_idx]  ← 0          (start at first key)
# reg_countdown[hop_idx]  ← refresh_rate  (packets before first key advance)
#
# The old six registers (reg_lfsr_state, reg_num_keys, reg_lfsr_seed,
# reg_refresh_rate, reg_pkt_counter, reg_key_index) no longer exist.
# ─────────────────────────────────────────────────────────────────────────────

def init_switch_registers(p4info: P4InfoHelper, sw_conn,
                          hop_idx: int, refresh_rate: int):
    for reg_name, value in [
        ("MyIngress.reg_key_index", 0),
        ("MyIngress.reg_countdown", refresh_rate),
    ]:
        entry = p4info.buildRegisterEntry(
            register_name=reg_name,
            index=hop_idx,
            data=value,
        )
        sw_conn.WriteRegisterEntry(entry)

    print(f"[controller] Initialised registers hop_idx={hop_idx} "
          f"key_index=0 countdown={refresh_rate}")


def install_forward(p4info: P4InfoHelper, sw_conn,
                    flow_id: int, hop_idx: int, port: int):
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
# NEW: Controller-side LFSR / key-advance state.
#
# The P4 dataplane no longer runs LFSR or advances key_index.  This dict
# mirrors what the old P4 registers tracked, and advance_key() mirrors what
# the old P4 apply block did on every refresh_rate-th packet.
#
# Layout per hop_idx:
#   "lfsr"       – current LFSR state (0 while in initial sequential phase)
#   "key_idx"    – current key index written into reg_key_index
#   "initial"    – True while iterating 0..num_keys-1 sequentially
#   "num_keys"   – number of keys for this switch
#   "lfsr_seed"  – seed used when switching from sequential → LFSR phase
#   "keys"       – list of shared key values
#   "opcodes"    – list of opcode ints
# ─────────────────────────────────────────────────────────────────────────────
ctrl_state: dict = {}   # hop_idx (int) → dict


def advance_key(p4info: P4InfoHelper,
                switch_conns: dict,
                hop_idx: int,
                refresh_rate: int,
                hermes_host: str,
                hermes_port: int,
                G: int, P: int,
                flow_id: int):
    """
    Called when a digest arrives with trigger_dh == 1.
    Mirrors the LFSR logic formerly in the P4 dataplane:
      - Sequential phase: increment key_idx; if exhausted, switch to LFSR
        and trigger DH regen for a fresh key pool.
      - LFSR phase: step LFSR and map to next key_idx.
    Writes updated reg_key_index and resets reg_countdown in the dataplane.
    """
    st      = ctrl_state[hop_idx]
    sw_conn = switch_conns[hop_idx]

    if st["initial"]:
        st["key_idx"] += 1
        if st["key_idx"] >= st["num_keys"]:
            # Sequential pool exhausted — switch to LFSR and trigger DH regen
            st["initial"] = False
            lfsr          = lfsr_next(st["lfsr_seed"])
            st["lfsr"]    = lfsr
            st["key_idx"] = lfsr % st["num_keys"]

            sw_name = f"s{hop_idx + 1}"
            print(f"[controller] Key pool exhausted for {sw_name} — triggering DH regen")
            try:
                new_dh = dh_with_hermes(sw_name, hermes_host, hermes_port,
                                        G, P, NUM_KEYS_MAX, is_regen=True)
                install_switch_keys(p4info, sw_conn, flow_id, hop_idx, new_dh)

                # Reset controller-side state for the new key pool
                ctrl_state[hop_idx].update({
                    "keys":      new_dh["keys"],
                    "opcodes":   new_dh["opcodes"],
                    "lfsr_seed": new_dh["lfsr_seed"],
                    "num_keys":  new_dh["num_keys"],
                    "initial":   True,
                    "key_idx":   0,
                    "lfsr":      0,
                })
                st = ctrl_state[hop_idx]   # re-bind after update
                print(f"[controller] DH regen complete for {sw_name}")
            except Exception as e:
                print(f"[controller] DH regen error for {sw_name}: {e}")
    else:
        # LFSR phase
        st["lfsr"]    = lfsr_next(st["lfsr"])
        st["key_idx"] = st["lfsr"] % st["num_keys"]

    # Push updated key index and reset countdown into the dataplane
    for reg_name, value in [
        ("MyIngress.reg_key_index", st["key_idx"]),
        ("MyIngress.reg_countdown", refresh_rate),
    ]:
        entry = p4info.buildRegisterEntry(
            register_name=reg_name,
            index=hop_idx,
            data=value,
        )
        sw_conn.WriteRegisterEntry(entry)

    print(f"[controller] hop_idx={hop_idx} advanced to key_idx={st['key_idx']} "
          f"lfsr=0x{st['lfsr']:08x} countdown reset to {refresh_rate}")


# ─────────────────────────────────────────────────────────────────────────────
# Digest listener
#
# CHANGED:
#   • trigger_dh is now bit<8> — use extract_u32 directly (no & 1 needed,
#     but harmless if applied; any non-zero value means "advance").
#   • When trigger_dh is set, call advance_key() instead of doing an inline
#     DH regen — the LFSR logic now lives in advance_key().
# ─────────────────────────────────────────────────────────────────────────────

def listen_for_digests(p4info: P4InfoHelper,
                       hermes_host: str, hermes_port: int,
                       device_id: int, address: str,
                       result_queue: queue.Queue,
                       verbose: bool,
                       switch_conns: dict,
                       G: int, P: int,
                       flow_id: int = 1,
                       refresh_rate: int = 50):
    """
    Listens for hermes_digest_t messages on the final switch (s3).
    On receipt:
      1. If trigger_dh != 0, calls advance_key() for the triggering switch.
      2. Forwards (acc, seq, ts, nonce) to Hermes for VERIFY.
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
        arb.arbitration.device_id        = device_id
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
        de.digest_id             = digest_id
        de.config.max_timeout_ns = 0
        de.config.max_list_size  = 1
        de.config.ack_timeout_ns = 100_000_000
        stub.Write(wreq)

        if verbose:
            print(f"[digest] Configured hermes_digest_t (id={digest_id})")

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

                # hermes_digest_t field order (TNA version):
                # flow_id(32), hop_count(16), accumulator(32),
                # seq(32), timestamp_ms(48), nonce(32),
                # trigger_dh(8),   ← was bit<1> in V1Model, now bit<8>
                # hop_idx(32)
                rcv_flow_id    = extract_u32(members[0].bitstring)
                rcv_hop_count  = extract_u16(members[1].bitstring)
                rcv_acc        = extract_u32(members[2].bitstring)
                rcv_seq        = extract_u32(members[3].bitstring)
                rcv_ts_ms      = extract_u48(members[4].bitstring)
                rcv_nonce      = extract_u32(members[5].bitstring)
                # trigger_dh is now bit<8>; any non-zero value means "advance"
                rcv_trigger_dh = extract_u32(members[6].bitstring)
                rcv_hop_idx    = extract_u32(members[7].bitstring)

                digest_time = time.perf_counter()
                if verbose:
                    print(f"[digest] Received: flow_id={rcv_flow_id} "
                          f"hop_count={rcv_hop_count} acc={rcv_acc:#010x} "
                          f"seq={rcv_seq} nonce={rcv_nonce:#010x} "
                          f"trigger_dh={rcv_trigger_dh} hop_idx={rcv_hop_idx}")

                # ── Key advance / DH regen ─────────────────────────────────
                # CHANGED: advance_key() handles LFSR step, DH regen if the
                # pool is exhausted, and register writes — all previously done
                # inline in the P4 dataplane.
                if rcv_trigger_dh:
                    hop = int(rcv_hop_idx)
                    if hop in ctrl_state:
                        try:
                            advance_key(p4info, switch_conns, hop,
                                        refresh_rate,
                                        hermes_host, hermes_port,
                                        G, P, rcv_flow_id)
                        except Exception as e:
                            print(f"[digest] advance_key error hop={hop}: {e}")
                    else:
                        print(f"[digest] No ctrl_state for hop_idx={hop} — skipping advance")

                # ── VERIFY ────────────────────────────────────────────────
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
# Probe packet construction and injection  (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def build_probe(flow_id: int, seq: int) -> bytes:
    """
    Build a raw Ethernet frame carrying a Hermes data packet.
    Layout: Ethernet(14) + hermes_base(4) + hermes_data(26)
    """
    dst_mac      = bytes.fromhex("080000000302")
    src_mac      = bytes.fromhex("080000000101")
    eth          = struct.pack("!6s6sH", dst_mac, src_mac, ETHERTYPE_HERMES)
    accumulator  = 0
    key_index    = 0
    hop_count    = 0
    timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFFFFFF
    nonce        = random.randint(0, 0xFFFFFFFF)

    base = struct.pack("!BBH", MSG_DATA, 1, 0)
    data = (struct.pack("!I", accumulator & 0xFFFFFFFF)
          + struct.pack("!H", key_index & 0xFFFF)
          + struct.pack("!H", hop_count & 0xFFFF)
          + struct.pack("!I", flow_id & 0xFFFFFFFF)
          + struct.pack("!I", seq & 0xFFFFFFFF)
          + struct.pack("!I", (timestamp_ms >> 16) & 0xFFFFFFFF)
          + struct.pack("!H", timestamp_ms & 0xFFFF)
          + struct.pack("!I", nonce & 0xFFFFFFFF))

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
#
# CHANGED:
#   • install_switch_keys now writes accumulate_table.
#   • init_switch_registers writes reg_key_index + reg_countdown only.
#   • ctrl_state is populated here so advance_key() can track LFSR state.
#   • listen_for_digests receives refresh_rate so it can pass it to advance_key.
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
      - DH_INIT with Hermes for each switch
      - Install accumulate_table entries (merged key+opcode table)
      - Initialise reg_key_index=0, reg_countdown=refresh_rate
      - Populate ctrl_state for controller-side LFSR tracking
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

    # DH exchange, table install, register init, ctrl_state population
    dh_results = {}
    for hop_idx, (sw_id, sw_conn) in enumerate([("s1", s1), ("s2", s2), ("s3", s3)]):
        num_keys  = random.randint(NUM_KEYS_MIN, NUM_KEYS_MAX)
        dh_result = dh_with_hermes(sw_id, hermes_host, hermes_port,
                                   G, P, num_keys)
        dh_results[hop_idx] = dh_result

        # Write accumulate_table entries
        install_switch_keys(p4info, sw_conn, flow_id, hop_idx, dh_result)

        # Initialise the two dataplane registers
        init_switch_registers(p4info, sw_conn, hop_idx, refresh_rate)

        # Populate controller-side LFSR state for this switch
        ctrl_state[hop_idx] = {
            "lfsr":      0,                       # 0 = sequential phase
            "key_idx":   0,
            "initial":   True,
            "num_keys":  dh_result["num_keys"],
            "lfsr_seed": dh_result["lfsr_seed"],
            "keys":      dh_result["keys"],
            "opcodes":   dh_result["opcodes"],
        }

    # Register path with Hermes before sending any probes
    register_path_with_hermes(hermes_host, hermes_port,
                              flow_id=flow_id,
                              path=["s1", "s2", "s3"])

    # Forward entries: each switch forwards on port 2
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
                  switch_conns, G, P, flow_id, refresh_rate),
            daemon=True)
        t.start()

    return switch_conns


# ─────────────────────────────────────────────────────────────────────────────
# Throughput test  (unchanged except refresh_rate forwarded to digest listener)
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
              switch_conns, G, P, 1, refresh_rate),
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
        totals  = [r[0] for r in valid]
        accepts = sum(1 for r in valid if r[3])
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
                    help="Packets per key before controller-driven key rotation")
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
