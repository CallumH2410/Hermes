#!/usr/bin/env python3
# run_hermes_bfrt.py — single-switch version (h1 → s1 → h2)
#
# Topology: h1 ──── sw1 ──── h2
#                 (s1, hop_idx=0)
#
# Usage:
#   sudo python3 run_hermes_bfrt.py \
#       --s1          10.10.2.47  \
#       --s1-h2-port  <dev_port>  \   # device port on sw1 facing h2
#       --h1-iface    <iface>     \   # NIC on h1 (or this machine) facing sw1
#       --hermes-host 127.0.0.1
#
# Finding device port numbers:
#   On sw1 run:  ucli pm show
#   Read the D_P column for the front-panel port your h2 cable is plugged into.
#   Example: front-panel 3/0 shows D_P = 2  →  pass --s1-h2-port 2
#
# What this script does:
#   1. Connects to sw1 via BF-RT gRPC
#   2. Performs DH_INIT with Hermes server (generates shared keys for hop 0)
#   3. Installs accumulate_table entries (key + opcode per key index)
#   4. Installs forward table entry: (flow_id, hop_count=0) → h2 dev_port
#   5. Initialises reg_key_index[0]=0, reg_countdown[0]=refresh_rate
#   6. Registers path ["s1"] with Hermes server
#   7. Starts digest listener on sw1 (final hop = 1 in this topology)
#   8. Sends probe packet(s) from h1
#   9. Prints ACCEPT / REJECT for each probe

import argparse
import queue
import random
import socket
import struct
import sys
import threading
import time
import ssl

try:
    import bfrt_grpc.client as gc
except ImportError:
    sys.exit(
        "ERROR: bfrt_grpc not found.\n"
        "Add $SDE_INSTALL/lib/python3/dist-packages to PYTHONPATH:\n"
        "  export PYTHONPATH=$SDE_INSTALL/lib/python3/dist-packages:$PYTHONPATH"
    )

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
ETHERTYPE_HERMES = 0xD1F1
MSG_DATA         = 0
NUM_KEYS_MIN     = 330
NUM_KEYS_MAX     = 350
BFRT_GRPC_PORT   = 50052
P4_PROGRAM       = "hermes_line"

# Single switch → single hop
HOP_IDX          = 0
NUM_HOPS         = 1   # must match `hop_count == 1` in hermes_line_tna.p4

# Opcode → accumulate_table action name
OP_ADD    = 0;  OP_ROT_BA = 1;  OP_ROT_AB = 2;  OP_AND    = 3
OP_OR     = 4;  OP_SUB_BA = 5;  OP_SUB_AB = 6;  OP_XOR    = 7

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
# Accumulator / LFSR helpers
# ─────────────────────────────────────────────────────────────────────────────

def rot_left(a: int, b: int) -> int:
    amount  = (b >> 27) & 0x1f
    add_val = b & 0x07FFFFFF
    a &= 0xFFFFFFFF
    rotated = a if amount == 0 else ((a << amount) | (a >> (32 - amount))) & 0xFFFFFFFF
    return (rotated + add_val) & 0xFFFFFFFF

def lfsr_next(state: int) -> int:
    return ((state >> 1) ^ 0xB4BCD35C) if (state & 1) else (state >> 1)

# ─────────────────────────────────────────────────────────────────────────────
# TCP / Hermes server helpers
# ─────────────────────────────────────────────────────────────────────────────
def hermes_tls_socket(hermes_host: str, hermes_port: int):
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile="certs/ca.crt",
    )

    context.load_cert_chain(
        certfile="certs/client.crt",
        keyfile="certs/client.key",
    )

    # For local test certs where CN=127.0.0.1, hostname checking can be awkward.
    # Keep this False for the prototype if you connect by IP.
    context.check_hostname = False

    raw = socket.create_connection((hermes_host, hermes_port))
    return context.wrap_socket(raw, server_hostname=hermes_host)

def tcp_readline(sock) -> str:
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("Connection closed")
        buf += chunk
    return buf.decode().strip()

def dh_public_key(G, P, secret):
    return ((G ^ P) & secret) & 0xFFFFFFFF

def dh_shared_key(K_other, my_secret, P):
    return ((K_other & my_secret) ^ P) & 0xFFFFFFFF

def dh_with_hermes(sw_id: str, hermes_host: str, hermes_port: int,
                   G: int, P: int, is_regen: bool = False) -> dict:
    """Perform DH_INIT (or DH_KEY regen) with the Hermes server."""
    B_list  = [random.randint(1, 0xFFFFFFFE) for _ in range(NUM_KEYS_MAX)]
    Ka_list = [dh_public_key(G, P, B) for B in B_list]
    cmd = "DH_KEY" if is_regen else "DH_INIT"
    msg = f"{cmd} {sw_id} {G} {P} " + " ".join(str(k) for k in Ka_list) + "\n"

    s = hermes_tls_socket(hermes_host, hermes_port)
    t0 = time.perf_counter()
    s.sendall(msg.encode())
    resp = tcp_readline(s)
    t1 = time.perf_counter()
    s.close()

    resp_cmd = "DH_KEY_RESP" if is_regen else "DH_RESP"
    parts = resp.split()
    if parts[0] != resp_cmd:
        raise RuntimeError(f"Expected {resp_cmd}, got: {resp}")

    idx = 1
    n        = int(parts[idx]); idx += 1
    Kb_list  = [int(parts[idx + i]) for i in range(NUM_KEYS_MAX)]; idx += NUM_KEYS_MAX
    op_list  = [int(parts[idx + i]) for i in range(NUM_KEYS_MAX)]; idx += NUM_KEYS_MAX
    lfsr_seed = int(parts[idx])

    Kb_list = Kb_list[:n]; op_list = op_list[:n]
    shared  = [dh_shared_key(Kb_list[i], B_list[i], P) for i in range(n)]

    print(f"[{sw_id}] DH {'regen' if is_regen else 'init'}: "
          f"num_keys={n} lfsr_seed=0x{lfsr_seed:08x} RTT={(t1-t0)*1000:.1f}ms")
    return {"keys": shared, "opcodes": op_list, "lfsr_seed": lfsr_seed, "num_keys": n}

def verify_with_hermes(hermes_host: str, hermes_port: int,
                       flow_id: int, hop_count: int, acc: int,
                       seq: int, timestamp_ms: int, nonce: int) -> bool:
    s = hermes_tls_socket(hermes_host, hermes_port)
    try:
        s.sendall(f"VERIFY {flow_id} {hop_count} {acc} {seq} {timestamp_ms} {nonce}\n".encode())
        parts = tcp_readline(s).split()
        return len(parts) == 2 and parts[0] == "RESULT" and parts[1] == "ACCEPT"
    finally:
        s.close()

def register_path_with_hermes(hermes_host: str, hermes_port: int,
                               flow_id: int, path: list):
    msg = f"PATH_REGISTER {flow_id} {len(path)} " + " ".join(path) + "\n"
    s = hermes_tls_socket(hermes_host, hermes_port)
    s.sendall(msg.encode())
    resp = tcp_readline(s)
    s.close()
    parts = resp.split()
    if parts[0] != "PATH_ACK" or int(parts[1]) != flow_id:
        raise RuntimeError(f"PATH_REGISTER failed: {resp}")
    print(f"[hermes] Path registered flow={flow_id}: {' -> '.join(path)}")

# ─────────────────────────────────────────────────────────────────────────────
# BF-RT connection
# ─────────────────────────────────────────────────────────────────────────────

def bfrt_connect(switch_ip: str, device_id: int = 0):
    """Connect to a Tofino switch's BF-RT gRPC server."""
    grpc_addr = f"{switch_ip}:{BFRT_GRPC_PORT}"
    # Clear all proxy env vars — gRPC ignores no_proxy and routes via HTTP proxy
    # which returns 403 for localhost connections.
    import os
    for _k in ['http_proxy','https_proxy','HTTP_PROXY','HTTPS_PROXY',
               'ftp_proxy','FTP_PROXY']:
        os.environ.pop(_k, None)

    interface = gc.ClientInterface(
        grpc_addr=grpc_addr,
        client_id=0,
        device_id=device_id,
        perform_subscribe=True,
    )
    print(f"[bfrt] Subscribed to {grpc_addr}")
    interface.bind_pipeline_config(P4_PROGRAM)
    print(f"[bfrt] Pipeline bound: {P4_PROGRAM}")
    bfrt_info = interface.bfrt_info_get(P4_PROGRAM)
    target    = gc.Target(device_id=device_id, pipe_id=0xFFFF)
    print(f"[bfrt] Connected to {grpc_addr}")
    return interface, bfrt_info, target

# ─────────────────────────────────────────────────────────────────────────────
# BF-RT table helpers
# ─────────────────────────────────────────────────────────────────────────────

def _tbl(bfrt_info, name: str):
    for candidate in (f"pipe.{name}", name):
        try:
            return bfrt_info.table_get(candidate)
        except Exception:
            continue
    raise KeyError(f"Table not found: {name}")

def install_switch_keys(bfrt_info, target, flow_id: int,
                        hop_idx: int, dh_result: dict):
    """
    Write one accumulate_table entry per key.
    accumulate_table key:  (flow_id, hop_count, key_index)
    accumulate_table data: action = OPCODE_ACTION[opcode], param kv = key value
    """
    tbl = _tbl(bfrt_info, "MyIngress.accumulate_table")
    added = 0; modified = 0
    for idx, (key, op) in enumerate(zip(dh_result["keys"], dh_result["opcodes"])):
        action = OPCODE_ACTION.get(op, "do_add")
        k = tbl.make_key([
            gc.KeyTuple("hdr.data.flow_id",   flow_id),
            gc.KeyTuple("hdr.data.hop_count", hop_idx),
            gc.KeyTuple("hdr.data.key_index", idx),
        ])
        d = tbl.make_data([gc.DataTuple("kv", key)], f"MyIngress.{action}")
        try:
            tbl.entry_add(target, [k], [d])
            added += 1
        except Exception:
            # Entry exists from a previous run — modify in place
            tbl.entry_mod(target, [k], [d])
            modified += 1
    print(f"[controller] accumulate_table hop={hop_idx} flow={flow_id}: "
          f"{added} added, {modified} modified ({dh_result['num_keys']} total)")

def install_forward(bfrt_info, target, flow_id: int, hop_idx: int, dev_port: int):
    """
    forward table: (flow_id, hop_count=hop_idx) → set_egress(dev_port)
    hop_count in the packet equals hop_idx when the packet arrives at that switch
    (s1 receives packets with hop_count=0).
    """
    tbl = _tbl(bfrt_info, "MyIngress.forward")
    k   = tbl.make_key([
        gc.KeyTuple("hdr.data.flow_id",   flow_id),
        gc.KeyTuple("hdr.data.hop_count", hop_idx),
    ])
    d   = tbl.make_data([gc.DataTuple("port", dev_port)], "MyIngress.set_egress")
    try:
        tbl.entry_add(target, [k], [d])
    except Exception:
        tbl.entry_mod(target, [k], [d])
    print(f"[controller] forward (flow={flow_id}, hop={hop_idx}) → dev_port={dev_port}")

def write_register(bfrt_info, target, reg_name: str, index: int, value: int):
    tbl        = _tbl(bfrt_info, f"MyIngress.{reg_name}")
    k          = tbl.make_key([gc.KeyTuple("$REGISTER_INDEX", index)])
    field_name = f"MyIngress.{reg_name}.f1"
    d          = tbl.make_data([gc.DataTuple(field_name, value)])
    tbl.entry_mod(target, [k], [d])

def init_registers(bfrt_info, target, hop_idx: int, refresh_rate: int):
    write_register(bfrt_info, target, "reg_key_index", hop_idx, 0)
    # Initialise countdown to 0 so the very first packet triggers an advance.
    # With refresh_rate=R, the switch advances key every R packets:
    #   countdown=0 → trigger on packet 1 → reset to R-1
    #   countdown decrements R-1→0 → trigger again on packet R+1, etc.
    write_register(bfrt_info, target, "reg_countdown",  hop_idx, 0)
    print(f"[controller] Registers hop={hop_idx}: key_index=0 countdown=0 (refresh_rate={refresh_rate})")

# ─────────────────────────────────────────────────────────────────────────────
# Controller-side LFSR / key-advance state
# ─────────────────────────────────────────────────────────────────────────────
ctrl_state: dict = {}   # hop_idx → state dict

def advance_key(bfrt_info, target, hop_idx: int, refresh_rate: int,
                hermes_host: str, hermes_port: int,
                G: int, P: int, flow_id: int):
    """
    Called when digest.trigger_dh != 0.
    Steps the LFSR; triggers DH regen when the key pool is exhausted.
    Writes updated reg_key_index and resets reg_countdown.
    """
    st = ctrl_state[hop_idx]

    if st["initial"]:
        st["key_idx"] += 1
        if st["key_idx"] >= st["num_keys"]:
            # Pool exhausted — seed LFSR and trigger DH regen
            st["initial"] = False
            st["lfsr"]    = lfsr_next(st["lfsr_seed"])
            st["key_idx"] = st["lfsr"] % st["num_keys"]
            sw_name = f"s{hop_idx + 1}"
            print(f"[controller] Key pool exhausted for {sw_name} — DH regen")
            try:
                new_dh = dh_with_hermes(sw_name, hermes_host, hermes_port,
                                        G, P, is_regen=True)
                install_switch_keys(bfrt_info, target, flow_id, hop_idx, new_dh)
                ctrl_state[hop_idx].update({
                    "keys": new_dh["keys"],       "opcodes": new_dh["opcodes"],
                    "lfsr_seed": new_dh["lfsr_seed"], "num_keys": new_dh["num_keys"],
                    "initial": True, "key_idx": 0, "lfsr": 0,
                })
                st = ctrl_state[hop_idx]
                print(f"[controller] DH regen complete for {sw_name}")
            except Exception as e:
                print(f"[controller] DH regen error: {e}")
    else:
        st["lfsr"]    = lfsr_next(st["lfsr"])
        st["key_idx"] = st["lfsr"] % st["num_keys"]

    write_register(bfrt_info, target, "reg_key_index", hop_idx, st["key_idx"])
    # Reset countdown to refresh_rate-1 so the advance fires every refresh_rate packets.
    # refresh_rate=1 → always 0 → every packet triggers advance (one key per packet).
    # refresh_rate=N → resets to N-1 → next advance fires N packets later.
    next_countdown = max(0, refresh_rate - 1)
    write_register(bfrt_info, target, "reg_countdown",  hop_idx, next_countdown)
    print(f"[controller] hop={hop_idx} key_idx={st['key_idx']} "
          f"lfsr=0x{st['lfsr']:08x} countdown reset={next_countdown}")

# ─────────────────────────────────────────────────────────────────────────────
# Digest listener  (runs on sw1 — the only and final switch)
# ─────────────────────────────────────────────────────────────────────────────

def listen_for_digests(interface, bfrt_info, target,
                       hermes_host: str, hermes_port: int,
                       G: int, P: int, flow_id: int,
                       refresh_rate: int,
                       result_queue: queue.Queue,
                       verbose: bool):
    """
    Polls sw1's BF-RT interface for hermes_digest_t learn notifications.
    For a single-switch topology sw1 is both the only hop and the final hop,
    so the digest fires here after hop_count reaches 1.
    """
    # Get the learn object once — used to parse raw digests into data objects.
    # Name from bfrt_info.learn_name_list_get(): "pipe.IngressDeparser.hermes_digest"
    LEARN_NAME = "pipe.IngressDeparser.hermes_digest"
    learn_obj  = bfrt_info.learn_get(LEARN_NAME)

    print("[digest] Listener started on sw1 — waiting for hermes_digest_t")
    while True:
        try:
            # Step 1: get raw digest message from the stream channel
            raw = interface.digest_get(timeout=1)
            if raw is None:
                continue

            # Step 2: parse raw digest into a list of _Data objects
            data_list = learn_obj.make_data_list(raw)
            if not data_list:
                continue

            for data_obj in data_list:
                # Step 3: convert _Data to dict and extract fields
                try:
                    d = data_obj.to_dict()
                except AttributeError:
                    # Fallback: some SDE versions use __str__ or field accessors
                    d = {}
                    for fname in ["flow_id","hop_count","accumulator","seq",
                                  "timestamp_ms","nonce","trigger_dh","hop_idx"]:
                        try:
                            d[fname] = data_obj[fname]
                        except Exception:
                            d[fname] = 0

                flow_id_r    = int(d.get("flow_id",      0))
                hop_count_r  = int(d.get("hop_count",    0))
                acc_r        = int(d.get("accumulator",  0))
                seq_r        = int(d.get("seq",          0))
                ts_ms_r      = int(d.get("timestamp_ms", 0))
                nonce_r      = int(d.get("nonce",        0))
                trigger_dh_r = int(d.get("trigger_dh",  0))
                hop_idx_r    = int(d.get("hop_idx",      0))
                e = d   # keep rest of code unchanged

                digest_time = time.perf_counter()
                if verbose:
                    print(f"[digest] flow={flow_id_r} hops={hop_count_r} "
                          f"acc={acc_r:#010x} seq={seq_r} nonce={nonce_r:#010x} "
                          f"trigger_dh={trigger_dh_r}")

                # Key advance / DH regen
                if trigger_dh_r and HOP_IDX in ctrl_state:
                    try:
                        advance_key(bfrt_info, target, HOP_IDX, refresh_rate,
                                    hermes_host, hermes_port, G, P, flow_id_r)
                    except Exception as ex:
                        print(f"[digest] advance_key error: {ex}")

                # VERIFY with Hermes
                verify_start = time.perf_counter()
                ok = verify_with_hermes(hermes_host, hermes_port,
                                        flow_id_r, hop_count_r, acc_r,
                                        seq_r, ts_ms_r, nonce_r)
                verify_time = time.perf_counter()

                status = "ACCEPT" if ok else "REJECT"
                print(f"[digest] Hermes verification: {status} "
                      f"(RTT={(verify_time-verify_start)*1000:.2f}ms)")

                if result_queue is not None:
                    result_queue.put((digest_time, verify_time, ok))

        except Exception as ex:
            err = str(ex)
            if "timeout" not in err.lower() and "deadline" not in err.lower():
                print(f"[digest] Warning: {ex}")
            continue

# ─────────────────────────────────────────────────────────────────────────────
# Probe packet
# ─────────────────────────────────────────────────────────────────────────────

def build_probe(flow_id: int, seq: int) -> bytes:
    """Build a raw Ethernet Hermes data frame with hop_count=0, accumulator=0."""
    dst_mac      = bytes.fromhex("080000000302")   # h2 MAC — adjust if needed
    src_mac      = bytes.fromhex("080000000101")   # h1 MAC — adjust if needed
    eth          = struct.pack("!6s6sH", dst_mac, src_mac, ETHERTYPE_HERMES)
    timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFFFFFF
    nonce        = random.randint(0, 0xFFFFFFFF)
    base = struct.pack("!BBH", MSG_DATA, 1, 0)           # msg_type=0, version=1
    data = (struct.pack("!I", 0)                         # accumulator = 0
          + struct.pack("!H", 0)                         # key_index   = 0
          + struct.pack("!H", 0)                         # hop_count   = 0
          + struct.pack("!I", flow_id & 0xFFFFFFFF)
          + struct.pack("!I", seq     & 0xFFFFFFFF)
          + struct.pack("!I", (timestamp_ms >> 16) & 0xFFFFFFFF)  # ts_hi
          + struct.pack("!H",  timestamp_ms        & 0xFFFF)      # ts_lo
          + struct.pack("!I", nonce   & 0xFFFFFFFF))
    frame = eth + base + data
    return frame + b"\x00" * max(0, 60 - len(frame))

def send_probe(iface: str, flow_id: int, seq: int, verbose: bool = True) -> float:
    """Send one probe on a raw AF_PACKET socket. Must run as root."""
    import socket as _socket
    frame = build_probe(flow_id, seq)
    s = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW)
    s.bind((iface, 0))
    t = time.perf_counter()
    s.send(frame)
    s.close()
    if verbose:
        print(f"[h1] Sent probe seq={seq} flow_id={flow_id} on {iface}")
    return t

# ─────────────────────────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────────────────────────

def setup(args) -> tuple:
    """Connect to sw1, run DH, install tables, start digest listener."""

    # 1. Connect to sw1
    interface, bfrt_info, target = bfrt_connect(args.s1, device_id=0)

    # 2. DH exchange with Hermes for hop 0 (s1)
    dh = dh_with_hermes("s1", args.hermes_host, args.hermes_port,
                         args.G, args.P)

    # 3. Install accumulate_table entries for hop 0
    install_switch_keys(bfrt_info, target, args.flow_id, HOP_IDX, dh)

    # 4. Install forward entry: (flow_id, hop_count=0) → h2 device port
    install_forward(bfrt_info, target, args.flow_id, HOP_IDX, args.s1_h2_port)

    # 5. Initialise registers
    init_registers(bfrt_info, target, HOP_IDX, args.refresh_rate)

    # 6. Populate controller-side LFSR state
    ctrl_state[HOP_IDX] = {
        "lfsr":      0,
        "key_idx":   0,
        "initial":   True,
        "num_keys":  dh["num_keys"],
        "lfsr_seed": dh["lfsr_seed"],
        "keys":      dh["keys"],
        "opcodes":   dh["opcodes"],
    }

    # 7. Register single-switch path with Hermes
    register_path_with_hermes(args.hermes_host, args.hermes_port,
                              args.flow_id, ["s1"])

    # 8. Start digest listener thread (sw1 is the final hop for this topology)
    result_queue = queue.Queue()
    t = threading.Thread(
        target=listen_for_digests,
        args=(interface, bfrt_info, target,
              args.hermes_host, args.hermes_port,
              args.G, args.P, args.flow_id,
              args.refresh_rate, result_queue, True),
        daemon=True,
    )
    t.start()

    print("\n[hermes] sw1 fully programmed — ready to send probes.\n")
    return result_queue

# ─────────────────────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Hermes BF-RT controller — single switch (h1 → s1 → h2)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Finding --s1-h2-port:
  SSH into sw1, run bfshell → ucli, then:
    ucli pm show
  Find the row for the front-panel port your h2 cable is in and
  read the D_P column.  Pass that number as --s1-h2-port.

Example:
  sudo python3 run_hermes_bfrt.py \\
      --s1 10.10.2.47 \\
      --s1-h2-port 2 \\
      --h1-iface enp3s0f0 \\
      --hermes-host 127.0.0.1 \\
      --num-probes 5
""")
    ap.add_argument("--s1",           required=True,
                    help="IP address of sw1")
    ap.add_argument("--s1-h2-port",   type=int, required=True,
                    help="Device port on sw1 facing h2 (from ucli pm show, D_P column)")
    ap.add_argument("--h1-iface",     default="eth0",
                    help="Network interface on h1 to send probes from")
    ap.add_argument("--hermes-host",  default="127.0.0.1")
    ap.add_argument("--hermes-port",  type=int, default=5555)
    ap.add_argument("--G",            type=lambda x: int(x, 0), default=0x5A5A5A5A)
    ap.add_argument("--P",            type=lambda x: int(x, 0), default=0xA5A5A5A5)
    ap.add_argument("--flow-id",      type=int, default=1)
    ap.add_argument("--refresh-rate", type=int, default=50,
                    help="Packets per key before key rotation")
    ap.add_argument("--num-probes",   type=int, default=1)
    ap.add_argument("--delay-ms",     type=float, default=100.0,
                    help="Delay between probes in milliseconds")
    ap.add_argument("--timeout",      type=float, default=15.0,
                    help="Seconds to wait for verification result per probe")
    args = ap.parse_args()

    result_queue = setup(args)

    print(f"[hermes] Sending {args.num_probes} probe(s) on {args.h1_iface}")
    send_times = []
    for i in range(args.num_probes):
        t = send_probe(args.h1_iface, args.flow_id, i + 1)
        send_times.append(t)
        if args.delay_ms > 0 and i < args.num_probes - 1:
            time.sleep(args.delay_ms / 1000.0)

    print(f"[hermes] Waiting up to {args.timeout:.0f}s per probe for results...\n")
    for i in range(args.num_probes):
        try:
            digest_t, verify_t, ok = result_queue.get(timeout=args.timeout)
            send_t  = send_times[i]
            total   = (verify_t - send_t)   * 1000
            dig_lat = (digest_t - send_t)   * 1000
            ver_lat = (verify_t - digest_t) * 1000
            status  = "ACCEPT" if ok else "REJECT"
            print(f"  probe {i+1:3d}: {status}  "
                  f"total={total:.2f}ms  "
                  f"digest={dig_lat:.2f}ms  "
                  f"verify={ver_lat:.2f}ms")
        except queue.Empty:
            print(f"  probe {i+1:3d}: TIMEOUT — no digest received within {args.timeout:.0f}s")


if __name__ == "__main__":
    main()