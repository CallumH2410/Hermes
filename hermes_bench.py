#!/usr/bin/env python3
"""
hermes_bench.py  --  measurement toolkit for the Hermes Tofino prototype
========================================================================
Runs on the SAME hosts/switch you already use with run_hermes_bfrt.py.

It does NOT replace run_hermes_bfrt.py -- that still does the DH exchange,
installs the (flow_id, hop_count) forward + key/opcode entries, and runs the
digest->VERIFY listener. This tool generates load, captures arrivals, and
reads Tofino counters so you can measure throughput and flow-completion time.

Subcommands
-----------
  load      high-rate Hermes data-packet generator (h1).  Open/closed loop.
  rx        receiver/capture on h2: timestamps every Hermes data frame.
  fct       flow-completion-time driver (h1): flows drawn from a size
            distribution, Poisson arrivals at a target load; logs tx times.
  counters  read Tofino TX/RX port counters via bfrt_grpc (ground truth).

Frame format is byte-identical to run_hermes_bfrt.build_probe(), with an
optional 12-byte experiment tag in the payload so the receiver can group
packets into logical flows without needing a separate flow_id per flow:
    [eth 14][base 4][hermes_data 26][TAG 12][padding...]
    TAG = magic(u32=0x48455254 'HERT') | logical_flow(u32) | pkt_idx(u32)

IMPORTANT: this measures what the prototype implements. Because the switch
emits a digest -> VERIFY for every data packet at the final hop, end-to-end
*verified* throughput is bounded by the controller/server path, not the data
plane. Measure both (see METHODOLOGY.md).
"""

import argparse, csv, os, random, socket, struct, sys, time

ETHERTYPE_HERMES = 0xD1F1
MSG_DATA = 0
TAG_MAGIC = 0x48455254                      # 'HERT'
DATA_HDR_LEN = 26
HDR_LEN = 14 + 4 + DATA_HDR_LEN             # 44
TAG_LEN = 12
MIN_FRAME = 60

DST_MAC = bytes.fromhex("080000000302")     # h2 MAC  (match run_hermes_bfrt.py)
SRC_MAC = bytes.fromhex("080000000101")     # h1 MAC


# ───────────────────────────── frame builder ────────────────────────────────
def build_frame(flow_id, seq, logical_flow=0, pkt_idx=0, size=MIN_FRAME):
    """Byte-compatible with run_hermes_bfrt.build_probe + a 12B experiment tag."""
    eth = struct.pack("!6s6sH", DST_MAC, SRC_MAC, ETHERTYPE_HERMES)
    base = struct.pack("!BBH", MSG_DATA, 1, 0)
    ts = int(time.time() * 1000) & 0xFFFFFFFFFFFF
    nonce = random.getrandbits(32)
    data = (struct.pack("!I", 0)                       # accumulator
            + struct.pack("!H", 0)                     # key_index
            + struct.pack("!H", 0)                     # hop_count
            + struct.pack("!I", flow_id & 0xFFFFFFFF)
            + struct.pack("!I", seq & 0xFFFFFFFF)
            + struct.pack("!I", (ts >> 16) & 0xFFFFFFFF)
            + struct.pack("!H", ts & 0xFFFF)
            + struct.pack("!I", nonce))
    tag = struct.pack("!III", TAG_MAGIC, logical_flow & 0xFFFFFFFF, pkt_idx & 0xFFFFFFFF)
    frame = eth + base + data + tag
    if size > len(frame):
        frame += b"\x00" * (size - len(frame))
    return frame[:max(size, MIN_FRAME)] if size >= MIN_FRAME else frame + b"\x00" * (MIN_FRAME - len(frame))


def open_tx(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 22)
    except OSError:
        pass
    return s


# ───────────────────────────── pcap -> rx.csv ───────────────────────────────
def cmd_pcap2rx(a):
    """Convert a libpcap file (from `tcpdump -w`) into the rx.csv format.
    Kernel timestamps + libpcap capture drop far fewer packets than the Python
    rx loop, so use this for FCT. Supports classic (us) and nanosecond pcap."""
    with open(a.pcap, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            sys.exit("not a pcap file")
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian, nano = "<", magic == b"\x4d\x3c\xb2\xa1"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian, nano = ">", magic == b"\xa1\xb2\x3c\x4d"
        else:
            sys.exit(f"unrecognised pcap magic {magic!r} (pcapng not supported; "
                     f"use 'tcpdump -w' which writes classic pcap)")
        rec = struct.Struct(endian + "IIII")
        rows, n = [], 0
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                break
            ts_sec, ts_frac, incl, _orig = rec.unpack(rh)
            pkt = f.read(incl)
            if len(pkt) < incl:
                break
            t = ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6)
            if len(pkt) < HDR_LEN or pkt[12:14] != struct.pack("!H", ETHERTYPE_HERMES):
                continue
            if pkt[14] != MSG_DATA:
                continue
            seq = struct.unpack("!I", pkt[14 + 4 + 8:14 + 4 + 12])[0]
            lflow = pidx = -1
            if len(pkt) >= HDR_LEN + TAG_LEN:
                magic2, lflow, pidx = struct.unpack("!III", pkt[HDR_LEN:HDR_LEN + TAG_LEN])
                if magic2 != TAG_MAGIC:
                    lflow = pidx = -1
            rows.append((f"{t:.9f}", seq, lflow, pidx, len(pkt)))
            n += 1
    with open(a.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rx_time_s", "seq", "logical_flow", "pkt_idx", "frame_size"])
        w.writerows(rows)
    print(f"[pcap2rx] {n} Hermes data frames -> {a.out}")
    if n:
        flows = len({r[2] for r in rows if r[2] >= 0})
        print(f"[pcap2rx] distinct logical flows seen: {flows}")


# ───────────────────────────── load generator ───────────────────────────────
def cmd_load(a):
    """Open-loop generator: send `count` (or for `duration` s) frames, optional
    rate cap `pps`. Reuses one AF_PACKET socket (far faster than per-packet
    sockets). For true line-rate use kernel pktgen / TRex (see METHODOLOGY.md)."""
    s = open_tx(a.iface)
    frame = build_frame(a.flow_id, 1, size=a.size)
    flen = len(frame)
    gap = 1.0 / a.pps if a.pps > 0 else 0.0
    sent = 0
    bytes_sent = 0
    t0 = time.perf_counter()
    next_t = t0
    end = t0 + a.duration if a.duration > 0 else None
    seq = 1
    try:
        while True:
            if a.count and sent >= a.count:
                break
            if end and time.perf_counter() >= end:
                break
            # refresh seq/timestamp cheaply every packet only if requested
            if a.unique_seq:
                frame = build_frame(a.flow_id, seq, size=a.size)
            s.send(frame)
            sent += 1
            seq += 1
            bytes_sent += flen
            if gap:
                next_t += gap
                now = time.perf_counter()
                if next_t > now:
                    time.sleep(next_t - now)
    except KeyboardInterrupt:
        pass
    dt = time.perf_counter() - t0
    s.close()
    pps = sent / dt if dt else 0
    gbps = bytes_sent * 8 / dt / 1e9 if dt else 0
    print(f"[load] sent={sent} frames  size={flen}B  dur={dt:.3f}s  "
          f"rate={pps:,.0f} pps  {gbps:.3f} Gbps (offered at h1)")
    if a.out:
        new = not os.path.exists(a.out)
        with open(a.out, "a", newline="") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["frame_size", "target_pps", "sent", "duration_s",
                            "achieved_pps", "offered_gbps"])
            w.writerow([flen, a.pps, sent, f"{dt:.6f}", f"{pps:.1f}", f"{gbps:.4f}"])
        print(f"[load] appended summary to {a.out}")


# ───────────────────────────── receiver / capture ───────────────────────────
def cmd_rx(a):
    """Capture Hermes data frames on h2; log per-packet rx timestamp + tag.
    Run this BEFORE starting load/fct on h1. Stop with Ctrl-C or --duration."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((a.iface, 0))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 25)
    # Hermes frames use a fixed dst MAC (08:00:00:00:03:02) that won't match this
    # NIC, so without promiscuous mode the hardware drops them before capture.
    promisc_on = False
    if a.promisc:
        try:
            SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
            PACKET_ADD_MEMBERSHIP = getattr(socket, "PACKET_ADD_MEMBERSHIP", 1)
            PACKET_MR_PROMISC = 1
            ifidx = socket.if_nametoindex(a.iface)
            mreq = struct.pack("iHH8s", ifidx, PACKET_MR_PROMISC, 0, b"")
            s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
            promisc_on = True
            print(f"[rx] promiscuous mode enabled on {a.iface}")
        except OSError as e:
            print(f"[rx] WARNING: could not enable promisc ({e}); "
                  f"run 'sudo ip link set {a.iface} promisc on' manually")
    s.settimeout(1.0)
    rows = []
    n = 0
    t0 = None
    end = time.perf_counter() + a.duration if a.duration > 0 else None
    print(f"[rx] capturing Hermes frames on {a.iface} ... Ctrl-C to stop")
    try:
        while True:
            if end and time.perf_counter() >= end:
                break
            try:
                pkt = s.recv(2048)
            except socket.timeout:
                continue
            now = time.perf_counter()
            if len(pkt) < HDR_LEN or pkt[12:14] != struct.pack("!H", ETHERTYPE_HERMES):
                continue
            if pkt[14] != MSG_DATA:
                continue
            t0 = t0 or now
            # parse seq from data header, and tag if present
            seq = struct.unpack("!I", pkt[14 + 4 + 8:14 + 4 + 12])[0]
            lflow = pidx = -1
            if len(pkt) >= HDR_LEN + TAG_LEN:
                magic, lflow, pidx = struct.unpack("!III", pkt[HDR_LEN:HDR_LEN + TAG_LEN])
                if magic != TAG_MAGIC:
                    lflow = pidx = -1
            rows.append((f"{now:.9f}", seq, lflow, pidx, len(pkt)))
            n += 1
    except KeyboardInterrupt:
        pass
    s.close()
    if t0 and rows:
        span = float(rows[-1][0]) - float(rows[0][0])
        pps = n / span if span else 0
        print(f"[rx] received={n} frames  span={span:.3f}s  rate={pps:,.0f} pps (delivered to h2)")
    else:
        print(f"[rx] received 0 Hermes frames on {a.iface}.")
        print("     Diagnose with:  sudo tcpdump -i %s -e -n ether proto 0xd1f1" % a.iface)
        print("     - frames in tcpdump but 0 here  -> promisc/socket issue (try --promisc)")
        print("     - nothing in tcpdump either     -> forwarding/cabling: check the iface is")
        print("       UP, cabled to switch egress port 65 (57/1), and run_hermes_bfrt.py is up")
        print("       with flow_id=1 installed.")
    with open(a.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rx_time_s", "seq", "logical_flow", "pkt_idx", "frame_size"])
        w.writerows(rows)
    print(f"[rx] wrote {len(rows)} rows to {a.out}")


# ───────────────────────────── flow-size distribution ───────────────────────
# Default = DCTCP "web-search"-style CDF (flow size in BYTES -> cumulative prob).
# REPLACE with the distribution fctm uses if different (see METHODOLOGY.md).
WEBSEARCH_CDF = [
    (10_000, 0.15), (20_000, 0.20), (30_000, 0.30), (50_000, 0.40),
    (80_000, 0.53), (200_000, 0.60), (1_000_000, 0.70), (2_000_000, 0.80),
    (5_000_000, 0.90), (10_000_000, 0.97), (30_000_000, 1.00),
]


def sample_flow_size(rng, cdf=WEBSEARCH_CDF):
    u = rng.random()
    prev_sz, prev_p = 1_000, 0.0
    for sz, p in cdf:
        if u <= p:
            # log-uniform interpolation between breakpoints
            import math
            frac = (u - prev_p) / (p - prev_p) if p > prev_p else 0
            lo, hi = math.log(prev_sz), math.log(sz)
            return int(math.exp(lo + frac * (hi - lo)))
        prev_sz, prev_p = sz, p
    return cdf[-1][0]


# ───────────────────────────── FCT driver ───────────────────────────────────
def cmd_fct(a):
    """Generate `nflows` flows: sizes ~ distribution, Poisson arrivals tuned to
    `load` (fraction of `linkrate` Gbps). Each flow's packets carry a unique
    logical_flow tag so the h2 capture can reconstruct per-flow completion.
    Logs per-flow tx start/end; FCT is computed offline by analyze_hermes.py by
    joining this with the rx capture."""
    rng = random.Random(a.seed)
    s = open_tx(a.iface)
    payload = a.size                                  # bytes per packet on wire
    line_bps = a.linkrate * 1e9
    # mean flow size (bytes) for arrival-rate calc
    sizes = [sample_flow_size(rng) for _ in range(a.nflows)]
    mean_sz = sum(sizes) / len(sizes)
    # offered load L = lambda * mean_sz * 8 / line_bps  ->  lambda
    lam = (a.load * line_bps) / (mean_sz * 8) if mean_sz else 1.0
    print(f"[fct] {a.nflows} flows  mean_size={mean_sz/1e3:.1f} kB  "
          f"target_load={a.load:.2f}  arrival_rate={lam:.1f} flows/s")
    rows = []
    t_start = time.perf_counter()
    next_arr = t_start
    for fid, sz in enumerate(sizes):
        # wait until this flow's Poisson arrival time
        now = time.perf_counter()
        if next_arr > now:
            time.sleep(next_arr - now)
        npkts = max(1, -(-sz // payload))            # ceil
        f_tx0 = time.perf_counter()
        for i in range(npkts):
            s.send(build_frame(a.flow_id, i + 1, logical_flow=fid, pkt_idx=i, size=payload))
        f_tx1 = time.perf_counter()
        rows.append((fid, sz, npkts, f"{f_tx0:.9f}", f"{f_tx1:.9f}"))
        next_arr += rng.expovariate(lam) if lam > 0 else 0
    s.close()
    with open(a.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["logical_flow", "size_bytes", "n_pkts", "tx_first_s", "tx_last_s"])
        w.writerows(rows)
    print(f"[fct] sent {len(rows)} flows in {time.perf_counter()-t_start:.2f}s -> {a.out}")
    print("[fct] now stop the h2 rx capture and run: "
          "analyze_hermes.py fct --tx <thisfile> --rx <rxfile>")


# ───────────────────────────── Tofino counters ──────────────────────────────
def cmd_counters(a):
    """Read TX/RX frame + byte counters for a device port via bfrt_grpc.
    Run with --phase before and again with --phase after; analyze diffs.
    NOTE: counter table/field names vary by SDE version -- adjust if needed."""
    try:
        import bfrt_grpc.client as gc
    except ImportError:
        sys.exit("bfrt_grpc not found; set PYTHONPATH to the SDE as in run_hermes_bfrt.py")
    iface = gc.ClientInterface(f"{a.switch}:{a.grpc_port}", client_id=0, device_id=0)
    iface.bind_pipeline_config("hermes_line")
    info = iface.bfrt_info_get("hermes_line")
    tgt = gc.Target(device_id=0)
    port_stat = info.table_get("$PORT_STAT")          # SDE-standard port stats table
    key = port_stat.make_key([gc.KeyTuple("$DEV_PORT", a.dev_port)])
    resp = port_stat.entry_get(tgt, [key], {"from_hw": True})
    data = next(resp)[0].to_dict()
    rxf = data.get("$FramesReceivedOK") or data.get("$FramesReceivedAll", 0)
    txf = data.get("$FramesTransmittedOK") or data.get("$FramesTransmittedAll", 0)
    rxb = data.get("$OctetsReceived", 0)
    txb = data.get("$OctetsTransmitted", 0)
    ts = time.time()
    print(f"[counters] dev_port={a.dev_port} phase={a.phase}  "
          f"rx_frames={rxf} tx_frames={txf} rx_bytes={rxb} tx_bytes={txb}")
    new = not os.path.exists(a.out)
    with open(a.out, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["phase", "wall_time", "dev_port", "rx_frames", "tx_frames",
                        "rx_bytes", "tx_bytes"])
        w.writerow([a.phase, f"{ts:.6f}", a.dev_port, rxf, txf, rxb, txb])
    print(f"[counters] wrote row to {a.out}")
    # Cleanup: method name varies across SDE versions; never let it crash the run.
    for m in ("_tear_down_stream", "tear_down_stream", "close"):
        fn = getattr(iface, m, None)
        if callable(fn):
            try:
                fn()
            except Exception:
                pass
            break


# ───────────────────────────── CLI ──────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("load", help="high-rate generator (h1)")
    pl.add_argument("--iface", required=True)
    pl.add_argument("--flow-id", type=int, default=1, dest="flow_id")
    pl.add_argument("--size", type=int, default=64, help="on-wire frame bytes (>=60)")
    pl.add_argument("--pps", type=float, default=0, help="target pps (0 = max)")
    pl.add_argument("--count", type=int, default=0)
    pl.add_argument("--duration", type=float, default=0, help="seconds (0 = use count)")
    pl.add_argument("--unique-seq", action="store_true",
                    help="rebuild frame each packet for unique seq/ts (slower)")
    pl.add_argument("--out", default="")
    pl.set_defaults(func=cmd_load)

    pr = sub.add_parser("rx", help="receiver/capture (h2)")
    pr.add_argument("--iface", required=True)
    pr.add_argument("--duration", type=float, default=0)
    pr.add_argument("--out", default="rx.csv")
    pr.add_argument("--promisc", dest="promisc", action="store_true", default=True,
                    help="enable promiscuous mode (default on)")
    pr.add_argument("--no-promisc", dest="promisc", action="store_false")
    pr.set_defaults(func=cmd_rx)

    pf = sub.add_parser("fct", help="flow-completion-time driver (h1)")
    pf.add_argument("--iface", required=True)
    pf.add_argument("--flow-id", type=int, default=1, dest="flow_id")
    pf.add_argument("--size", type=int, default=1500, help="bytes per packet on wire")
    pf.add_argument("--nflows", type=int, default=2000)
    pf.add_argument("--load", type=float, default=0.3, help="offered load fraction of linkrate")
    pf.add_argument("--linkrate", type=float, default=10.0, help="Gbps")
    pf.add_argument("--seed", type=int, default=1)
    pf.add_argument("--out", default="fct_tx.csv")
    pf.set_defaults(func=cmd_fct)

    pp = sub.add_parser("pcap2rx", help="convert tcpdump pcap -> rx.csv (for FCT)")
    pp.add_argument("--pcap", required=True)
    pp.add_argument("--out", default="rx.csv")
    pp.set_defaults(func=cmd_pcap2rx)

    pc = sub.add_parser("counters", help="read Tofino port counters")
    pc.add_argument("--switch", required=True)
    pc.add_argument("--grpc-port", type=int, default=50052)
    pc.add_argument("--dev-port", type=int, required=True)
    pc.add_argument("--phase", choices=["before", "after"], required=True)
    pc.add_argument("--out", default="counters.csv")
    pc.set_defaults(func=cmd_counters)

    a = p.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()