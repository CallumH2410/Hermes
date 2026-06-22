#!/usr/bin/env python3
# exp1_dh_latency.py
# Measures DH_INIT RTT with hermes_server 30 times for each N_k value.
# Runs independently of the switch — just needs hermes_server running.
#
# Usage:
#   python3 exp1_dh_latency.py --hermes-host 127.0.0.1 --hermes-port 5555

import argparse
import random
import socket
import time

def tcp_readline(sock):
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("Connection closed")
        buf += chunk
    return buf.decode().strip()

NUM_KEYS_MAX = 350   # server always expects exactly this many Ka values

def dh_rtt(hermes_host, hermes_port, n_keys, sw_id="s1",
           G=0x5A5A5A5A, P=0xA5A5A5A5):
    """
    Perform one DH_INIT exchange and return RTT in milliseconds.
    Always sends NUM_KEYS_MAX Ka values (server requires padding to 350).
    n_keys controls how many are "real"; the rest are random padding.
    """
    # Always generate NUM_KEYS_MAX secrets — server requires exactly 350
    B_list  = [random.randint(1, 0xFFFFFFFE) for _ in range(NUM_KEYS_MAX)]
    Ka_list = [((G ^ P) & B) & 0xFFFFFFFF for B in B_list]

    msg = f"DH_INIT {sw_id} {G} {P} " + " ".join(str(k) for k in Ka_list) + "\n"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hermes_host, hermes_port))

    t0 = time.perf_counter()
    s.sendall(msg.encode())
    resp = tcp_readline(s)
    t1 = time.perf_counter()
    s.close()

    if not resp.startswith("DH_RESP"):
        raise RuntimeError(f"Unexpected response: {resp[:80]}")

    return (t1 - t0) * 1000   # milliseconds

def stats(values):
    s = sorted(values)
    n = len(s)
    p95_idx = int(0.95 * n)
    return {
        "min":    round(s[0], 2),
        "median": round(s[n // 2], 2),
        "max":    round(s[-1], 2),
        "p95":    round(s[p95_idx], 2),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hermes-host", default="127.0.0.1")
    ap.add_argument("--hermes-port", type=int, default=5555)
    ap.add_argument("--runs",        type=int, default=30)
    args = ap.parse_args()

    print(f"{'Switch':<8} {'N_k':<6} {'Min':>8} {'Median':>8} {'Max':>8} {'p95':>8}")
    print("-" * 52)

    for sw_id in ["s1"]:           # extend to s2, s3 when multi-switch
        for n_keys in [330, 340, 350]:
            # Warmup run — discarded — warms up TCP connection and server state
            try:
                dh_rtt(args.hermes_host, args.hermes_port, n_keys, sw_id)
            except Exception:
                pass

            rtts = []
            for run in range(args.runs):
                try:
                    rtt = dh_rtt(args.hermes_host, args.hermes_port,
                                 n_keys, sw_id)
                    rtts.append(rtt)
                except Exception as e:
                    print(f"  Run {run+1} failed: {e}")

            if rtts:
                st = stats(rtts)
                print(f"{sw_id:<8} {n_keys:<6} "
                      f"{st['min']:>8.2f} {st['median']:>8.2f} "
                      f"{st['max']:>8.2f} {st['p95']:>8.2f}")
                # Also print raw values for box plot
                print(f"  raw: {[round(r,2) for r in rtts]}")
            else:
                print(f"{sw_id:<8} {n_keys:<6}  NO DATA")

if __name__ == "__main__":
    main()