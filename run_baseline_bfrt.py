#!/usr/bin/env python3
"""
run_baseline_bfrt.py -- install forwarding entries for baseline_fwd.p4.

This is the no-Hermes counterpart to run_hermes_bfrt.py: no DH, no keys, no
digest listener -- it only programs the generic `forward` table so the same
frames are switched without any Hermes processing.

Enable the front-panel ports the same way you already do for Hermes
(`pm port-add 57/0 10g none`, `pm port-enb ...`), then run this.

Modes:
  --mode line     install (h1_port -> h2_port): for throughput + FCT baselines
  --mode reflect  install (h1_port -> h1_port): for the latency (RTT) baseline,
                  so the switch bounces frames back to h1 on one clock

Example:
  sudo -E PYTHONPATH=$SDE/install/lib/python3.8/site-packages/tofino \
       python3 run_baseline_bfrt.py --switch localhost --mode line \
       --h1-port 64 --h2-port 65
"""
import argparse, sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--switch", default="localhost")
    ap.add_argument("--grpc-port", type=int, default=50052)
    ap.add_argument("--program", default="baseline_fwd")
    ap.add_argument("--mode", choices=["line", "reflect"], default="line")
    ap.add_argument("--h1-port", type=int, default=64)
    ap.add_argument("--h2-port", type=int, default=65)
    ap.add_argument("--flow-id", type=int, default=1, dest="flow_id",
                    help="used when the forward table is keyed on flow_id")
    ap.add_argument("--table", default="", help="override forward table name")
    ap.add_argument("--set-action", default="", dest="set_action",
                    help="override the set-egress action name")
    ap.add_argument("--port-param", default="", dest="port_param",
                    help="override the egress-port action parameter name")
    a = ap.parse_args()

    try:
        import bfrt_grpc.client as gc
    except ImportError:
        sys.exit("bfrt_grpc not found; set PYTHONPATH to the SDE as for run_hermes_bfrt.py")

    iface = gc.ClientInterface(f"{a.switch}:{a.grpc_port}", client_id=0, device_id=0)
    try:
        iface.bind_pipeline_config(a.program)
    except Exception as e:
        sys.exit(
            f"\n[baseline] Could not bind to program '{a.program}': {e}\n"
            f"[baseline] The device has no P4 program registered under that name.\n"
            f"[baseline] Likely fixes:\n"
            f"  1. bf_switchd is still running a different program. Restart it with\n"
            f"     baseline_fwd:   cd $SDE && ./p4_build.sh <path>/baseline_fwd.p4 && \\\n"
            f"                     ./run_switchd.sh -p baseline_fwd\n"
            f"  2. It loaded under a different name. Find it in bfshell:\n"
            f"     bfshell -> bfrt_python -> print([n for n in dir(bfrt) if n[0]!='_'])\n"
            f"     then re-run this script with  --program <that_name>\n")
    info = iface.bfrt_info_get(a.program)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)

    # locate the forwarding table by name (handles Ingress/MyIngress/SwitchIngress, with or without pipe.)
    fwd = None
    chosen = None
    for cand in [a.table, "pipe.MyIngress.forward", "pipe.Ingress.forward",
                 "pipe.SwitchIngress.forward", "MyIngress.forward", "Ingress.forward"]:
        if not cand:
            continue
        try:
            fwd = info.table_get(cand)
            chosen = cand
            break
        except Exception:
            continue
    if fwd is None:
        # last resort: scan every table whose short name is 'forward'
        for n in info.table_dict.keys():
            if n.split(".")[-1] == "forward":
                fwd = info.table_get(n); chosen = n; break
    if fwd is None:
        sys.exit("[baseline] could not find a 'forward' table; pass --table <name>")
    print(f"[baseline] using table: {chosen}")

    # discover the key fields and the egress-port-setting action + its param
    key_fields = fwd.info.key_field_name_list_get()
    print(f"[baseline] key fields: {key_fields}")
    set_action = None
    port_param = None
    for act in fwd.info.action_name_list_get():
        params = fwd.info.data_field_name_list_get(act)
        for p in params:
            if "port" in p.lower():
                set_action, port_param = act, p
                break
        if set_action:
            break
    if a.set_action:
        set_action = a.set_action
    if a.port_param:
        port_param = a.port_param
    if set_action is None:
        sys.exit(f"[baseline] no action with a port parameter found; actions = "
                 f"{fwd.info.action_name_list_get()}. Pass --set-action/--port-param.")
    print(f"[baseline] action: {set_action}(param '{port_param}')")

    port_keyed = any("ingress_port" in kf.lower() for kf in key_fields)

    def build_key(in_port):
        kts = []
        for kf in key_fields:
            s = kf.split(".")[-1].lower()
            if "ingress_port" in s:
                kts.append(gc.KeyTuple(kf, in_port))
            elif "flow" in s:
                kts.append(gc.KeyTuple(kf, a.flow_id))
            elif "hop" in s:
                kts.append(gc.KeyTuple(kf, 0))
            else:
                kts.append(gc.KeyTuple(kf, 0))
        return kts

    def install(out_port, in_port):
        key = fwd.make_key(build_key(in_port))
        try:
            fwd.entry_del(tgt, [key])               # idempotent
        except Exception:
            pass
        data = fwd.make_data([gc.DataTuple(port_param, out_port)], set_action)
        fwd.entry_add(tgt, [key], [data])
        tag = f"ingress_port {in_port}" if port_keyed else f"flow_id {a.flow_id}, hop_count 0"
        print(f"[baseline] installed [{tag}] -> egress_port {out_port}")

    if a.mode == "line":
        install(a.h2_port, a.h1_port)               # h1 -> h2
        if port_keyed:
            install(a.h1_port, a.h2_port)           # h2 -> h1 (symmetric; harmless)
        print("[baseline] LINE mode installed (throughput/FCT).")
    else:
        install(a.h1_port, a.h1_port)               # reflect back to h1
        print("[baseline] REFLECT mode installed (latency RTT).")

    print("[baseline] done. Leave this installed while you run hermes_bench.")


if __name__ == "__main__":
    main()