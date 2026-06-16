/* baseline_fwd.p4 -- generic L2 port-forwarding baseline for Hermes evaluation.
 *
 * Purpose: forward the SAME frames as the Hermes pipeline, but with NONE of the
 * Hermes logic (no accumulator, no key schedule, no digest, no verification).
 * This is the "plain forwarding" reference the evaluation compares against.
 *
 * It parses only Ethernet and forwards by ingress port via a tiny table the
 * controller fills:
 *    - throughput / FCT:  install (port 64 -> 65) so h1's frames reach h2.
 *    - latency (RTT):     install (port 64 -> 64) so the switch reflects frames
 *                         back to h1, giving a single-clock round-trip measure.
 *
 * Build for Tofino (TNA). Port numbers below are device ports; set them from the
 * controller, not here. Pipeline name "baseline_fwd" must match the controller.
 *
 * NOTE: TNA boilerplate is SDE-version sensitive. This compiles against the
 * 9.x tna.p4; if your build uses a different intrinsic-metadata signature, copy
 * the parser/deparser skeleton from your hermes_line_tna.p4 and keep only the
 * forward table + set_port action below.
 */
#include <core.p4>
#include <tna.p4>

/* ----------------------------------------------------------------- headers */
header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

struct headers_t { ethernet_h ethernet; }
struct metadata_t { }

/* --------------------------------------------------------------- ingress */
parser IngressParser(packet_in pkt,
                     out headers_t hdr,
                     out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control Ingress(inout headers_t hdr,
                inout metadata_t md,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    action set_port(PortId_t port) { ig_tm_md.ucast_egress_port = port; }
    action drop() { ig_dprsr_md.drop_ctl = 1; }

    table forward {
        key     = { ig_intr_md.ingress_port : exact; }
        actions = { set_port; drop; }
        default_action = drop();
        size    = 16;
    }

    apply { forward.apply(); }
}

control IngressDeparser(packet_out pkt,
                        inout headers_t hdr,
                        in    metadata_t md,
                        in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply { pkt.emit(hdr.ethernet); }
}

/* ---------------------------------------------------------------- egress (pass-through) */
parser EgressParser(packet_in pkt,
                    out headers_t hdr,
                    out metadata_t md,
                    out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control Egress(inout headers_t hdr,
               inout metadata_t md,
               in    egress_intrinsic_metadata_t              eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t  eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply { }
}

control EgressDeparser(packet_out pkt,
                       inout headers_t hdr,
                       in    metadata_t md,
                       in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply { pkt.emit(hdr.ethernet); }
}

Pipeline(IngressParser(), Ingress(), IngressDeparser(),
         EgressParser(),  Egress(),  EgressDeparser()) pipe;

Switch(pipe) main;
