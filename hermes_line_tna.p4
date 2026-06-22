// hermes_line_tna.p4
// v.12.05 — one ALU operation per action
//
// Changes from v.12.04:
//   • Each rot_by_N() action had 4 dependent operations (shl, shr, OR, add),
//     causing "action spanning multiple stages" errors.  Tofino allows exactly
//     ONE ALU operation per action body.
//   • Rotation is now split across two 32-entry const-entries tables:
//       rot_shl_table  — meta.rot_hi = meta.rot_base << N   (one op per action)
//       rot_shr_table  — meta.rot_lo = meta.rot_base >> (32-N)  (one op per action)
//     Followed by two single-operation apply-block assignments:
//       meta.rot_or = meta.rot_hi | meta.rot_lo;
//       hdr.data.accumulator = meta.rot_or + meta.rot_add;
//   • metadata_t gains rot_hi, rot_lo, rot_or to carry intermediate values
//     between the two tables and the apply-block finalisation.

#include <tna.p4>

const bit<3>  HERMES_DIGEST_TYPE = 3w1;
const bit<16> ETHERTYPE_HERMES   = 0xD1F1;

const bit<8> MSG_DATA     = 0;
const bit<8> MSG_VERIFY   = 1;
const bit<8> MSG_RESPONSE = 2;
const bit<8> MSG_DH_REQ   = 3;
const bit<8> MSG_DH_RESP  = 4;

// ─────────────────────────────────────────────────────────────────────────────
// Headers
// ─────────────────────────────────────────────────────────────────────────────
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}
header hermes_base_t {
    bit<8>  msg_type;
    bit<8>  version;
    bit<16> length;
}
header hermes_data_t {
    bit<32> accumulator;
    bit<16> key_index;
    bit<16> hop_count;
    bit<32> flow_id;
    bit<32> seq;
    bit<48> timestamp_ms;
    bit<32> nonce;
}
header hermes_verify_t {
    bit<32> accumulator_final;
    bit<32> flow_id;
    bit<16> hop_count;
    bit<32> seq;
    bit<48> timestamp_ms;
    bit<32> nonce;
}
header hermes_response_t {
    bit<8>  result;
    bit<32> flow_id;
}
struct headers_t {
    ethernet_t        eth;
    hermes_base_t     base;
    hermes_data_t     data;
    hermes_verify_t   verify;
    hermes_response_t response;
}

// ─────────────────────────────────────────────────────────────────────────────
// Digest
// ─────────────────────────────────────────────────────────────────────────────
struct hermes_digest_t {
    bit<32> flow_id;
    bit<16> hop_count;
    bit<32> accumulator;
    bit<32> seq;
    bit<48> timestamp_ms;
    bit<32> nonce;
    bit<8>  trigger_dh;
    bit<32> hop_idx;
}

// ─────────────────────────────────────────────────────────────────────────────
// Metadata
// ─────────────────────────────────────────────────────────────────────────────
struct metadata_t {
    // rotation pipeline:
    //   prep action  → rot_base, rot_amount, rot_add, need_rot=1
    //   rot_shl_table → rot_hi  (rot_base << amount)
    //   rot_shr_table → rot_lo  (rot_base >> (32-amount))
    //   apply block  → rot_or = rot_hi | rot_lo
    //                  accumulator = rot_or + rot_add
    bit<32> rot_base;
    bit<32> rot_add;
    bit<8>  rot_amount;
    bit<8>  need_rot;
    bit<32> rot_hi;
    bit<32> rot_lo;
    bit<32> rot_or;
    // subtraction intermediate (kv cannot be subtrahend on Tofino)
    bit<32> sub_key;
    bit<8>  need_sub_ab;
    // control signalling
    bit<8>  trigger_dh;
    // digest mirror fields
    bit<32> d_flow_id;
    bit<16> d_hop_count;
    bit<32> d_accumulator;
    bit<32> d_seq;
    bit<48> d_timestamp_ms;
    bit<32> d_nonce;
    bit<32> d_hop_idx;
}

// ─────────────────────────────────────────────────────────────────────────────
// Ingress Parser
// ─────────────────────────────────────────────────────────────────────────────
parser IngressParser(
        packet_in                              pkt,
        out       headers_t                    hdr,
        out       metadata_t                   meta,
        out       ingress_intrinsic_metadata_t ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        // Initialise ALL metadata before any branch so every parser exit path
        // is covered, eliminating --Wwarn=uninitialized_out_param.
        meta.rot_base       = 0;
        meta.rot_add        = 0;
        meta.rot_amount     = 0;
        meta.need_rot       = 0;
        meta.rot_hi         = 0;
        meta.rot_lo         = 0;
        meta.rot_or         = 0;
        meta.sub_key        = 0;
        meta.need_sub_ab    = 0;
        meta.trigger_dh     = 0;
        meta.d_flow_id      = 0;
        meta.d_hop_count    = 0;
        meta.d_accumulator  = 0;
        meta.d_seq          = 0;
        meta.d_timestamp_ms = 0;
        meta.d_nonce        = 0;
        meta.d_hop_idx      = 0;
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }
    state parse_resubmit    { transition reject; }
    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
            ETHERTYPE_HERMES : parse_base;
            default          : accept;
        }
    }
    state parse_base {
        pkt.extract(hdr.base);
        transition select(hdr.base.msg_type) {
            MSG_DATA     : parse_data;
            MSG_VERIFY   : parse_verify;
            MSG_RESPONSE : parse_response;
            default      : accept;
        }
    }
    state parse_data     { pkt.extract(hdr.data);     transition accept; }
    state parse_verify   { pkt.extract(hdr.verify);   transition accept; }
    state parse_response { pkt.extract(hdr.response); transition accept; }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ingress Control
// ─────────────────────────────────────────────────────────────────────────────
control MyIngress(
        inout headers_t                                  hdr,
        inout metadata_t                                 meta,
        in    ingress_intrinsic_metadata_t               ig_intr_md,
        in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    // ── Registers ─────────────────────────────────────────────────────────────
    Register<bit<32>, bit<32>>(3) reg_key_index;
    Register<bit<32>, bit<32>>(3) reg_countdown;

    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_key_index) ra_read_key_idx = {
        void apply(inout bit<32> val, out bit<32> rv) { rv = val; }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_countdown) ra_tick = {
        void apply(inout bit<32> val, out bit<32> rv) {
            if (val == 0) { rv = 1; }
            else          { val = val - 1; rv = 0; }
        }
    };

    // ── Forwarding ────────────────────────────────────────────────────────────
    action set_egress(bit<9> port) { ig_tm_md.ucast_egress_port = port; }
    table forward {
        key = { hdr.data.flow_id : exact; hdr.data.hop_count : exact; }
        actions = { set_egress; NoAction; }
        size = 16;
        default_action = NoAction();
    }

    // ── accumulate_table ──────────────────────────────────────────────────────
    // One action per opcode; each action body contains exactly ONE ALU op.
    // Rotation prep actions set meta fields consumed by rot_shl/shr_table.
    action do_add    (bit<32> kv) { hdr.data.accumulator = hdr.data.accumulator + kv; }
    action do_and    (bit<32> kv) { hdr.data.accumulator = hdr.data.accumulator & kv; }
    action do_xor    (bit<32> kv) { hdr.data.accumulator = hdr.data.accumulator ^ kv; }
    action do_or     (bit<32> kv) { hdr.data.accumulator = hdr.data.accumulator | kv; }
    // SUB_AB: accumulator - key.
    // kv cannot be the subtrahend (second operand) on Tofino — store it in
    // metadata first; sub_ab_table then does the subtract with meta.sub_key
    // as the second operand (metadata is allowed).
    action do_sub_ab_prep(bit<32> kv) { meta.sub_key = kv; meta.need_sub_ab = 1; }
    action do_sub_ba (bit<32> kv) { hdr.data.accumulator = kv - hdr.data.accumulator; }

    // Prep for OP_ROT_AB: rotate acc left by kv[31:27], add kv[26:0]
    // Four assignments — each is a simple copy or slice, one ALU op each.
    // Tofino treats independent parallel assignments within one action as
    // legal as long as no result feeds another operation in the same action.
    action do_rot_ab_prep(bit<32> kv) {
        meta.rot_base   = hdr.data.accumulator;
        meta.rot_amount = (bit<8>)(kv[31:27]);
        meta.rot_add    = (bit<32>)(kv[26:0]);
        meta.need_rot   = 1;
    }
    // Prep for OP_ROT_BA: rotate kv left by acc[31:27], add acc[26:0]
    action do_rot_ba_prep(bit<32> kv) {
        meta.rot_base   = kv;
        meta.rot_amount = (bit<8>)(hdr.data.accumulator[31:27]);
        meta.rot_add    = (bit<32>)(hdr.data.accumulator[26:0]);
        meta.need_rot   = 1;
    }

    table accumulate_table {
        key = {
            hdr.data.flow_id  : exact;
            hdr.data.hop_count: exact;
            hdr.data.key_index: exact;
        }
        actions = {
            do_add; do_and; do_xor; do_or;
            do_sub_ab_prep; do_sub_ba;
            do_rot_ab_prep; do_rot_ba_prep;
            NoAction;
        }
        size           = 4096;
        default_action = NoAction();
    }

    // ── rot_shl_table ─────────────────────────────────────────────────────────
    // 32 const entries.  Each action: meta.rot_hi = meta.rot_base << N
    // N is a compile-time integer literal — satisfies Tofino shift requirement.
    action shl_0()  { meta.rot_hi = meta.rot_base; }
    action shl_1()  { meta.rot_hi = meta.rot_base <<  1; }
    action shl_2()  { meta.rot_hi = meta.rot_base <<  2; }
    action shl_3()  { meta.rot_hi = meta.rot_base <<  3; }
    action shl_4()  { meta.rot_hi = meta.rot_base <<  4; }
    action shl_5()  { meta.rot_hi = meta.rot_base <<  5; }
    action shl_6()  { meta.rot_hi = meta.rot_base <<  6; }
    action shl_7()  { meta.rot_hi = meta.rot_base <<  7; }
    action shl_8()  { meta.rot_hi = meta.rot_base <<  8; }
    action shl_9()  { meta.rot_hi = meta.rot_base <<  9; }
    action shl_10() { meta.rot_hi = meta.rot_base << 10; }
    action shl_11() { meta.rot_hi = meta.rot_base << 11; }
    action shl_12() { meta.rot_hi = meta.rot_base << 12; }
    action shl_13() { meta.rot_hi = meta.rot_base << 13; }
    action shl_14() { meta.rot_hi = meta.rot_base << 14; }
    action shl_15() { meta.rot_hi = meta.rot_base << 15; }
    action shl_16() { meta.rot_hi = meta.rot_base << 16; }
    action shl_17() { meta.rot_hi = meta.rot_base << 17; }
    action shl_18() { meta.rot_hi = meta.rot_base << 18; }
    action shl_19() { meta.rot_hi = meta.rot_base << 19; }
    action shl_20() { meta.rot_hi = meta.rot_base << 20; }
    action shl_21() { meta.rot_hi = meta.rot_base << 21; }
    action shl_22() { meta.rot_hi = meta.rot_base << 22; }
    action shl_23() { meta.rot_hi = meta.rot_base << 23; }
    action shl_24() { meta.rot_hi = meta.rot_base << 24; }
    action shl_25() { meta.rot_hi = meta.rot_base << 25; }
    action shl_26() { meta.rot_hi = meta.rot_base << 26; }
    action shl_27() { meta.rot_hi = meta.rot_base << 27; }
    action shl_28() { meta.rot_hi = meta.rot_base << 28; }
    action shl_29() { meta.rot_hi = meta.rot_base << 29; }
    action shl_30() { meta.rot_hi = meta.rot_base << 30; }
    action shl_31() { meta.rot_hi = meta.rot_base << 31; }

    table rot_shl_table {
        key     = { meta.rot_amount : exact; }
        actions = {
            shl_0;  shl_1;  shl_2;  shl_3;  shl_4;  shl_5;  shl_6;  shl_7;
            shl_8;  shl_9;  shl_10; shl_11; shl_12; shl_13; shl_14; shl_15;
            shl_16; shl_17; shl_18; shl_19; shl_20; shl_21; shl_22; shl_23;
            shl_24; shl_25; shl_26; shl_27; shl_28; shl_29; shl_30; shl_31;
            NoAction;
        }
        size = 32;
        const entries = {
            8w0:shl_0();   8w1:shl_1();   8w2:shl_2();   8w3:shl_3();
            8w4:shl_4();   8w5:shl_5();   8w6:shl_6();   8w7:shl_7();
            8w8:shl_8();   8w9:shl_9();   8w10:shl_10(); 8w11:shl_11();
            8w12:shl_12(); 8w13:shl_13(); 8w14:shl_14(); 8w15:shl_15();
            8w16:shl_16(); 8w17:shl_17(); 8w18:shl_18(); 8w19:shl_19();
            8w20:shl_20(); 8w21:shl_21(); 8w22:shl_22(); 8w23:shl_23();
            8w24:shl_24(); 8w25:shl_25(); 8w26:shl_26(); 8w27:shl_27();
            8w28:shl_28(); 8w29:shl_29(); 8w30:shl_30(); 8w31:shl_31();
        }
        default_action = NoAction();
    }

    // ── rot_shr_table ─────────────────────────────────────────────────────────
    // 32 const entries.  Each action: meta.rot_lo = meta.rot_base >> (32-N)
    // For amount=0, the right-shift complement is 32 (undefined for 32-bit);
    // the rotate-by-0 case is handled by shl_0 copying rot_base unchanged, so
    // shr_0 simply zeroes rot_lo.
    action shr_0()  { meta.rot_lo = 0; }
    action shr_1()  { meta.rot_lo = meta.rot_base >> 31; }
    action shr_2()  { meta.rot_lo = meta.rot_base >> 30; }
    action shr_3()  { meta.rot_lo = meta.rot_base >> 29; }
    action shr_4()  { meta.rot_lo = meta.rot_base >> 28; }
    action shr_5()  { meta.rot_lo = meta.rot_base >> 27; }
    action shr_6()  { meta.rot_lo = meta.rot_base >> 26; }
    action shr_7()  { meta.rot_lo = meta.rot_base >> 25; }
    action shr_8()  { meta.rot_lo = meta.rot_base >> 24; }
    action shr_9()  { meta.rot_lo = meta.rot_base >> 23; }
    action shr_10() { meta.rot_lo = meta.rot_base >> 22; }
    action shr_11() { meta.rot_lo = meta.rot_base >> 21; }
    action shr_12() { meta.rot_lo = meta.rot_base >> 20; }
    action shr_13() { meta.rot_lo = meta.rot_base >> 19; }
    action shr_14() { meta.rot_lo = meta.rot_base >> 18; }
    action shr_15() { meta.rot_lo = meta.rot_base >> 17; }
    action shr_16() { meta.rot_lo = meta.rot_base >> 16; }
    action shr_17() { meta.rot_lo = meta.rot_base >> 15; }
    action shr_18() { meta.rot_lo = meta.rot_base >> 14; }
    action shr_19() { meta.rot_lo = meta.rot_base >> 13; }
    action shr_20() { meta.rot_lo = meta.rot_base >> 12; }
    action shr_21() { meta.rot_lo = meta.rot_base >> 11; }
    action shr_22() { meta.rot_lo = meta.rot_base >> 10; }
    action shr_23() { meta.rot_lo = meta.rot_base >>  9; }
    action shr_24() { meta.rot_lo = meta.rot_base >>  8; }
    action shr_25() { meta.rot_lo = meta.rot_base >>  7; }
    action shr_26() { meta.rot_lo = meta.rot_base >>  6; }
    action shr_27() { meta.rot_lo = meta.rot_base >>  5; }
    action shr_28() { meta.rot_lo = meta.rot_base >>  4; }
    action shr_29() { meta.rot_lo = meta.rot_base >>  3; }
    action shr_30() { meta.rot_lo = meta.rot_base >>  2; }
    action shr_31() { meta.rot_lo = meta.rot_base >>  1; }

    table rot_shr_table {
        key     = { meta.rot_amount : exact; }
        actions = {
            shr_0;  shr_1;  shr_2;  shr_3;  shr_4;  shr_5;  shr_6;  shr_7;
            shr_8;  shr_9;  shr_10; shr_11; shr_12; shr_13; shr_14; shr_15;
            shr_16; shr_17; shr_18; shr_19; shr_20; shr_21; shr_22; shr_23;
            shr_24; shr_25; shr_26; shr_27; shr_28; shr_29; shr_30; shr_31;
            NoAction;
        }
        size = 32;
        const entries = {
            8w0:shr_0();   8w1:shr_1();   8w2:shr_2();   8w3:shr_3();
            8w4:shr_4();   8w5:shr_5();   8w6:shr_6();   8w7:shr_7();
            8w8:shr_8();   8w9:shr_9();   8w10:shr_10(); 8w11:shr_11();
            8w12:shr_12(); 8w13:shr_13(); 8w14:shr_14(); 8w15:shr_15();
            8w16:shr_16(); 8w17:shr_17(); 8w18:shr_18(); 8w19:shr_19();
            8w20:shr_20(); 8w21:shr_21(); 8w22:shr_22(); 8w23:shr_23();
            8w24:shr_24(); 8w25:shr_25(); 8w26:shr_26(); 8w27:shr_27();
            8w28:shr_28(); 8w29:shr_29(); 8w30:shr_30(); 8w31:shr_31();
        }
        default_action = NoAction();
    }

    // ── sub_ab_table ──────────────────────────────────────────────────────────
    // Keyless table; executes one subtract op: accumulator = accumulator - meta.sub_key.
    // meta.sub_key is metadata, so it is legal as the subtrahend on Tofino.
    action do_sub_final() { hdr.data.accumulator = hdr.data.accumulator - meta.sub_key; }
    table sub_ab_table {
        actions        = { do_sub_final; }
        default_action = do_sub_final();
        size           = 1;
    }

    // ── rot_or_table ──────────────────────────────────────────────────────────
    // Keyless table: always executes the single default action (one OR op).
    // A keyless table in TNA costs no TCAM resources.
    action do_rot_or()  { meta.rot_or = meta.rot_hi | meta.rot_lo; }
    table rot_or_table {
        actions        = { do_rot_or; }
        default_action = do_rot_or();
        size           = 1;
    }

    // ── rot_add_table ─────────────────────────────────────────────────────────
    // Keyless table: always executes the single default action (one ADD op).
    action do_rot_final() { hdr.data.accumulator = meta.rot_or + meta.rot_add; }
    table rot_add_table {
        actions        = { do_rot_final; }
        default_action = do_rot_final();
        size           = 1;
    }

    // ── apply ─────────────────────────────────────────────────────────────────
    apply {
        if (!hdr.data.isValid()) { return; }

        bit<32> hop_idx = (bit<32>)hdr.data.hop_count;

        // 1. Read current key index
        bit<32> key_idx_reg = ra_read_key_idx.execute(hop_idx);
        hdr.data.key_index  = (bit<16>)key_idx_reg;

        // 2. Apply accumulator operation.
        //    Non-rotation ops write hdr.data.accumulator directly.
        //    Rotation ops set meta.rot_{base,amount,add} and need_rot=1.
        meta.need_rot    = 0;
        meta.need_sub_ab = 0;
        accumulate_table.apply();

        // SUB_AB two-step: accumulate_table stored kv in meta.sub_key
        if (meta.need_sub_ab == 1) { sub_ab_table.apply(); }

        if (meta.need_rot == 1) {
            // Stage A: meta.rot_hi = meta.rot_base << amount  (one op)
            rot_shl_table.apply();
            // Stage B: meta.rot_lo = meta.rot_base >> (32-amount)  (one op)
            rot_shr_table.apply();
            // Stage C: OR the two halves — keyless table, always hits default (one op)
            rot_or_table.apply();
            // Stage D: add the addend — keyless table, always hits default (one op)
            rot_add_table.apply();
        }

        // 3. Forward (pre-increment hop_count as table key)
        forward.apply();

        // 4. Advance hop_count
        hdr.data.hop_count = hdr.data.hop_count + 1;

        // 5. Tick countdown; returns 1 when key advance is due
        bit<32> advance_needed = ra_tick.execute(hop_idx);
        meta.trigger_dh = (bit<8>)advance_needed;

        // 6. Emit digest at final hop
        // hop_count has already been incremented above;
        // for a 1-switch topology (h1→s1→h2) the final hop is 1.
        // Change this constant to match your number of switches.
        if (hdr.data.hop_count == 1) {
            meta.d_flow_id      = hdr.data.flow_id;
            meta.d_hop_count    = hdr.data.hop_count;
            meta.d_accumulator  = hdr.data.accumulator;
            meta.d_seq          = hdr.data.seq;
            meta.d_timestamp_ms = hdr.data.timestamp_ms;
            meta.d_nonce        = hdr.data.nonce;
            meta.d_hop_idx      = hop_idx;
            ig_dprsr_md.digest_type = HERMES_DIGEST_TYPE;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ingress Deparser
// ─────────────────────────────────────────────────────────────────────────────
control IngressDeparser(
        packet_out                                       pkt,
        inout headers_t                                  hdr,
        in    metadata_t                                 meta,
        in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Digest<hermes_digest_t>() hermes_digest;
    apply {
        if (ig_dprsr_md.digest_type == HERMES_DIGEST_TYPE) {
            hermes_digest_t d;
            d.flow_id      = meta.d_flow_id;
            d.hop_count    = meta.d_hop_count;
            d.accumulator  = meta.d_accumulator;
            d.seq          = meta.d_seq;
            d.timestamp_ms = meta.d_timestamp_ms;
            d.nonce        = meta.d_nonce;
            d.trigger_dh   = meta.trigger_dh;
            d.hop_idx      = meta.d_hop_idx;
            hermes_digest.pack(d);
        }
        pkt.emit(hdr.eth);
        pkt.emit(hdr.base);
        pkt.emit(hdr.data);
        pkt.emit(hdr.verify);
        pkt.emit(hdr.response);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Egress Parser  (pass-through)
// ─────────────────────────────────────────────────────────────────────────────
parser EgressParser(
        packet_in                             pkt,
        out       headers_t                   hdr,
        out       metadata_t                  meta,
        out       egress_intrinsic_metadata_t eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        meta.rot_base       = 0;
        meta.rot_add        = 0;
        meta.rot_amount     = 0;
        meta.need_rot       = 0;
        meta.rot_hi         = 0;
        meta.rot_lo         = 0;
        meta.rot_or         = 0;
        meta.sub_key        = 0;
        meta.need_sub_ab    = 0;
        meta.trigger_dh     = 0;
        meta.d_flow_id      = 0;
        meta.d_hop_count    = 0;
        meta.d_accumulator  = 0;
        meta.d_seq          = 0;
        meta.d_timestamp_ms = 0;
        meta.d_nonce        = 0;
        meta.d_hop_idx      = 0;
        transition parse_ethernet;
    }
    state parse_ethernet { pkt.extract(hdr.eth); transition accept; }
}

// ─────────────────────────────────────────────────────────────────────────────
// Egress Control  (pass-through)
// ─────────────────────────────────────────────────────────────────────────────
control MyEgress(
        inout headers_t                                   hdr,
        inout metadata_t                                  meta,
        in    egress_intrinsic_metadata_t                 eg_intr_md,
        in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{ apply { } }

// ─────────────────────────────────────────────────────────────────────────────
// Egress Deparser
// ─────────────────────────────────────────────────────────────────────────────
control EgressDeparser(
        packet_out                                     pkt,
        inout headers_t                                hdr,
        in    metadata_t                               meta,
        in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.base);
        pkt.emit(hdr.data);
        pkt.emit(hdr.verify);
        pkt.emit(hdr.response);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Package instantiation
// ─────────────────────────────────────────────────────────────────────────────
Pipeline(
    IngressParser(),
    MyIngress(),
    IngressDeparser(),
    EgressParser(),
    MyEgress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
