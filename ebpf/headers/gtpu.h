/* GTP-U header structures and constants for BPF dataplane programs.
 *
 * All constants extracted from TS 29.281 V15.7.0 (docs/specs/29281-f70.docx):
 *   §4.4.2.1 P310: UDP port 2152
 *   §5.1 Figure 5.1-1: octet 1 flag bit positions
 *   §5.1 P353: "version number shall be set to '1'"
 *   §5.1 P354: "GTP (when PT is '1')"
 *   §5.1 NOTE 0 P371: spare bit "receiver shall not evaluate this bit"
 *   Table 6.1-1: message type codes
 *   §5.2.1 P380/P384: extension header length in 4-octet units
 */
#pragma once

#include <linux/types.h>

/* UDP port per TS 29.281 §4.4.2.1 P310:
 * "The port number for GTP-U request messages is 2152." */
#define GTP_UDP_PORT  2152u

/*
 * Octet 1 flag bit masks per TS 29.281 §5.1 Figure 5.1-1.
 * 3GPP bit numbering: bit 8 = MSB.
 *
 *   Bits 8-6: Version (3 bits)
 *   Bit  5:   PT (Protocol Type)
 *   Bit  4:   (*) spare — "receiver shall not evaluate this bit" (P371 NOTE 0)
 *   Bit  3:   E (Extension Header flag)
 *   Bit  2:   S (Sequence Number flag)
 *   Bit  1:   PN (N-PDU Number flag)
 *
 * Version=1: bits 8-6 = 001 → 0x20 (P353: "version number shall be set to '1'")
 * PT=1 for GTP-U: bit 5 = 1 → 0x10 (P354: "GTP (when PT is '1')")
 */
#define GTP_VERSION_MASK  0xE0u  /* bits 8-6: version field */
#define GTP_VERSION_VAL   0x20u  /* version=1: bits 8-6 = 001 → 0x20 */
#define GTP_PT_FLAG       0x10u  /* bit 5: PT=1 for GTP-U */
/* Spare bit (0x08, bit 4) is not checked per P371 NOTE 0 */
#define GTP_E_FLAG        0x04u  /* bit 3: Extension Header flag */
#define GTP_S_FLAG        0x02u  /* bit 2: Sequence Number flag */
#define GTP_PN_FLAG       0x01u  /* bit 1: N-PDU Number flag */

/*
 * Fast-path invariant check mask and value.
 * Covers only version(3b)+PT(1b) = bits 8-5 = 0xF0.
 * Spare bit (bit 4 = 0x08) is deliberately excluded per P371 NOTE 0.
 * GTP_VPTMASK & flags == GTP_VPTVAL → version=1 and PT=1.
 */
#define GTP_VPTMASK  0xF0u  /* bits 8-5: version(3b) + PT(1b) */
#define GTP_VPTVAL   0x30u  /* version=1 (0x20) | PT=1 (0x10) */

/* Message type codes per TS 29.281 Table 6.1-1:
 *   "1   | Echo Request       | GTP-U: X"
 *   "2   | Echo Response      | GTP-U: X"
 *   "26  | Error Indication   | GTP-U: X"
 *   "254 | End Marker         | GTP-U: X"
 *   "255 | G-PDU              | GTP-U: X"
 */
#define GTPU_ECHO_REQUEST      1u
#define GTPU_ECHO_RESPONSE     2u
#define GTPU_ERROR_INDICATION  26u
#define GTPU_END_MARKER        254u
#define GTPU_G_PDU             255u

/*
 * GTP-U mandatory 8-byte header per TS 29.281 §5.1:
 * "The GTP-U header is a variable length header whose minimum length is 8 bytes."
 *
 * Using plain field types to avoid bitfield endianness issues across compilers.
 */
struct gtpuhdr {
    __u8   flags;           /* octet 1: version|PT|spare|E|S|PN */
    __u8   message_type;    /* octet 2: message type (Table 6.1-1) */
    __be16 message_length;  /* octets 3-4: payload length after mandatory 8-byte header */
    __be32 teid;            /* octets 5-8: Tunnel Endpoint Identifier */
} __attribute__((packed));

/*
 * Optional 4-byte field group present when any of E, S, PN is set.
 * Per TS 29.281 §5.1 NOTE 4:
 * "This field shall be present if and only if any one or more of the S, PN and E flags are set."
 */
struct gtp_opt_fields {
    __be16 seq_num;      /* octets 9-10: Sequence Number */
    __u8   npdu_num;     /* octet 11: N-PDU Number */
    __u8   next_ext_hdr; /* octet 12: Next Extension Header Type (0=chain end per §5.2.2.1 P403) */
} __attribute__((packed));

/* Per-rule packet/byte counters for sgw_rule_stats map. */
struct sgw_rule_stats {
    __u64 packets;
    __u64 bytes;
};
