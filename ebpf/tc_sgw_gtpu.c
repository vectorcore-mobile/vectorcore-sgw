/*
 * TC-BPF GTP-U ingress forwarding for SGW-U.
 *
 * Attaches to the ingress of S1-U (Access side) and S5/S8-U (Core side)
 * interfaces. Performs TEID-keyed lookup and in-place outer IP/TEID rewrite
 * for G-PDU packets. All other packets (Echo, Error Indication, End Marker,
 * extension headers, unknown TEID) are punted to userspace via TC_ACT_OK.
 *
 * GTP-U constants from TS 29.281 V15.7.0 (docs/specs/29281-f70.docx):
 *   §4.4.2.1 P310: UDP port 2152
 *   §5.1 Table 0: octet 1 flag bits (version, PT, E, S, PN)
 *   Table 13: G-PDU=255, End Marker=254, Echo Request=1, Error Indication=26
 *   §5.2.1 P380: extension header Length in 4-octet units
 *
 * Project-internal BPF action codes (§6.3 of vectorcore-sgw-project.md):
 *   ACTION_FORWARD=1, ACTION_DROP=2, ACTION_PUNT=3
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/stddef.h>

#include "headers/gtpu.h"
#include "headers/csum.h"

/* Project-internal BPF action codes (not from 3GPP spec, per project §6.3) */
#define ACTION_FORWARD  1
#define ACTION_DROP     2
#define ACTION_PUNT     3

/*
 * AUD-04: GTPU_HDR_OFF is NOT a compile-time constant — IPv4 header length
 * is determined by ip->ihl (RFC 791, §3.1). sizeof(struct iphdr)=20 assumes
 * ihl=5 (no IP options). Computed at runtime after ip->ihl is validated.
 * The macro is kept for the minimum-header bounds check only.
 */
#define GTPU_HDR_OFF_MIN  (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))

/* ── BPF map definitions ─────────────────────────────────────────────────── */

/*
 * Forwarding rule key: {local TEID, ingress ifindex}.
 * The TEID is in host byte order (the BPF program converts from network byte
 * order before lookup). The combination uniquely identifies the tunnel endpoint.
 */
struct sgw_rule_key {
    __u32 teid;     /* local GTP-U TEID, host byte order */
    __u32 ifindex;  /* ingress interface index */
};

/*
 * Forwarding rule value: rewrite instructions for the fast path.
 * action: ACTION_FORWARD / DROP / PUNT (project-internal codes).
 * outer_src_ip / outer_dst_ip: new outer IP addresses, network byte order.
 * new_teid: new GTP-U TEID, host byte order (BPF converts to network before write).
 * egress_ifindex: target interface for bpf_redirect_neigh.
 * counter_id: key into sgw_rule_stats map for per-rule accounting.
 */
struct sgw_rule_value {
    __u8  action;
    __u8  _pad[3];
    __u32 egress_ifindex;
    __u8  outer_src_ip[4]; /* network byte order */
    __u8  outer_dst_ip[4]; /* network byte order */
    __u32 new_teid;        /* host byte order */
    __u32 counter_id;
};

/*
 * sgw_fwd_map: TEID + ifindex → forwarding rule.
 * Populated by the Go BPF rule compiler after PFCP session establishment.
 * max_entries matches DataplaneConfig.BPFMapMaxEntries (default 65536).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   struct sgw_rule_key);
    __type(value, struct sgw_rule_value);
    __uint(max_entries, 65536);
} sgw_fwd_map SEC(".maps");

/*
 * sgw_rule_stats: per-rule packet/byte counters (per-CPU hash).
 * Keyed by counter_id from sgw_rule_value. Per-CPU avoids atomic operations.
 * Go reads and aggregates per-CPU values.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key,   __u32);
    __type(value, struct sgw_rule_stats);
    __uint(max_entries, 65536);
} sgw_rule_stats SEC(".maps");

/* ── TC ingress program ───────────────────────────────────────────────────── */

SEC("tc")
int tc_sgw_gtpu_func(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Minimum bounds check: must have ETH + min-IP(20) + UDP + GTP-U header. */
    if (data + GTPU_HDR_OFF_MIN + sizeof(struct gtpuhdr) > data_end)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    struct iphdr  *ip  = data + ETH_HLEN;

    /* Only handle IPv4. */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* Must be UDP (17). */
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    /*
     * AUD-04: compute the actual IPv4 header length from ihl (RFC 791 §3.1).
     * ihl is in 32-bit words; valid range is 5..15 (20..60 bytes).
     * Fragments (frag_off MF or non-zero offset) have no reliable transport header;
     * punt them to userspace.
     */
    __u32 ip_hdr_len = (__u32)ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return TC_ACT_OK;
    if (ip->frag_off & bpf_htons(0x3FFF)) /* MF or fragment offset non-zero */
        return TC_ACT_OK;

    /* Re-check bounds now that we know the real IP header length. */
    if (data + ETH_HLEN + ip_hdr_len + sizeof(struct udphdr) + sizeof(struct gtpuhdr) > data_end)
        return TC_ACT_OK;

    struct udphdr  *udp = data + ETH_HLEN + ip_hdr_len;
    struct gtpuhdr *gtp = data + ETH_HLEN + ip_hdr_len + sizeof(struct udphdr);

    /* GTP-U UDP destination port = 2152 per TS 29.281 §4.4.2.1. */
    if (udp->dest != bpf_htons(GTP_UDP_PORT))
        return TC_ACT_OK;

    /*
     * GTP-U invariant check: version(3b)+PT(1b) per TS 29.281 §5.1 Table 0.
     * GTP_VPTMASK=0xF0 masks bits 8-5 (version+PT); spare bit (0x08) is excluded
     * per §5.1 NOTE 0 P371: "receiver shall not evaluate this bit".
     * GTP_VPTVAL=0x30 requires version=1 (0x20) and PT=1 (0x10).
     */
    __u8 flags = gtp->flags;
    if ((flags & GTP_VPTMASK) != GTP_VPTVAL)
        return TC_ACT_OK;

    /*
     * Only G-PDU (255) on fast path per TS 29.281 Table 13.
     * Echo Request/Response (1/2), Error Indication (26), End Marker (254)
     * all go to userspace for correct handling.
     */
    if (gtp->message_type != GTPU_G_PDU)
        return TC_ACT_OK;

    /*
     * Extension headers (E=1) require chain walking — punt to userspace.
     * Per TS 29.281 §5.2.1: chain must be walked to find T-PDU start.
     * Per project §6.5: "extension headers" is a punt-path trigger.
     */
    if (flags & GTP_E_FLAG)
        return TC_ACT_OK;

    /*
     * Look up forwarding rule: {teid in host byte order, ingress ifindex}.
     * bpf_ntohl converts from network byte order (wire) to host byte order.
     */
    struct sgw_rule_key key = {};
    key.teid    = bpf_ntohl(gtp->teid);
    key.ifindex = skb->ingress_ifindex;

    struct sgw_rule_value *val = bpf_map_lookup_elem(&sgw_fwd_map, &key);
    if (!val)
        return TC_ACT_OK; /* unknown TEID — punt to userspace */

    if (val->action == ACTION_DROP)
        return TC_ACT_SHOT;

    if (val->action != ACTION_FORWARD)
        return TC_ACT_OK; /* ACTION_PUNT or unknown */

    /*
     * Fast path: rewrite outer src IP, dst IP, TEID; update IP checksum.
     *
     * Read all values from packet and rule before any store calls,
     * since bpf_skb_store_bytes invalidates direct struct pointers.
     */
    __be32 old_saddr = ip->saddr;
    __be32 old_daddr = ip->daddr;
    __be32 new_saddr = *(__be32 *)val->outer_src_ip;
    __be32 new_daddr = *(__be32 *)val->outer_dst_ip;
    __be32 new_teid  = bpf_htonl(val->new_teid);
    __u32  egress    = val->egress_ifindex;
    __u32  ctr_id    = val->counter_id;

    /*
     * Incremental IP checksum update for saddr:
     * bpf_l3_csum_replace computes csum_diff(old, new) and patches
     * the checksum field at the given offset. Called before store so
     * the helper sees the original checksum value.
     */
    bpf_l3_csum_replace(skb,
        ETH_HLEN + offsetof(struct iphdr, check),
        old_saddr, new_saddr, 4);
    bpf_skb_store_bytes(skb,
        ETH_HLEN + offsetof(struct iphdr, saddr),
        &new_saddr, 4, 0);

    /* Incremental IP checksum update for daddr. */
    bpf_l3_csum_replace(skb,
        ETH_HLEN + offsetof(struct iphdr, check),
        old_daddr, new_daddr, 4);
    bpf_skb_store_bytes(skb,
        ETH_HLEN + offsetof(struct iphdr, daddr),
        &new_daddr, 4, 0);

    /*
     * Zero UDP checksum: GTP-U uses optional checksum; zeroing avoids
     * computing a full pseudo-header checksum after the IP address rewrite.
     * Per TS 29.281 §4.4 the checksum is implementation-defined for GTP-U.
     * Offset uses ip_hdr_len (not sizeof(struct iphdr)) per AUD-04 — the
     * outer IP header may carry options, shifting the UDP header forward.
     */
    __u16 zero = 0;
    bpf_skb_store_bytes(skb,
        ETH_HLEN + ip_hdr_len + offsetof(struct udphdr, check),
        &zero, 2, 0);

    /*
     * Rewrite GTP-U TEID in network byte order.
     * Offset matches the `gtp` pointer computed above (ETH_HLEN + ip_hdr_len
     * + sizeof(struct udphdr)) — GTPU_HDR_OFF_MIN is bounds-check-only and
     * must not be used here per the AUD-04 comment at its definition.
     */
    bpf_skb_store_bytes(skb,
        ETH_HLEN + ip_hdr_len + sizeof(struct udphdr) + offsetof(struct gtpuhdr, teid),
        &new_teid, 4, 0);

    /* Increment per-rule counters (per-CPU, no atomic needed). */
    struct sgw_rule_stats *stats = bpf_map_lookup_elem(&sgw_rule_stats, &ctr_id);
    if (stats) {
        stats->packets++;
        stats->bytes += skb->len;
    }

    /*
     * Redirect to egress interface with neighbor/ARP resolution.
     * bpf_redirect_neigh rewrites the Ethernet src/dst to the correct
     * next-hop MAC before transmitting on egress_ifindex.
     */
    return bpf_redirect_neigh(egress, NULL, 0, 0);
}

char __license[] SEC("license") = "GPL";
