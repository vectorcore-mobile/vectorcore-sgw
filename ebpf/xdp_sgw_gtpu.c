/*
 * XDP GTP-U ingress forwarding for SGW-U.
 *
 * Attaches to S1-U and S5/S8-U interfaces in xdp-generic or xdp-native mode.
 * Matched G-PDUs are rewritten in place and redirected at XDP. Control and
 * unsupported packets are passed to the normal kernel stack for userspace GTP-U.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/if_packet.h>
#include <linux/stddef.h>

#include "headers/gtpu.h"
#include "headers/csum.h"

#define ACTION_FORWARD  1
#define ACTION_DROP     2
#define ACTION_PUNT     3

#define SGW_AF_INET     2
#define GTPU_HDR_OFF_MIN  (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))

struct sgw_rule_key {
    __u32 teid;
    __u32 ifindex;
};

struct sgw_rule_value {
    __u8  action;
    __u8  _pad[3];
    __u32 egress_ifindex;
    __u8  outer_src_ip[4];
    __u8  outer_dst_ip[4];
    __u32 new_teid;
    __u32 counter_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   struct sgw_rule_key);
    __type(value, struct sgw_rule_value);
    __uint(max_entries, 65536);
} sgw_fwd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key,   __u32);
    __type(value, struct sgw_rule_stats);
    __uint(max_entries, 65536);
} sgw_rule_stats SEC(".maps");

static __always_inline int rewrite_l3_l4(struct xdp_md *ctx, struct ethhdr *eth,
                                         struct iphdr *ip, struct udphdr *udp,
                                         struct gtpuhdr *gtp,
                                         struct sgw_rule_value *val,
                                         __u32 ip_hdr_len)
{
    __be32 new_saddr = *(__be32 *)val->outer_src_ip;
    __be32 new_daddr = *(__be32 *)val->outer_dst_ip;
    __be32 new_teid = bpf_htonl(val->new_teid);

    ip->saddr = new_saddr;
    ip->daddr = new_daddr;
    ip->check = 0;
    ip->check = ipv4_csum(ip, ip_hdr_len);

    udp->check = 0;
    gtp->teid = new_teid;

    struct bpf_fib_lookup fib = {};
    fib.family = SGW_AF_INET;
    fib.tos = ip->tos;
    fib.l4_protocol = ip->protocol;
    fib.sport = udp->source;
    fib.dport = udp->dest;
    fib.tot_len = bpf_ntohs(ip->tot_len);
    fib.ipv4_src = new_saddr;
    fib.ipv4_dst = new_daddr;
    fib.ifindex = ctx->ingress_ifindex;

    long rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (rc != BPF_FIB_LKUP_RET_SUCCESS)
        return bpf_redirect(val->egress_ifindex, 0);
    if (fib.ifindex != val->egress_ifindex)
        return bpf_redirect(val->egress_ifindex, 0);

    __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);

    return bpf_redirect(val->egress_ifindex, 0);
}

SEC("xdp")
int xdp_sgw_gtpu_func(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + GTPU_HDR_OFF_MIN + sizeof(struct gtpuhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    struct iphdr *ip = data + ETH_HLEN;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 ip_hdr_len = (__u32)ip->ihl * 4;
    if (ip_hdr_len != sizeof(struct iphdr))
        return XDP_PASS;
    if (ip->frag_off & bpf_htons(0x3FFF))
        return XDP_PASS;
    if (data + ETH_HLEN + ip_hdr_len + sizeof(struct udphdr) + sizeof(struct gtpuhdr) > data_end)
        return XDP_PASS;

    struct udphdr *udp = data + ETH_HLEN + ip_hdr_len;
    struct gtpuhdr *gtp = data + ETH_HLEN + ip_hdr_len + sizeof(struct udphdr);

    if (udp->dest != bpf_htons(GTP_UDP_PORT))
        return XDP_PASS;

    __u8 flags = gtp->flags;
    if ((flags & GTP_VPTMASK) != GTP_VPTVAL)
        return XDP_PASS;
    if (gtp->message_type != GTPU_G_PDU)
        return XDP_PASS;
    if (flags & GTP_E_FLAG)
        return XDP_PASS;

    struct sgw_rule_key key = {};
    key.teid = bpf_ntohl(gtp->teid);
    key.ifindex = ctx->ingress_ifindex;

    struct sgw_rule_value *val = bpf_map_lookup_elem(&sgw_fwd_map, &key);
    if (!val)
        return XDP_PASS;

    if (val->action == ACTION_DROP)
        return XDP_DROP;
    if (val->action != ACTION_FORWARD)
        return XDP_PASS;

    __u32 ctr_id = val->counter_id;
    struct sgw_rule_stats *stats = bpf_map_lookup_elem(&sgw_rule_stats, &ctr_id);
    if (stats) {
        stats->packets++;
        stats->bytes += (__u64)((void *)(long)ctx->data_end - (void *)(long)ctx->data);
    }

    return rewrite_l3_l4(ctx, eth, ip, udp, gtp, val, ip_hdr_len);
}

char __license[] SEC("license") = "GPL";
