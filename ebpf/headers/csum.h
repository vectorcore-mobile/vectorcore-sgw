/* Incremental checksum helpers for TC-BPF programs. */
#pragma once

#include <bpf/bpf_helpers.h>
#include <linux/types.h>

static __always_inline __u16 csum_fold(__u64 csum)
{
#pragma unroll
    for (int i = 0; i < 4; i++)
        csum = (csum & 0xffff) + (csum >> 16);
    return ~csum;
}

static __always_inline __u16 ipv4_csum(void *hdr, __u32 len)
{
    __u64 csum = bpf_csum_diff(0, 0, hdr, len, 0);
    return csum_fold(csum);
}
