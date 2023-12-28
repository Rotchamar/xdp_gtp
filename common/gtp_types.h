#ifndef __GTP_TYPES
#define __GTP_TYPES

#include <linux/bpf.h>

typedef struct
{
  __u64 packets;
  __u64 bytes;
} usage_stats;

typedef struct
{
  __u32 local_ip;
  unsigned char eth_next_hop[ETH_ALEN];
  unsigned char eth_local[ETH_ALEN];
  __u32 ifindex;
} upf_addrs;

typedef struct
{
  __u32 teid;
  __u32 upf_ip;
  unsigned char eth_next_hop[ETH_ALEN];
  unsigned char eth_local[ETH_ALEN];
  __u32 ifindex;
} client_info;

#endif