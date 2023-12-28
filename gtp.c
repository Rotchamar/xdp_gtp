#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <arpa/inet.h>

#include "common/parsing_helpers.h"
#include "common/gtp_types.h"

#define IHL_MIN 0x5
#define GTP_UDP_PORT 2152

struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, usage_stats);
  __uint(max_entries, 2);
} rxcnt SEC(".maps");

// struct
// {
//   __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//   __type(key, __u32);
//   __type(value, __u32);
//   __uint(max_entries, 2);
// } rxcnttot SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, upf_addrs);
  __uint(max_entries, 256);
} upf_map SEC(".maps"); // IP addrs in network byte order

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, client_info);
  __uint(max_entries, 256);
} client_map SEC(".maps"); // IP addrs in network byte order

static __always_inline void
calculate_ip_checksum(struct iphdr* iphdr)
{
  // We always create minimum size IP headers, therefore we only calculate
  // checksums for those headers
  __u32 checksum = 0;

#pragma unroll
  for (int i = 0; i < IHL_MIN * 2; i++)
    checksum += *(__u16*)((void*)iphdr + 2 * i);

  iphdr->check = ~(__u16)((checksum >> 16) + (checksum & 0xffff));
}

static __always_inline __u32
encapsulate_gtp(struct xdp_md* ctx,
                struct ethhdr* eth,
                struct iphdr* iphdr,
                client_info* client_inf,
                upf_addrs* upf_addrs)
{
  struct udphdr* udphdr;
  struct gtphdr* gtphdr;

  if (bpf_xdp_adjust_head(ctx,
                          0 - (int)sizeof(*iphdr) - (int)(sizeof(*udphdr)) -
                            (int)(sizeof(*gtphdr)))) {
    return 0;
  }

  void* data_end = (void*)(long)ctx->data_end;
  struct ethhdr* oldeth = eth;
  eth = (void*)(long)ctx->data;

  // We only use minimum length IP and GTP headers
  if ((void*)eth + sizeof(*eth) + sizeof(*iphdr) + sizeof(*udphdr) +
        sizeof(*gtphdr) >
      data_end) {
    return 0;
  }

  __builtin_memcpy(eth, &oldeth, sizeof(*oldeth));

  __builtin_memcpy(eth,
                   upf_addrs->eth_next_hop,
                   2 *
                     ETH_ALEN); // Copy both source and destinadion mac address

  eth->h_proto = 0x0008; // IP over Ethernet

  struct iphdr* oldip = iphdr;
  iphdr = (void*)(eth + 1);

  __builtin_memset(
    iphdr, 0, sizeof(*iphdr) + sizeof(*udphdr) + sizeof(*gtphdr));

  iphdr->daddr = client_inf->upf_ip;
  iphdr->saddr = upf_addrs->local_ip;

  iphdr->ihl = IHL_MIN;
  iphdr->version = 0x4; // IPv4
  iphdr->ttl = 128;
  iphdr->protocol = 0x11; // UDP
  iphdr->tot_len = bpf_htons(data_end - (void*)iphdr);

  calculate_ip_checksum(iphdr);

  udphdr =
    (void*)(iphdr + 1); // Equivalent to (void*)iphdr + 4*iphdr->ihl in our case

  udphdr->dest = bpf_htons(GTP_UDP_PORT);
  udphdr->len = bpf_htons(data_end - (void*)udphdr);

  gtphdr = (void*)(udphdr + 1);

  gtphdr->version = 1;
  gtphdr->protocol_type = 1;
  gtphdr->message_type = GTP_G_PDU;
  gtphdr->message_len = bpf_htons(data_end - (void*)(gtphdr + 1));
  gtphdr->teid = client_inf->teid;

  return upf_addrs->ifindex;
}

static __always_inline __u32
pop_gtp(struct xdp_md* ctx,
        struct udphdr* udphdr,
        struct hdr_cursor* nh,
        void* data,
        void* data_end)
{
  struct ethhdr* newethhdr;
  struct gtphdr* gtphdr;
  client_info* client_inf;
  __s32 len;
  __s32 num_bytes_to_remove;
  struct iphdr* innerip;

  len = parse_gtp(nh, data_end, &gtphdr);
  if (len < 0) {
    return 0;
  }

  if (parse_iphdr(nh, data_end, &innerip) < 0) {
    return 0;
  }

  client_inf = bpf_map_lookup_elem(&client_map, &(innerip->daddr));

  if (!client_inf) {
    return 0;
  }

  num_bytes_to_remove = data_end - data - len - sizeof(*newethhdr);

  if (bpf_xdp_adjust_head(ctx, num_bytes_to_remove)) {
    return 0;
  }

  data_end = (void*)(long)ctx->data_end;
  data = (void*)(long)ctx->data;
  newethhdr = data;

  if ((void*)(newethhdr + 1) > data_end) {
    return 0;
  }

  __builtin_memcpy(newethhdr,
                   client_inf->eth_next_hop,
                   2 *
                     ETH_ALEN); // Copy both source and destinadion mac address
  newethhdr->h_proto = 0x0008;  // IP over Ethernet

  return client_inf->ifindex;
}

SEC("xdp")
int
xdp_gtp_common(struct xdp_md* ctx)
{
  int action = XDP_PASS;
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;
  __s16 eth_type, ip_type;
  struct ethhdr* eth = data;
  struct iphdr* iphdr;
  struct ipv6hdr* ipv6hdr;
  struct udphdr* udphdr;
  struct hdr_cursor nh = { .pos = data };
  client_info* client_inf;
  upf_addrs* upf_addrs;
  __u32 client2upf_key = 0;
  __u32 upf2client_key = 1;
  usage_stats* value;
  __u32 ifindex;

  eth_type = parse_ethhdr(&nh, data_end, &eth);
  if (eth_type != bpf_htons(ETH_P_IP)) {
    goto out;
  }

  ip_type = parse_iphdr(&nh, data_end, &iphdr);
  if (ip_type < 0) {
    goto out;
  }

  client_inf = bpf_map_lookup_elem(&client_map, &(iphdr->saddr));
  if (client_inf) {

    upf_addrs = bpf_map_lookup_elem(&upf_map, &(client_inf->upf_ip));
    if (upf_addrs) {

      ifindex = encapsulate_gtp(ctx, eth, iphdr, client_inf, upf_addrs);
      if (ifindex == 0) {
        goto out;
      }

      value = bpf_map_lookup_elem(&rxcnt, &client2upf_key);
      if (value) {
        value->packets += 1;
        value->bytes += (__u64)(data_end - data);
      }

      action = XDP_TX;
      goto out;
    }
  }

  if ((void*)(iphdr + 1) > data_end) {
    goto out;
  }

  if (ip_type == IPPROTO_UDP) {
    if (parse_udphdr(&nh, data_end, &udphdr) < 0 ||
        udphdr->dest != bpf_htons(GTP_UDP_PORT)) {
      goto out;
    }

    upf_addrs = bpf_map_lookup_elem(&upf_map, &(iphdr->saddr));
    if (!upf_addrs) {
      goto out;
    }

    if (pop_gtp(ctx, udphdr, &nh, data, data_end)) {
      goto out;
    }

    value = bpf_map_lookup_elem(&rxcnt, &upf2client_key);
    if (value) {
      value->packets += 1;
      value->bytes += (__u64)(data_end - data);
    }

    action = XDP_TX;
    goto out;
  }

out:
  return action;
}

SEC("xdp")
int
xdp_gtp_client(struct xdp_md* ctx)
{
  int action = XDP_PASS;
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;
  __s16 eth_type, ip_type;
  struct ethhdr* eth = data;
  struct iphdr* iphdr;
  struct hdr_cursor nh = { .pos = data };
  client_info* client_inf;
  upf_addrs* upf_addrs;
  __u32 key = 0;
  usage_stats* value;
  __u32 ifindex;

  eth_type = parse_ethhdr(&nh, data_end, &eth);
  if (eth_type != bpf_htons(ETH_P_IP)) {
    goto out;
  }

  ip_type = parse_iphdr(&nh, data_end, &iphdr);
  if (ip_type < 0) {
    goto out;
  }

  client_inf = bpf_map_lookup_elem(&client_map, &(iphdr->saddr));
  if (client_inf) {

    upf_addrs = bpf_map_lookup_elem(&upf_map, &(client_inf->upf_ip));
    if (upf_addrs) {

      ifindex = encapsulate_gtp(ctx, eth, iphdr, client_inf, upf_addrs);
      if (ifindex == 0) {
        goto out;
      }

      action = bpf_redirect(ifindex, 0);

      if (action == XDP_REDIRECT) {
        value = bpf_map_lookup_elem(&rxcnt, &key);
        if (value) {
          value->packets += 1;
          value->bytes += (__u64)(data_end - data);
        }
      }

      goto out;
    }
  }

out:
  return action;
}

SEC("xdp")
int
xdp_gtp_upf(struct xdp_md* ctx)
{ 
  int action = XDP_PASS;
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;
  __s16 eth_type, ip_type;
  struct ethhdr* eth = data;
  struct iphdr* iphdr;
  struct udphdr* udphdr;
  struct hdr_cursor nh = { .pos = data };
  upf_addrs* upf_addrs;
  __u32 key = 1;
  usage_stats* value;
  __u32 ifindex;

  eth_type = parse_ethhdr(&nh, data_end, &eth);
  if (eth_type != bpf_htons(ETH_P_IP)) {
    goto out;
  }

  ip_type = parse_iphdr(&nh, data_end, &iphdr);
  if (ip_type < 0) {
    goto out;
  }

  if ((void*)(iphdr + 1) > data_end) {
    goto out;
  }

  if (ip_type == IPPROTO_UDP) {
    if (parse_udphdr(&nh, data_end, &udphdr) < 0 ||
        udphdr->dest != bpf_htons(GTP_UDP_PORT)) {
      goto out;
    }

    upf_addrs = bpf_map_lookup_elem(&upf_map, &(iphdr->saddr));
    if (!upf_addrs) {
      goto out;
    }

    ifindex = pop_gtp(ctx, udphdr, &nh, data, data_end);
    if (ifindex == 0) {
      goto out;
    }

    action = bpf_redirect(ifindex, 0);

    if (action == XDP_REDIRECT) {
        value = bpf_map_lookup_elem(&rxcnt, &key);
        if (value) {
          value->packets += 1;
          value->bytes += (__u64)(data_end - data);
        }
      }

    goto out;
  }

out:
  return action;
}

char _license[] SEC("license") = "GPL";
