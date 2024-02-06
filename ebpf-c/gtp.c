#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <arpa/inet.h>

#include "common/parsing_helpers.h"
#include "common/gtp_types.h"

#define IHL_MIN 0x5
#define GTP_UDP_PORT 2152

/**
 * @brief BPF map for storing information on transmitted packets.
 *
 * @note `key` corresponds to an 32 bit unsigned integer representing the
 * direction of travel of the packets (0 for client->UPF and 1 for UPF->client).
 */
struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct usage_stats);
  __uint(max_entries, 2);
} txcnt SEC(".maps");

/**
 * @brief BPF map for storing information on each of the available UPFs
 *
 * @note `key` corresponds to an 32 bit unsigned integer representing the
 * source's IPv4 address in network byte order.
 */
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct upf_info);
  __uint(max_entries, 256);
} upf_map SEC(".maps");

/**
 * @brief BPF map for storing information on each of the registered clients
 *
 * @note `key` corresponds to an 32 bit unsigned integer representing the
 * source's IPv4 address in network byte order.
 */
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct client_info);
  __uint(max_entries, 256);
} client_map SEC(".maps");

/**
 * @brief Function for calculating IPv4 header checksum.
 *
 * @param iphdr IPv4 header for checksum calculation
 * (checksum field must be empty).
 *
 * @note We always create minimum size IP headers, therefore we only calculate
 * checksums for those headers.
 */
static __always_inline void
calculate_ip_checksum(struct iphdr* iphdr)
{
  __u32 checksum = 0;

#pragma unroll
  for (int i = 0; i < IHL_MIN * 2; i++)
    checksum += *(__u16*)((void*)iphdr + 2 * i);

  iphdr->check = ~(__u16)((checksum >> 16) + (checksum & 0xffff));
}

/**
 * @brief Function for encapsulating client's IP datagram in a GTP tunnel
 * towards the UPF.
 *
 * @param ctx User accessible metadata for XDP packet hook.
 * @param client_inf Struct containing information on the registered client.
 * @param upf_inf Struct containing information on the UPF assigned to the
 * registered client.
 * @return Output interface index or 0 on error.
 */
static __always_inline __u32
encapsulate_gtp(struct xdp_md* ctx,
                struct client_info* client_inf,
                struct upf_info* upf_inf)
{
  /* Increase packet size for new headers. */
  if (bpf_xdp_adjust_head(ctx,
                          0 - (int)sizeof(struct iphdr) -
                            (int)(sizeof(struct udphdr)) -
                            (int)(sizeof(struct gtphdr)))) {
    return 0;
  }

  void* data_end = (void*)(long)ctx->data_end;
  struct ethhdr* ethhdr = (void*)(long)ctx->data;

  /* We only use minimum length IP and GTP headers. */
  if ((void*)ethhdr + sizeof(struct ethhdr) + sizeof(struct iphdr) +
        sizeof(struct udphdr) + sizeof(struct gtphdr) >
      data_end) {
    return 0;
  }

  /* Copy both the source and destination MAC address. */
  __builtin_memcpy(ethhdr, upf_inf->eth_next_hop, 2 * ETH_ALEN);

  ethhdr->h_proto = 0x0008; /* IP over Ethernet */
  struct iphdr* iphdr = (void*)(ethhdr + 1);

  __builtin_memset(
    iphdr, 0, sizeof(*iphdr) + sizeof(struct udphdr) + sizeof(struct gtphdr));

  iphdr->daddr = client_inf->upf_ip;
  iphdr->saddr = upf_inf->local_ip;

  iphdr->ihl = IHL_MIN;
  iphdr->version = 0x4; /* IPv4 */
  iphdr->ttl = 128;
  iphdr->protocol = 0x11; /* UPD */
  iphdr->tot_len = bpf_htons(data_end - (void*)iphdr);

  calculate_ip_checksum(iphdr);

  /* Equivalent to (void*)iphdr + 4*iphdr->ihl for minimum length IP packets. */
  struct udphdr* udphdr = (void*)(iphdr + 1);

  udphdr->dest = bpf_htons(GTP_UDP_PORT);
  udphdr->len = bpf_htons(data_end - (void*)udphdr);

  struct gtphdr* gtphdr = (void*)(udphdr + 1);

  gtphdr->version = 1;
  gtphdr->protocol_type = 1;
  gtphdr->message_type = GTP_G_PDU;
  gtphdr->message_len = bpf_htons(data_end - (void*)(gtphdr + 1));
  gtphdr->teid = client_inf->teid;

  return upf_inf->ifindex;
}

/**
 * @brief Function for de-encapsulating client's IP datagram from the GTP tunnel
 * sent by the UPF.
 *
 * @param ctx User accessible metadata for XDP packet hook.
 * @param nh Next header cursor situated on GTP header.
 * @param data Pointer to start of packet.
 * @param data_end Pointer to end of packet.
 * @return Output interface index or 0 on error.
 */
static __always_inline __u32
pop_gtp(struct xdp_md* ctx, struct hdr_cursor* nh, void* data, void* data_end)
{
  struct ethhdr* newethhdr;
  struct gtphdr* gtphdr;
  struct client_info* client_inf;
  struct iphdr* innerip;

  __s32 payload_len = parse_gtp(nh, data_end, &gtphdr);
  if (payload_len < 0) {
    return 0;
  }

  if (parse_iphdr(nh, data_end, &innerip) < 0) {
    return 0;
  }

  client_inf = bpf_map_lookup_elem(&client_map, &(innerip->daddr));

  if (!client_inf) {
    return 0;
  }

  __s32 num_bytes_to_remove =
    data_end - data - payload_len - sizeof(struct ethhdr);

  /* Decrease packet size for de-encapsulation. */
  if (bpf_xdp_adjust_head(ctx, num_bytes_to_remove)) {
    return 0;
  }

  data_end = (void*)(long)ctx->data_end;
  data = (void*)(long)ctx->data;
  newethhdr = data;

  if ((void*)(newethhdr + 1) > data_end) {
    return 0;
  }

  /* Copy both the source and destination MAC address. */
  __builtin_memcpy(newethhdr, client_inf->eth_next_hop, 2 * ETH_ALEN);
  newethhdr->h_proto = 0x0008; /* IP over Ethernet */

  return client_inf->ifindex;
}

/**
 * @brief xdp_gtp BPF program for listening and writing to the same interface
 * (shared interface for client and UPF side).
 */
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
  struct udphdr* udphdr;
  struct hdr_cursor nh = { .pos = data };
  struct client_info* client_inf;
  struct upf_info* upf_inf;
  __u32 client2upf_txcnt_key = 0;
  __u32 upf2client_txcnt_key = 1;
  struct usage_stats* value;
  __u32 ifindex;

  eth_type = parse_ethhdr(&nh, data_end, &eth);
  if (eth_type != bpf_htons(ETH_P_IP)) {
    goto out;
  }

  ip_type = parse_iphdr(&nh, data_end, &iphdr);
  if (ip_type < 0) {
    goto out;
  }

  /* Check if IP source address is registered in clients map. */
  client_inf = bpf_map_lookup_elem(&client_map, &(iphdr->saddr));
  if (client_inf) {

    /* Check if client's UPF address is registered in UPFs map. */
    upf_inf = bpf_map_lookup_elem(&upf_map, &(client_inf->upf_ip));
    if (!upf_inf) {
      goto out;
    }

    ifindex = encapsulate_gtp(ctx, client_inf, upf_inf);
    if (ifindex == 0) {
      goto out;
    }

    action = bpf_redirect(ifindex, 0);

    if (action != XDP_REDIRECT) {
      goto out;
    }

    /* Update information on transmitted package and byte count. */
    value = bpf_map_lookup_elem(&txcnt, &client2upf_txcnt_key);
    if (value) {
      value->packets += 1;
      value->bytes += (__u64)(data_end - data);
    }

    goto out;
  }

  if ((void*)(iphdr + 1) > data_end) {
    goto out;
  }

  if (ip_type != IPPROTO_UDP) {
    goto out;
  }

  /* Parse UDP header and check if next header corresponds to GTP. */
  if (parse_udphdr(&nh, data_end, &udphdr) < 0 ||
      udphdr->dest != bpf_htons(GTP_UDP_PORT)) {
    goto out;
  }

  /**
   * Check if IP source address is registered in UPFs map.
   *
   * This check is placed as late as possible to delay (and possibly avoid)
   * the performance hit caused by reading memory.
   */
  upf_inf = bpf_map_lookup_elem(&upf_map, &(iphdr->saddr));
  if (!upf_inf) {
    goto out;
  }

  ifindex = pop_gtp(ctx, &nh, data, data_end);
  if (ifindex == 0) {
    goto out;
  }

  action = bpf_redirect(ifindex, 0);

  if (action != XDP_REDIRECT) {
    goto out;
  }

  /* Update information on transmitted package and byte count. */
  value = bpf_map_lookup_elem(&txcnt, &upf2client_txcnt_key);
  if (value) {
    value->packets += 1;
    value->bytes += (__u64)(data_end - data);
  }

out:
  return action;
}

/**
 * @brief xdp_gtp BPF program for client-facing interface.
 */
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
  struct client_info* client_inf;
  struct upf_info* upf_inf;
  __u32 txcnt_key = 0;
  struct usage_stats* value;
  __u32 ifindex;

  eth_type = parse_ethhdr(&nh, data_end, &eth);
  if (eth_type != bpf_htons(ETH_P_IP)) {
    goto out;
  }

  ip_type = parse_iphdr(&nh, data_end, &iphdr);
  if (ip_type < 0) {
    goto out;
  }

  /* Check if IP source address is registered in clients map. */
  client_inf = bpf_map_lookup_elem(&client_map, &(iphdr->saddr));
  if (!client_inf) {
    goto out;
  }

  /* Check if client's UPF address is registered in UPFs map. */
  upf_inf = bpf_map_lookup_elem(&upf_map, &(client_inf->upf_ip));
  if (!upf_inf) {
    goto out;
  }

  ifindex = encapsulate_gtp(ctx, client_inf, upf_inf);
  if (ifindex == 0) {
    goto out;
  }

  action = bpf_redirect(ifindex, 0);

  if (action != XDP_REDIRECT) {
    goto out;
  }

  /* Update information on transmitted package and byte count. */
  value = bpf_map_lookup_elem(&txcnt, &txcnt_key);
  if (value) {
    value->packets += 1;
    value->bytes += (__u64)(data_end - data);
  }

out:
  return action;
}

/**
 * @brief xdp_gtp BPF program for UPF-facing interface.
 */
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
  struct upf_info* upf_inf;
  __u32 txcnt_key = 1;
  struct usage_stats* value;
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

  if (ip_type != IPPROTO_UDP) {
    goto out;
  }

  /* Parse UDP header and check if next header corresponds to GTP. */
  if (parse_udphdr(&nh, data_end, &udphdr) < 0 ||
      udphdr->dest != bpf_htons(GTP_UDP_PORT)) {
    goto out;
  }

  /**
   * Check if IP source address is registered in UPFs map.
   *
   * This check is placed as late as possible to delay (and possibly avoid)
   * the performance hit caused by reading memory.
   */
  upf_inf = bpf_map_lookup_elem(&upf_map, &(iphdr->saddr));
  if (!upf_inf) {
    goto out;
  }

  ifindex = pop_gtp(ctx, &nh, data, data_end);
  if (ifindex == 0) {
    goto out;
  }

  action = bpf_redirect(ifindex, 0);

  if (action != XDP_REDIRECT) {
    goto out;
  }

  /* Update information on transmitted package and byte count. */
  value = bpf_map_lookup_elem(&txcnt, &txcnt_key);
  if (value) {
    value->packets += 1;
    value->bytes += (__u64)(data_end - data);
  }

out:
  return action;
}

char _license[] SEC("license") = "MIT";
