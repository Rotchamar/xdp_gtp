/**
 * This file contains struct definitions for XDP_GTP
 *
 * Should any type or struct be changed, modify accordingly in companion Go code
 */

#ifndef __GTP_TYPES
#define __GTP_TYPES

#include <linux/bpf.h>

/**
 * @brief Struct for storing usage statistics in BPF map
 */
struct usage_stats
{
  /** Number of packets sent since program was attached */
  __u64 packets;
  /** Number of bytes sent since program was attached */
  __u64 bytes;
};

/**
 * @brief Struct for storing upf information in BPF map
 */
struct upf_addrs
{
  /** IP address of the host's UPF-facing interface */
  __u32 local_ip;
  /** Destination Ethernet address for packets sent towards UPF */
  unsigned char eth_next_hop[ETH_ALEN];
  /** Source Ethernet address for packets sent towards UPF */
  unsigned char eth_local[ETH_ALEN];
  /** UPF-facing interface index */
  __u32 ifindex;
};

/**
 * @brief Struct for storing client information in BPF map
 */
struct client_info
{
  /** GTP Tunnel Endpoint Identifier */
  __u32 teid;
  /** Client's IP address */
  __u32 upf_ip;
  /** Destination Ethernet address for packets sent towards client */
  unsigned char eth_next_hop[ETH_ALEN];
  /** Source Ethernet address for packets sent towards client */
  unsigned char eth_local[ETH_ALEN];
  /** Client-facing interface index */
  __u32 ifindex;
};

#endif