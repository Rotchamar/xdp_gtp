/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */
/*
 * This file contains parsing functions that are used in the packetXX XDP
 * programs. The functions are marked as __always_inline, and fully defined in
 * this header file to be included in the BPF program.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type
 * field. All return values are in host byte order.
 *
 * The versions of the functions included here are slightly expanded versions
 * of the functions in the packet01 lesson. For instance, the Ethernet header
 * parsing has support for parsing VLAN tags.
 */

#ifndef __PARSING_HELPERS_H
#define __PARSING_HELPERS_H

// #include <stddef.h>
#include <linux/if_ether.h>
// #include <linux/if_packet.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define GTP_G_PDU 0xff
#define GTP_MAX_EXTENSION_HDR_NUM 3
#define GTP_NO_NEXT_EXTENSION_HDR 0x00

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
  void *pos;
};

struct gtphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
  __u8 npdu_num_flag : 1, seq_num_flag : 1, ext_hdr_flag : 1, reserved : 1,
      protocol_type : 1, version : 2;
#elif defined(__BIG_ENDIAN_BITFIELD)
  __u8 version : 2, protocol_type : 1, reserved : 1, ext_hdr_flag : 1,
      seq_num_flag : 1, npdu_num_flag : 1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
  __u8 message_type;
  __u16 message_len;
  __u32 teid;
};

struct gtpadditionalfields {
  __u16 sequence_number;
  __u8 npdu_number;
  __u8 next_extension_hdr_type;
};

static __always_inline __s16 parse_ethhdr(struct hdr_cursor *nh, void *data_end,
                                          struct ethhdr **ethhdr) {
  struct ethhdr *eth = nh->pos;
  __u16 hdrsize = sizeof(*eth);

  /* Byte-count bounds check; check if current pointer + size of header
   * is after data_end.
   */
  if (nh->pos + hdrsize > data_end)
    return -1;

  nh->pos += hdrsize;
  *ethhdr = eth;

  return eth->h_proto; /* network-byte-order */
}

static __always_inline __s16 parse_iphdr(struct hdr_cursor *nh, void *data_end,
                                         struct iphdr **iphdr) {
  struct iphdr *iph = nh->pos;
  __u16 hdrsize;

  if ((void *)(iph + 1) > data_end)
    return -1;

  hdrsize = iph->ihl * 4;
  /* Sanity check packet field is valid */
  if (hdrsize < sizeof(*iph))
    return -1;

  /* Variable-length IPv4 header, need to use byte-based arithmetic */
  if (nh->pos + hdrsize > data_end)
    return -1;

  nh->pos += hdrsize;
  *iphdr = iph;

  return iph->protocol;
}

/*
 * parse_udphdr: parse the udp header and return the length of the udp payload
 */
static __always_inline __s32 parse_udphdr(struct hdr_cursor *nh, void *data_end,
                                          struct udphdr **udphdr) {
  __s32 len;
  struct udphdr *h = nh->pos;

  if ((void *)(h + 1) > data_end)
    return -1;

  nh->pos = h + 1;
  *udphdr = h;

  len = bpf_ntohs(h->len) - sizeof(struct udphdr);
  if (len < 0)
    return -1;

  return len;
}

/*
 * parse_gtphdr: parse the gtp header and return the GTP payload length
 */
static __always_inline __s32 parse_gtp(struct hdr_cursor *nh, void *data_end,
                                       struct gtphdr **gtphdr) {
  __s32 len;
  struct gtphdr *h = nh->pos;

  if ((void *)(h + 1) > data_end) {
    return -1;
  }

  nh->pos = h + 1;
  *gtphdr = h;

  if (h->message_type != GTP_G_PDU) {
    return -1;
  }

  if (!(h->ext_hdr_flag && h->seq_num_flag && h->npdu_num_flag)) {
    goto out;
  }

  struct gtpadditionalfields *gtpaddfields = nh->pos;

  if ((void *)(gtpaddfields + 1) > data_end) {
    return -1;
  }

  nh->pos = gtpaddfields + 1;

  __u8 *next_extension_hdr_type = &gtpaddfields->next_extension_hdr_type;
  __u8 *extension_length;

#pragma unroll
  for (int i = 0; i < GTP_MAX_EXTENSION_HDR_NUM; i++) {
    if (next_extension_hdr_type == GTP_NO_NEXT_EXTENSION_HDR) {
      goto out;
    }

    extension_length = nh->pos;

    if ((void *)(extension_length + 1) > data_end) {
      return -1;
    }

    if ((void *)(nh->pos) + *extension_length * 4 > data_end) {
      return -1;
    }

    nh->pos += *extension_length * 4;
    next_extension_hdr_type = nh->pos - 1;
  }

  if (next_extension_hdr_type == GTP_NO_NEXT_EXTENSION_HDR) {
    return -1;
  }

out:
  len = (__s32)(data_end - nh->pos);
  return len;
}

#endif /* __PARSING_HELPERS_H */
