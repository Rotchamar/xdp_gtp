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

#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define GTP_G_PDU 0xff
#define GTP_MAX_EXTENSION_HDR_NUM 3
#define GTP_NO_NEXT_EXTENSION_HDR 0x00

/** 
 * @brief Header cursor to keep track of current parsing position.
 */
struct hdr_cursor {
  /** Pointer to parsing position */
  void *pos;
};

/** 
 * @brief GTP header mandatory fields (3GPP TS 29.060 chapter 6)
 */
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

/** 
 * @brief GTP header optional fields (3GPP TS 29.060 chapter 6)
 */
struct gtpadditionalfields {
  __u16 sequence_number;
  __u8 npdu_number;
  __u8 next_extension_hdr_type;
};

/**
 * @brief Ethernet frame header parser
 * 
 * @param nh Cursor located at Ethernet header start.
 * Must be updated to the next header's location on return.
 * @param data_end Pointer to end of packet.
 * @param ethhdr Empty Ethernet header.
 * Must be updated with adequate contents on return.
 * @return  Ethertype field (network-byte order) or -1 on error.
 */
static __always_inline __s16 parse_ethhdr(struct hdr_cursor *nh, void *data_end,
                                          struct ethhdr **ethhdr) {
  struct ethhdr *eth = nh->pos;
  __u16 hdrsize = sizeof(*eth);

  /** 
   * Byte-count bounds check; check if current pointer + size of header
   * is after data_end.
   */
  if (nh->pos + hdrsize > data_end)
    return -1;

  nh->pos += hdrsize;
  *ethhdr = eth;

  return eth->h_proto; /* network-byte-order */
}

/**
 * @brief IPv4 header parser
 * 
 * @param nh Cursor located at IPv4 header start.
 * Must be updated to the next header's location on return.
 * @param data_end Pointer to end of packet.
 * @param iphdr Empty IPv4 header.
 * Must be updated with adequate contents on return.
 * @return  IP protocol for next header or -1 on error.
 */
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

  /* Variable-length IPv4 header, need to use byte-based arithmetic. */
  if (nh->pos + hdrsize > data_end)
    return -1;

  nh->pos += hdrsize;
  *iphdr = iph;

  return iph->protocol;
}

/**
 * @brief UDP header parser
 * 
 * @param nh Cursor located at UDP header start.
 * Must be updated to the next header's location on return.
 * @param data_end Pointer to end of packet.
 * @param udphdr Empty UDP header.
 * Must be updated with adequate contents on return.
 * @return Length of UDP payload or -1 on error.
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

/**
 * @brief GTP header parser
 * 
 * @param nh Cursor located at GTP header start.
 * Must be updated to the next header's location on return.
 * @param data_end Pointer to end of packet.
 * @param gtphdr Empty GTP header.
 * Must be updated with adequate contents on return.
 * @return Length of GTP payload or -1 on error.
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

  /* Return if GTP header doesn't contain encapsulated user traffic. */
  if (h->message_type != GTP_G_PDU) {
    return -1;
  }

  /* Check for GTP optional fields. */
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

  /* Check for extension headers and adjust cursor position accordingly. */
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

  /* Return if number of extension headers > GTP_MAX_EXTENSION_HDR_NUM. */
  if (next_extension_hdr_type == GTP_NO_NEXT_EXTENSION_HDR) {
    return -1;
  }

out:
  len = (__s32)(data_end - nh->pos);
  return len;
}

#endif /* __PARSING_HELPERS_H */
