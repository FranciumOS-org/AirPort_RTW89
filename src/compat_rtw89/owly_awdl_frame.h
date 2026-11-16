/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_AWDL_FRAME_H
#define OWLY_AWDL_FRAME_H
#include <stddef.h>
#include <stdint.h>

/* Packet codec only: no allocation, no skb ownership, no RF I/O.
 * Input is plain 802.11 (no radiotap, NO FCS) after hardware CRC validation.
 * A successful parse proves syntax only: NOT peer authenticity or a link. */
#define OWLY_AWDL_MAX_FRAME 16384u
#define OWLY_AWDL_MAX_MSDU 16u

/* 0: not an AWDL data frame; 1: valid; negative: malformed/unsupported. */
enum owly_awdl_parse_result {
    OWLY_AWDL_NOT_DATA = 0,
    OWLY_AWDL_OK = 1,
    OWLY_AWDL_MALFORMED = -1,
    OWLY_AWDL_UNSUPPORTED = -2,
    OWLY_AWDL_TOO_MANY = -3
};
struct owly_awdl_ip6 {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    const uint8_t *packet;  /* borrows backing frame, never owns it */
    size_t packet_len;
    uint16_t awdl_seq;
};
struct owly_awdl_batch {
    size_t count;
    struct owly_awdl_ip6 parts[OWLY_AWDL_MAX_MSDU];
};
/* out must not overlap frame. Invalid overlap returns MALFORMED without writing
 * either buffer. Other failure paths clear out; never process a partial batch. */
int owly_awdl_parse_80211(const uint8_t *frame, size_t n,
                           struct owly_awdl_batch *out);
/* A plain QoS data frame for caller's radio TX queue; no TX is performed.
 * out must not overlap any input. out_len must overlap neither input nor output.
 * Returns 0 on success. Other failures set *out_len=0 without changing out;
 * invalid out_len aliasing is rejected without writing through that pointer. */
int owly_awdl_pack_ipv6(const uint8_t *ipv6, size_t iplen,
                        const uint8_t dst_mac[6], const uint8_t src_mac[6],
                        uint16_t wifi_sequence, uint16_t awdl_sequence,
                        uint8_t *out, size_t out_cap, size_t *out_len);
#endif
