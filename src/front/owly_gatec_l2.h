/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_GATEC_L2_H
#define OWLY_GATEC_L2_H
/*
 * Gate C1: pure, bounded IPv6 -> Ethernet II receive envelope.
 * No mbuf, no Apple-private packet_info_tag, no Apple inputPacket() call.
 * The output is a *candidate* Ethernet frame; delivery remains forbidden.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "owly_abi6_packet.h"

#define OWLY_GATEC_ETH_HEADER_SIZE 14u
#define OWLY_GATEC_ETH_FRAME_MAX (OWLY_GATEC_ETH_HEADER_SIZE + OWLY_ABI6_PACKET_MAX_IPV6)

static inline bool owly_gatec_make_ipv6_eth(const struct owly_abi6_packet *pkt,
                                            uint8_t *frame, size_t capacity,
                                            size_t *frame_len)
{
    if (frame_len) *frame_len = 0;
    if (!pkt || !frame || !frame_len || pkt->kind != OWLY_ABI6_PACKET_IPV6)
        return false;
    if (pkt->length < 40u || pkt->length > OWLY_ABI6_PACKET_MAX_IPV6 ||
        capacity < (size_t)pkt->length + OWLY_GATEC_ETH_HEADER_SIZE)
        return false;
    if ((pkt->bytes[0] >> 4) != 6u ||
        (size_t)40u + ((((size_t)pkt->bytes[4]) << 8) | pkt->bytes[5]) != pkt->length)
        return false;
    /* Ethernet source must be an individual MAC, never multicast/broadcast. */
    if ((pkt->src[0] & 1u) != 0u)
        return false;
    /* IP multicast uses 33:33:xx:xx:xx:xx at Ethernet layer (RFC 2464). */
    if (pkt->bytes[24] == 0xffu) {
        if (pkt->dst[0] != 0x33u || pkt->dst[1] != 0x33u ||
            memcmp(pkt->dst + 2, pkt->bytes + 36, 4) != 0)
            return false;
    }
    /* Input/output may never alias: avoid overlapping source and destination. */
    uintptr_t in_start = (uintptr_t)pkt;
    uintptr_t out_start = (uintptr_t)frame;
    if (out_start >= in_start && out_start - in_start < sizeof(*pkt)) return false;
    if (in_start >= out_start && in_start - out_start < capacity) return false;

    memcpy(frame, pkt->dst, 6);
    memcpy(frame + 6, pkt->src, 6);
    frame[12] = 0x86u;
    frame[13] = 0xddu;
    memcpy(frame + OWLY_GATEC_ETH_HEADER_SIZE, pkt->bytes, pkt->length);
    *frame_len = (size_t)pkt->length + OWLY_GATEC_ETH_HEADER_SIZE;
    return true;
}
#endif
