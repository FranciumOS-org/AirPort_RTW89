/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_ABI6_PACKET_H
#define OWLY_ABI6_PACKET_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define OWLY_ABI6_PACKET_MAX_ACTION 1024u
#define OWLY_ABI6_PACKET_MAX_IPV6 1536u
#define OWLY_ABI6_PACKET_MAX OWLY_ABI6_PACKET_MAX_IPV6
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
#undef OWLY_ABI6_PACKET_MAX_ACTION
#undef OWLY_ABI6_PACKET_MAX
#define OWLY_ABI6_PACKET_MAX_ACTION 2048u
#define OWLY_ABI6_PACKET_MAX 2048u
#endif
#define OWLY_ABI6_PACKET_ACTION 1u
#define OWLY_ABI6_PACKET_IPV6 2u
#define OWLY_ABI6_PACKET_C3_SCAN_SIGNATURE 3u /* strictly passive candidate; NO peer auth */
struct owly_abi6_packet {
    uint32_t kind;
    uint32_t length;
    uint8_t src[6];
    uint8_t dst[6];
    uint8_t bytes[OWLY_ABI6_PACKET_MAX];
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    uint8_t channel;
    int8_t rssi;
    uint64_t received_us;
#endif
};
/* Fail-closed, fully copied packet. No borrowed skb survives the caller. */
static inline bool owly_abi6_packet_make(struct owly_abi6_packet *out,
     uint32_t kind, const uint8_t *data, size_t len,
     const uint8_t src[6], const uint8_t dst[6])
{
    if (!out || !data || !src || !dst) return false;
    if (kind == OWLY_ABI6_PACKET_ACTION) {
        if (len < 29u || len > OWLY_ABI6_PACKET_MAX_ACTION || data[0] != 0xd0)
            return false;
    } else if (kind == OWLY_ABI6_PACKET_C3_SCAN_SIGNATURE) {
        if (len < 31u || len > OWLY_ABI6_PACKET_MAX_ACTION || data[0] != 0xd0u ||
            (data[1] & 0x03u) != 0u)
            return false;
    } else if (kind == OWLY_ABI6_PACKET_IPV6) {
        if (len < 40u || len > OWLY_ABI6_PACKET_MAX_IPV6 || (data[0] >> 4) != 6u)
            return false;
        /* The whole IPv6 packet is needed; padding/truncation is rejected. */
        if ((size_t)(40u + (((unsigned int)data[4] << 8) | data[5])) != len)
            return false;
    } else return false;
    memset(out, 0, sizeof(*out));
    out->kind = kind;
    out->length = (uint32_t)len;
    memcpy(out->src, src, 6);
    memcpy(out->dst, dst, 6);
    memcpy(out->bytes, data, len);
    return true;
}
#endif
