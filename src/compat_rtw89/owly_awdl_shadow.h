/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_AWDL_SHADOW_H
#define OWLY_AWDL_SHADOW_H
#include <stddef.h>
#include <stdint.h>
/* No pointer retained. No skb ownership. No radio I/O. */
enum owly_shadow_event_kind {
    OWLY_SHADOW_OTHER = 0,
    OWLY_SHADOW_ACTION = 1,
    OWLY_SHADOW_IPV6 = 2,
    OWLY_SHADOW_BAD_DATA = 3,
    OWLY_SHADOW_UNSUPPORTED = 4
};
struct owly_shadow_event {
    uint64_t total;
    uint64_t candidates;
    uint64_t actions;
    uint64_t ipv6_frames;
    uint64_t ipv6_subframes;
    uint64_t bad_data;
    uint64_t unsupported;
    uint64_t counted;
    unsigned kind;
    unsigned log_milestone;
};
/* Input must be CRC-good raw 802.11 WITHOUT FCS; no radiotap. */
void owly_shadow_note(const uint8_t *frame, size_t len, struct owly_shadow_event *out);
#endif
