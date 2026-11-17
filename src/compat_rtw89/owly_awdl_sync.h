/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_AWDL_SYNC_H
#define OWLY_AWDL_SYNC_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "owly_native_config.h"
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
#include "owly_native_link.h"
#endif

/* SCC action frame scheduler, serialized with the wiphy mutex.
 * Apple supplies the static TLVs. Timing is derived from the host clock. */
#define OWLY_SYNC_TEMPLATE_MAX 1826u
#define OWLY_SYNC_FRAME_MAX 2048u
#define OWLY_SYNC_WIRE_OVERHEAD 160u
#define OWLY_SYNC_AW_US 16384ull
#define OWLY_SYNC_AF_US 110000ull
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
#define OWLY_MI_PENDING_US (16u * 4u * OWLY_SYNC_AW_US)
enum { OWLY_MI_INVALID=-1, OWLY_MI_BUSY=-2 };
struct owly_mi_template {
    size_t length;
    bool has_arpa;
    uint8_t bytes[OWLY_MI_TEMPLATE_MAX];
};
#endif
struct owly_sync {
    bool requested, active, blocked, hold_for_peer, explicitly_disabled;
    uint8_t channel, mac[6];
    uint16_t sequence;
    uint64_t due_us, last_us, staged, handed_off, failed, skipped;
    struct owly_native_config native;
    size_t template_len;
    uint8_t template_bytes[OWLY_SYNC_TEMPLATE_MAX];
    bool native_arpa, have_host;
    uint8_t host[36];
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    struct owly_link_window peer_clock;
    uint64_t mif_due_us;
    struct owly_mi_template auto_mi, pending_mi;
    uint64_t pending_mi_us, native_mi_handed_off;
    uint8_t pending_mi_destination[6], pending_mi_channel;
    bool pending_mi_ready, last_native_mi, last_pending_mi;
    bool broadcast_mif_submitted, last_broadcast_mif;
    /* The advertised slots and root prefix stay in the backend. */
    uint16_t shared_slots;
    /* Multichannel: slots we are on the social channel; 0 = all. */
    uint16_t presence_slots;
    bool have_master_election;
    uint8_t master_election[24];
#endif
};
void owly_sync_reset(struct owly_sync *s);
/* 0 succeeds; invalid/oversized/partial/non-TLV data returns -1 unchanged.
 * NULL,0 clears. Embedded schedule TLVs 4/18 are replaced, never duplicated. */
int owly_sync_template(struct owly_sync *s, const uint8_t *p, size_t n,
                       const uint8_t mac[6]);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
/* Copy the caller's MI template, returning 0 or OWLY_MI_INVALID/OWLY_MI_BUSY.
 * Channel 0 stages an automatic template before binding. A one-shot
 * stays on its original SCC channel for up to one 16-slot cycle. */
int owly_sync_mi(struct owly_sync *s, bool automatic, const uint8_t destination[6],
                 const uint8_t *p, size_t n, const uint8_t mac[6],
                 uint8_t channel, uint64_t now);
#endif
void owly_sync_request(struct owly_sync *s, bool on);
/* Learn only a local UUID host in an outbound mDNS response whose AAAA
 * matches the actual AWDL MAC and whose SRV names that same host. */
bool owly_sync_note_tx(struct owly_sync *s, const uint8_t *ethernet, size_t length);
bool owly_sync_configured(const struct owly_sync *s);
void owly_sync_reconcile(struct owly_sync *s, bool ready, uint8_t channel,
                         uint64_t now_us);
/* 1 frame ready, 0 not due/inactive, -1 invalid output. Updates the absolute
 * deadline, skips missed periods rather than bursting. Times are HOST clock
 * estimates, not a claim to know the chip's physical transmit timestamp. */
int owly_sync_frame(struct owly_sync *s, uint64_t now_us, uint8_t *frame,
                    size_t capacity, size_t *length);
void owly_sync_result(struct owly_sync *s, int enqueue_result);
#endif
