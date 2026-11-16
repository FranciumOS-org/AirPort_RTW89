/* SPDX-License-Identifier: GPL-2.0 */
#include "owly_awdl_shadow.h"
#include "owly_awdl_frame.h"
#include <string.h>

static volatile uint64_t g_total;
static volatile uint64_t g_candidates;
static volatile uint64_t g_actions;
static volatile uint64_t g_ipv6;
static volatile uint64_t g_subframes;
static volatile uint64_t g_bad;
static volatile uint64_t g_unsupported;
static const uint8_t bssid[6] = {0x00,0x25,0x00,0xff,0x94,0x73};

static uint64_t inc(volatile uint64_t *p) { return __sync_add_and_fetch(p, 1ULL); }
static uint64_t readc(volatile uint64_t *p) { return __sync_fetch_and_add(p, 0ULL); }
static int power_two(uint64_t n) { return n && ((n & (n - 1ULL)) == 0); }
static void snapshot(struct owly_shadow_event *e) {
    e->total = readc(&g_total);
    e->candidates = readc(&g_candidates);
    e->actions = readc(&g_actions);
    e->ipv6_frames = readc(&g_ipv6);
    e->ipv6_subframes = readc(&g_subframes);
    e->bad_data = readc(&g_bad);
    e->unsupported = readc(&g_unsupported);
}
void owly_shadow_note(const uint8_t *frame, size_t len, struct owly_shadow_event *out)
{
    uint16_t fc;
    unsigned type, subtype;
    uint64_t n;
    struct owly_awdl_batch batch;
    int rc;
    if (!out) return;
    memset(out, 0, sizeof(*out));
    n = inc(&g_total);
    /* Log total RX only at 1,2,4,8,..., showing the RX callback remains live. */
    out->log_milestone = power_two(n) ? 1u : 0u;
    if (!frame || len < 24u || len > OWLY_AWDL_MAX_FRAME ||
        memcmp(frame + 16, bssid, 6) != 0) {
        snapshot(out);
        return;
    }
    fc = (uint16_t)(frame[0] | ((uint16_t)frame[1] << 8));
    type = (fc >> 2) & 3u;
    subtype = (fc >> 4) & 15u;
    if (type != 0 && type != 2) { snapshot(out); return; }
    n = inc(&g_candidates);
    /* Candidate BSSID only, not verified peer identity. */
    out->log_milestone = (n <= 8 || power_two(n)) ? 1u : 0u;
    if (type == 0) {
        if (subtype == 13 && len >= 32 && frame[24] == 127 &&
            frame[25] == 0x00 && frame[26] == 0x17 && frame[27] == 0xf2 &&
            frame[28] == 8 && (frame[30] == 0 || frame[30] == 3)) {
            out->kind = OWLY_SHADOW_ACTION;
            inc(&g_actions);
        } else {
            out->kind = OWLY_SHADOW_UNSUPPORTED;
            inc(&g_unsupported);
        }
    } else {
        rc = owly_awdl_parse_80211(frame, len, &batch);
        if (rc == OWLY_AWDL_OK) {
            out->kind = OWLY_SHADOW_IPV6;
            inc(&g_ipv6);
            __sync_add_and_fetch(&g_subframes, (uint64_t)batch.count);
        } else if (rc == OWLY_AWDL_UNSUPPORTED || rc == OWLY_AWDL_TOO_MANY ||
                   rc == OWLY_AWDL_NOT_DATA) {
            out->kind = OWLY_SHADOW_UNSUPPORTED;
            inc(&g_unsupported);
        } else {
            out->kind = OWLY_SHADOW_BAD_DATA;
            inc(&g_bad);
        }
    }
    out->counted = 1;
    snapshot(out);
}
