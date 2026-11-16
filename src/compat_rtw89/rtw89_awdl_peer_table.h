// SPDX-License-Identifier: MIT
// OWLY Core-02: bounded, allocation-free, receive-only AWDL peer correlator.
// No radio changes, TX, channel scheduling, authentication, or peer approval.
#ifndef RTW89_AWDL_PEER_TABLE_H
#define RTW89_AWDL_PEER_TABLE_H

#define OWLY_PEER_CAPACITY 8u

struct owly_peer_entry {
    unsigned char source[6]; /* in-RAM only; NEVER output to logs */
    unsigned char used;
    unsigned char saw_mif;
    unsigned char last_subtype;
    unsigned char has_sync;
    unsigned char has_chanseq;
    unsigned short last_aw_seq;
    unsigned short last_aw_period;
    unsigned short last_tx_down;
    unsigned long seen;
    unsigned long psf_count;
    unsigned long mif_count;
};
struct owly_peer_table {
    struct owly_peer_entry peers[OWLY_PEER_CAPACITY];
    unsigned long serial;
    unsigned long evictions;
};
struct owly_peer_event {
    unsigned int slot;       /* 1-based, EPHEMERAL slot: not a MAC or identity */
    unsigned char newly_seen;
    unsigned char evicted;
    unsigned char saw_mif;   /* MIF observed, NOT an authenticated peer */
    unsigned long psf_count;
    unsigned long mif_count;
    unsigned short last_aw_seq;
};
static inline int owly_source_equal(const unsigned char *a, const unsigned char *b)
{
    unsigned int i;
    for (i = 0; i < 6u; ++i) if (a[i] != b[i]) return 0;
    return 1;
}
static inline int owly_peer_observe(struct owly_peer_table *tab,
                                    const unsigned char *source,
                                    const struct owly_action_info *action,
                                    struct owly_peer_event *out)
{
    unsigned int i, idx = OWLY_PEER_CAPACITY;
    unsigned int empty = OWLY_PEER_CAPACITY, oldest = 0;
    unsigned long min_seen = ~0ul;
    struct owly_peer_entry *p;
    if (!tab || !source || !action || !out ||
        (action->subtype != 0u && action->subtype != 3u)) return 0;
    *out = (struct owly_peer_event){0};
    for (i = 0; i < OWLY_PEER_CAPACITY; ++i) {
        p = &tab->peers[i];
        if (p->used && owly_source_equal(p->source, source)) { idx = i; break; }
        if (!p->used && empty == OWLY_PEER_CAPACITY) empty = i;
        if (p->used && p->seen < min_seen) { min_seen = p->seen; oldest = i; }
    }
    if (idx == OWLY_PEER_CAPACITY) {
        unsigned int k;
        idx = empty != OWLY_PEER_CAPACITY ? empty : oldest;
        p = &tab->peers[idx];
        if (p->used) { ++tab->evictions; out->evicted = 1u; }
        *p = (struct owly_peer_entry){0};
        for (k = 0; k < 6u; ++k) p->source[k] = source[k];
        p->used = 1u;
        out->newly_seen = 1u;
    }
    p = &tab->peers[idx];
    p->seen = ++tab->serial;
    p->last_subtype = action->subtype;
    if (action->subtype == 3u) { p->saw_mif = 1u; ++p->mif_count; }
    else ++p->psf_count;
    if (action->has_sync) {
        p->has_sync = 1u;
        p->last_aw_seq = action->next_aw_seq;
        p->last_aw_period = action->aw_period_tu;
        p->last_tx_down = action->tx_down_tu;
    }
    if (action->has_chanseq) p->has_chanseq = 1u;
    out->slot = idx + 1u;
    out->saw_mif = p->saw_mif;
    out->psf_count = p->psf_count;
    out->mif_count = p->mif_count;
    out->last_aw_seq = p->last_aw_seq;
    return 1;
}
#endif
