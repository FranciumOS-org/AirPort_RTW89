// SPDX-License-Identifier: MIT
// AWDL Core-03: passive per-peer AW sequence/uptime consistency tracker.
// This is NOT RF/TSF synchronization, not an AW boundary and NOT a TX scheduler.
// Inputs: local MONOTONIC receive-observation microseconds, parsed AW next_seq,
// and parsed AW period (TU). Does not allocate, send, change channels or filters.
#ifndef RTW89_AWDL_CLOCK_H
#define RTW89_AWDL_CLOCK_H

#define OWLY_CLOCK_PEER_CAPACITY 8u
#define OWLY_CLOCK_MAX_GAP_US 5000000ull

/* External platform-specific monotonic clock time is required in us. */
struct owly_clock_peer {
    unsigned long long last_us;
    unsigned short last_seq;
    unsigned short period_tu;
    unsigned short good_pairs;
    unsigned short rejected_pairs;
    unsigned char initialized;
};

/* Status 1=first sample, 2=consistent, 3=outlier reset,
 * 4=duplicate seq, 5=stale gap reset, 6=invalid input. */
struct owly_clock_event {
    unsigned int status;
    unsigned int seq_delta;
    unsigned int good_pairs;
    unsigned long long actual_us;
    unsigned long long expected_us;
    unsigned long long abs_error_us;
    unsigned long long tolerance_us;
};

static inline void owly_clock_reset(struct owly_clock_peer *p)
{
    if (!p) return;
    *p = (struct owly_clock_peer){0};
}

static inline struct owly_clock_event
owly_clock_observe(struct owly_clock_peer *p,
                   unsigned long long now_us,
                   unsigned short next_seq,
                   unsigned short period_tu,
                   int new_peer)
{
    struct owly_clock_event e = {0};
    unsigned int delta;
    unsigned long long actual, expected, difference, tolerance;
    if (!p || !now_us || !period_tu || period_tu > 256u) {
        e.status = 6u;
        return e;
    }
    if (new_peer || !p->initialized) {
        owly_clock_reset(p);
        p->last_us = now_us;
        p->last_seq = next_seq;
        p->period_tu = period_tu;
        p->initialized = 1u;
        e.status = 1u;
        return e;
    }
    if (now_us <= p->last_us || period_tu != p->period_tu) {
        owly_clock_reset(p);
        p->last_us = now_us;
        p->last_seq = next_seq;
        p->period_tu = period_tu;
        p->initialized = 1u;
        e.status = 3u;
        return e;
    }
    actual = now_us - p->last_us;
    delta = (unsigned short)(next_seq - p->last_seq); /* 16-bit wrap */
    if (!delta && actual < OWLY_CLOCK_MAX_GAP_US) {
        e.status = 4u; /* duplicates do not advance the reference */
        return e;
    }
    if (actual > OWLY_CLOCK_MAX_GAP_US || !delta || delta > 32768u) {
        owly_clock_reset(p);
        p->last_us = now_us;
        p->last_seq = next_seq;
        p->period_tu = period_tu;
        p->initialized = 1u;
        e.status = 5u;
        return e;
    }
    expected = (unsigned long long)delta * period_tu * 1024ull;
    difference = actual >= expected ? actual - expected : expected - actual;
    /* Receive timestamps include scheduling and logging jitter. This threshold
     * is an anti-outlier heuristic, NOT a bound on RF synchronization error. */
    tolerance = 4000ull + expected / 50ull;
    if (tolerance > 25000ull) tolerance = 25000ull;
    e.actual_us = actual;
    e.expected_us = expected;
    e.abs_error_us = difference;
    e.tolerance_us = tolerance;
    e.seq_delta = delta;
    if (difference > tolerance) {
        if (p->rejected_pairs < 65535u) ++p->rejected_pairs;
        p->good_pairs = 0;
        e.status = 3u;
    } else {
        if (p->good_pairs < 65535u) ++p->good_pairs;
        e.status = 2u;
    }
    p->last_us = now_us;
    p->last_seq = next_seq;
    p->period_tu = period_tu;
    e.good_pairs = p->good_pairs;
    return e;
}

/* Only extrapolates the sequence counter; DOES NOT predict physical AW start.
 * Returns 1 on a bounded, recent estimate. A caller MUST NOT use this for TX. */
static inline int owly_clock_project_sequence(const struct owly_clock_peer *p,
                                               unsigned long long now_us,
                                               unsigned short *seq)
{
    unsigned long long elapsed, period_us;
    if (!p || !seq || !p->initialized || p->good_pairs < 2u ||
        now_us < p->last_us) return 0;
    elapsed = now_us - p->last_us;
    if (elapsed > 1000000ull) return 0;
    period_us = (unsigned long long)p->period_tu * 1024ull;
    if (!period_us) return 0;
    *seq = (unsigned short)(p->last_seq + (unsigned short)(elapsed / period_us));
    return 1;
}
#endif
