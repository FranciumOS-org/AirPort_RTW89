/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_AWDL_MC_H
#define OWLY_AWDL_MC_H
#include <stdbool.h>
#include <stdint.h>

/*
 * Multichannel AWDL: while the station is associated on a channel AWDL does
 * not use, the radio visits the social channel (6) for some of the 16 AWDL
 * slots and spends the rest with the access point, which holds our traffic
 * because we tell it we are asleep (null frame with PM=1) before each visit.
 *
 * An AWDL slot is four 16 TU availability windows (64 TU). Slot n of the
 * sequence is (aw_sequence / 4) & 15, in the clock domain we advertise.
 * Pure policy, no kernel objects: tested by tools/hosttest/selftest.c.
 */
#define OWLY_MC_AW_US 16384u
#define OWLY_MC_SLOT_US (4u * OWLY_MC_AW_US)
/* Arrive this early on the social channel: the switch takes a few ms. */
#define OWLY_MC_LEAD_US 3000u

/* Interleaved order: alternate visits so the access point never waits
 * more than one slot (64 TU) for us while we stay at or under 8 slots. */
static const uint8_t owly_mc_order[16] = {0, 8, 4, 12, 2, 10, 6, 14,
                                          1, 9, 5, 13, 3, 11, 7, 15};

/* Choose the slots to spend on the social channel.
 * peer_slots: slots in which the followed peers are on the social channel,
 * 0 when no peer schedule is known (then every slot qualifies).
 * peers: number of AWDL peers heard recently; busy: AWDL data in flight. */
static inline uint16_t owly_mc_pick_slots(uint16_t peer_slots, unsigned peers,
                                          bool busy)
{
    const unsigned cap = busy ? 12u : peers ? 6u : 2u;
    uint16_t chosen = 0;
    unsigned n = 0;
    if (!peer_slots)
        peer_slots = 0xffffu;
    for (unsigned i = 0; i < 16u && n < cap; i++) {
        const unsigned slot = owly_mc_order[i];
        if (peer_slots & (1u << slot)) {
            chosen |= (uint16_t)(1u << slot);
            n++;
        }
    }
    /* Peers never on channel 6: still keep the discovery slots. */
    return chosen ? chosen : (uint16_t)((1u << 0) | (1u << 8));
}

/* Where we are in the 16-slot sequence. sequence/phase_us describe the
 * current AW (phase in [0, AW)). Returns the slot; *until_next_us is the
 * time to the next slot edge. */
static inline unsigned owly_mc_slot(uint16_t sequence, uint32_t phase_us,
                                    uint32_t *until_next_us)
{
    if (phase_us >= OWLY_MC_AW_US)
        phase_us = OWLY_MC_AW_US - 1u;
    if (until_next_us)
        *until_next_us = (3u - (sequence & 3u)) * OWLY_MC_AW_US +
                         (OWLY_MC_AW_US - phase_us);
    return (sequence / 4u) & 15u;
}

/* Should the radio be on the social channel now? True inside a chosen slot
 * and during the lead time before one. */
static inline bool owly_mc_want_social(uint16_t slots, unsigned slot,
                                       uint32_t until_next_us)
{
    if (slots & (1u << slot))
        return true;
    return until_next_us <= OWLY_MC_LEAD_US &&
           (slots & (1u << ((slot + 1u) & 15u)));
}

/* Delay until the next decision point: the lead before the next edge, or
 * just past the edge when the lead has already started. */
static inline uint32_t owly_mc_next_check_us(uint32_t until_next_us)
{
    if (until_next_us > OWLY_MC_LEAD_US + 500u)
        return until_next_us - OWLY_MC_LEAD_US;
    return until_next_us + 200u;
}
#endif
