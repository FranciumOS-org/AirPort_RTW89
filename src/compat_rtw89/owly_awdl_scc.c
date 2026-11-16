/* SPDX-License-Identifier: GPL-2.0 */
#include "owly_awdl_scc.h"
#include <stddef.h>

static int social(uint8_t ch) { return ch == 6u || ch == 44u || ch == 149u; }
int owly_scc_advertised_sequence(uint8_t ch, uint16_t served,
                                 uint8_t seq[OWLY_SCC_SLOTS])
{
    unsigned i;
    if (!seq || !social(ch)) return -1;
    for (i = 0; i < OWLY_SCC_SLOTS; ++i)
        seq[i] = (served & ((uint16_t)1u << i)) ? ch : 0;
    return 0;
}
int owly_scc_decide_unicast(const struct owly_scc_inputs *s)
{
    unsigned slot, time_in_aw;
    if (!s || !social(s->ap_channel)) return OWLY_SCC_BAD_INPUT;
    if (!s->master_clock_valid) return OWLY_SCC_UNSYNCED;
    if (!s->radio_on_ap_channel) return OWLY_SCC_WRONG_CHANNEL;
    slot = (unsigned)((s->master_tu / OWLY_SCC_TU_PER_SLOT) % OWLY_SCC_SLOTS);
    if (s->own_slot_channel[slot] != s->ap_channel ||
        s->peer_slot_channel[slot] != s->ap_channel)
        return OWLY_SCC_NO_SHARED_SLOT;
    time_in_aw = (unsigned)(s->master_tu % OWLY_SCC_AW_TU);
    /* Conservative 3 TU guard on both edges of a 16 TU AW. */
    if (time_in_aw < 3u || time_in_aw >= 13u)
        return OWLY_SCC_GUARD;
    return OWLY_SCC_SEND;
}
