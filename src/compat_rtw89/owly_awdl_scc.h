/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_AWDL_SCC_H
#define OWLY_AWDL_SCC_H
#include <stdint.h>
/* Pure decision only: neither establishes time synchronization nor moves RF. */
#define OWLY_SCC_SLOTS 16u
#define OWLY_SCC_AW_TU 16u
#define OWLY_SCC_TU_PER_SLOT 64u

struct owly_scc_inputs {
    int master_clock_valid;   /* real master/peer phase has been established */
    int radio_on_ap_channel; /* verified, no off-channel scan at decision time */
    uint8_t ap_channel;
    uint8_t own_slot_channel[OWLY_SCC_SLOTS];
    uint8_t peer_slot_channel[OWLY_SCC_SLOTS];
    uint64_t master_tu;       /* 1 TU = 1024us, corrected to master phase */
};
enum owly_scc_tx_decision {
    OWLY_SCC_SEND = 1,
    OWLY_SCC_UNSYNCED = 0,
    OWLY_SCC_WRONG_CHANNEL = -1,
    OWLY_SCC_NO_SHARED_SLOT = -2,
    OWLY_SCC_GUARD = -3,
    OWLY_SCC_BAD_INPUT = -4
};
int owly_scc_decide_unicast(const struct owly_scc_inputs *s);
/* Produce an honest local advertisement: 0 where radio is unavailable.
 * served_bitmap: 16 physical slots actually served on AP channel. */
int owly_scc_advertised_sequence(uint8_t ap_channel, uint16_t served_bitmap,
                                 uint8_t sequence[OWLY_SCC_SLOTS]);
#endif
