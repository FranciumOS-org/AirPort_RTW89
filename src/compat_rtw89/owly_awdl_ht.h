/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_AWDL_HT_H
#define OWLY_AWDL_HT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Legacy4C GET154: version followed by the complete EID45/length26 IE.
 * getHtCapabilityIE copies bytes 4..31, then builds AWDL TLV7 from the
 * capability body (skipping EID/length). Returning just the 26-byte body
 * shifts the MCS map and prevents remote peers from enabling their cache.
 * This is a subset of the real radio: HT20, one stream, long GI, no
 * LDPC/STBC/beamforming or large A-MSDU. TX may still use legacy OFDM6.
 */
#define OWLY_AWDL_HT_REPLY_BYTES 32u
static inline bool owly_awdl_build_ht(void *output, size_t capacity,
                                     uint8_t rx_mcs0, uint8_t ampdu_density)
{
    if (!output || capacity < OWLY_AWDL_HT_REPLY_BYTES || !rx_mcs0 ||
        ampdu_density > 7u) return false;
    uint8_t reply[OWLY_AWDL_HT_REPLY_BYTES] = {0};
    reply[0] = 1;             /* APPLE80211_VERSION, little endian */
    reply[4] = 45; reply[5] = 26;
    reply[6] = 0x0c;         /* SM power save disabled, HT20 */
    reply[8] = (uint8_t)(ampdu_density << 2); /* maximum A-MPDU 8191 */
    reply[9] = rx_mcs0;      /* only the hardware's first spatial stream */
    reply[21] = 1;          /* TX MCS set defined, same one-stream set */
    memcpy(output, reply, sizeof(reply));
    return true;
}
#endif
