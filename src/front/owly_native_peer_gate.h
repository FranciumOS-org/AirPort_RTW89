/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_NATIVE_PEER_GATE_H
#define OWLY_NATIVE_PEER_GATE_H
#include <stdint.h>
/* Read-only layout for Legacy UUID 4C07538B-62EB-3D6D-AEF9-93BCDCF45FAB.
 * Class size is from its MetaClass constructor. The RX condition is from
 * actionFrameProcessInput; AW-start events update sync_state, while
 * enableAWDL updates SYNC_ACTIVE. Neither substitutes for the other.
 * No object field is ever written through these offsets. */
#define OWLY_NATIVE_PEER_CLASS_BYTES 0xc528u
#define OWLY_NATIVE_PEER_SYNC_STATE_OFFSET 0xcd4u
#define OWLY_NATIVE_PEER_OWN_MAC_OFFSET 0x2801u
#define OWLY_NATIVE_PEER_RSSI_FLOOR_OFFSET 0x6e84u
#define OWLY_NATIVE_PEER_FLAGS_OFFSET 0x8528u
#define OWLY_NATIVE_PEER_RX_AF_OFFSET 0x8700u
#define OWLY_NATIVE_VIF_PEER_OFFSET 0xb0u
#define OWLY_NATIVE_PEER_CONFIGURED 1u
#define OWLY_NATIVE_PEER_SYNC_ACTIVE 2u
struct owly_native_peer_gate {
    uint32_t flags,sync_state;
    int32_t rssi_floor;
    uint8_t own_mac[6];
    uint32_t rx_af[4]; /* MIF2G, MIF5G, PSF2G, PSF5G; native updateAFStats. */
};
static inline bool owly_native_peer_rx_open(const struct owly_native_peer_gate *g)
{
    return g && (g->flags&OWLY_NATIVE_PEER_SYNC_ACTIVE) && g->sync_state!=0;
}
static inline uint32_t owly_native_peer_rx_af_total(const struct owly_native_peer_gate *g)
{
    return g->rx_af[0]+g->rx_af[1]+g->rx_af[2]+g->rx_af[3];
}
#endif
