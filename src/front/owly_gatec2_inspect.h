/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_GATEC2_INSPECT_H
#define OWLY_GATEC2_INSPECT_H
/* Gate C2: real backend-to-frontend packet inspection, no Apple RX call. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "owly_gatec_l2.h"

enum owly_gatec2_inspect_kind { OWLY_GATEC2_REJECT=0, OWLY_GATEC2_ACTION=1, OWLY_GATEC2_IPV6_L2=2 };
static inline enum owly_gatec2_inspect_kind owly_gatec2_inspect(
    const struct owly_abi6_packet *pkt, uint8_t *eth, size_t ethcap, size_t *ethlen)
{
    static const uint8_t bssid[6]={0x00,0x25,0x00,0xff,0x94,0x73};
    if (ethlen) *ethlen=0;
    if (!pkt || !ethlen) return OWLY_GATEC2_REJECT;
    if (pkt->kind==OWLY_ABI6_PACKET_ACTION) {
        if (pkt->length < 29u || pkt->length > OWLY_ABI6_PACKET_MAX_ACTION ||
            pkt->bytes[0]!=0xd0u || (pkt->bytes[1]&0x03u)!=0 ||
            memcmp(pkt->bytes+16,bssid,6)!=0 ||
            memcmp(pkt->bytes+10,pkt->src,6)!=0 ||
            memcmp(pkt->bytes+4,pkt->dst,6)!=0)
            return OWLY_GATEC2_REJECT;
        return OWLY_GATEC2_ACTION;
    }
    if (pkt->kind==OWLY_ABI6_PACKET_IPV6 &&
        owly_gatec_make_ipv6_eth(pkt,eth,ethcap,ethlen))
        return OWLY_GATEC2_IPV6_L2;
    return OWLY_GATEC2_REJECT;
}
#endif
