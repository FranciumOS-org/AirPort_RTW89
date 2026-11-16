/* SPDX-License-Identifier: GPL-2.0 */
#include "owly_abi6_rx.h"
#include "owly_awdl_frame.h"
#include <string.h>

/* Policy is deliberately tighter than broad FIF_OTHER_BSS: no delivery
 * during a scan, no off-channel reception, no TX or channel switching. */
static bool eligible(const struct owly_abi6_rx_context *s)
{
    if (!s || !s->crc_ok || (!s->sta_connected && !s->standalone_channel) ||
        !s->aux_present || s->scanning)
        return false;
    if (s->standalone_channel && (!s->sta_width_mhz || s->sta_width_mhz != 20u ||
        s->rx_freq_mhz != s->sta_freq_mhz)) return false;
    /* Reported RX freq can mean the primary 20 MHz channel or the
     * actual associated channel center. Never admit arbitrary +/-30 MHz
     * frames: the secondary path requires the negotiated center and width. */
    if (s->rx_freq_mhz != s->sta_freq_mhz) {
        unsigned int delta;
        if (s->sta_width_mhz != 40u && s->sta_width_mhz != 80u)
            return false;
        if (s->rx_freq_mhz != s->sta_center_freq_mhz)
            return false;
        delta = s->sta_freq_mhz > s->sta_center_freq_mhz ?
            s->sta_freq_mhz - s->sta_center_freq_mhz :
            s->sta_center_freq_mhz - s->sta_freq_mhz;
        if (s->sta_width_mhz == 80u ?
            !(delta == 10u || delta == 30u) : delta != 10u)
            return false;
    }
    return s->sta_freq_mhz == 2437u || s->sta_freq_mhz == 5220u ||
           s->sta_freq_mhz == 5745u;
}

struct owly_abi6_rx_result owly_abi6_demux(
    const uint8_t *frame, size_t len,
    const struct owly_abi6_rx_context *state,
    const struct owly_abi6_rx_sinks *sink)
{
    static const uint8_t awdl_bssid[6] = {0x00,0x25,0x00,0xff,0x94,0x73};
    struct owly_abi6_rx_result out = { OWLY_ABI6_RX_NOT_ELIGIBLE, 0, 0, false };
    struct owly_action_info action = {0};
    struct owly_awdl_batch batch;
    unsigned int type;
    int decode;
    size_t i;

    if (!eligible(state) || !frame || len < 24u) return out;
    out.kind = OWLY_ABI6_RX_NOT_AWDL;
    if (memcmp(frame + 16, awdl_bssid, 6) != 0) return out;
    type = (frame[0] >> 2) & 3u;
    if (type == 0u) {
        decode = owly_decode_action(frame, len, &action);
        if (decode == OWLY_ACTION_NOT_MATCH) return out;
        out.kind = OWLY_ABI6_RX_INVALID_AWDL;
        /* Known AWDL frames are owned by AWDL policy even when malformed.
         * A missing/refusing consumer means DROP, never STA fallback. */
        out.consumed = true;
        if (decode != OWLY_ACTION_DECODED || !action.complete) return out;
        out.kind = OWLY_ABI6_RX_ACTION;
        out.valid_units = 1;
        if (sink && sink->action && sink->action(sink->ctx, frame + 10, &action, frame, len))
            out.sink_accepted = 1;
        return out;
    }
    if (type != 2u) return out;
    decode = owly_awdl_parse_80211(frame, len, &batch);
    if (decode == OWLY_AWDL_NOT_DATA) return out;
    out.kind = OWLY_ABI6_RX_INVALID_AWDL;
    out.consumed = true; /* known AWDL BSSID; malformed does not enter STA */
    if (decode != OWLY_AWDL_OK || batch.count == 0u) return out;
    out.kind = OWLY_ABI6_RX_IPV6;
    out.valid_units = (unsigned int)batch.count;
    for (i = 0; i < batch.count; ++i) {
        const struct owly_awdl_ip6 *p = &batch.parts[i];
        /* Fail closed: this does not authorize peers or promise IP delivery. */
        /* Each validated A-MSDU subframe is independent. Inspect the rest
         * even if this sink has no Apple consumer or refuses a frame; never
         * imply delivery through the return value. The batch is bounded. */
        if (sink && sink->ipv6 &&
            sink->ipv6(sink->ctx, p->dst_mac, p->src_mac,
                       p->packet, p->packet_len))
            out.sink_accepted++;
    }
    /* Classified AWDL is handled or dropped here.  Delivery success is
     * measured only by sink_accepted, not by skb ownership/consumed. */
    return out;
}
