/* SPDX-License-Identifier: GPL-2.0 */
#include "owly_awdl_frame.h"
#include <stdbool.h>
#include <string.h>

static const uint8_t awdl_bssid[6] = {0x00,0x25,0x00,0xff,0x94,0x73};
static const uint8_t awdl_snap[8] = {0xaa,0xaa,0x03,0x00,0x17,0xf2,0x08,0x00};
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1]<<8)); }
static uint16_t be16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0]<<8) | p[1]); }

/* Compare address differences, never overflowing an end pointer. Buffer aliasing
 * is a caller error: reject before memset/memcpy can destroy borrowed inputs. */
static int ranges_overlap(const void *a, size_t an, const void *b, size_t bn)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    if (!a || !b || !an || !bn) return 0;
    return x <= y ? y - x < an : x - y < bn;
}

/* Validate the entire IP payload and AWDL trailer. No guessed FCS removal. */
static int decode_msdu(const uint8_t *p, size_t n, const uint8_t *da,
                       const uint8_t *sa, bool qos, struct owly_awdl_ip6 *out)
{
    static const uint8_t llc_length_header[6] = {0xaa,0xaa,0x03,0,0,0};
    const uint8_t *ip;
    size_t iplen, extra, i;
    /* Recent iOS QoS data can prepend an LLC length header to each MSDU.
     * Measure it inside the subframe, independently of aggregate padding. */
    if (qos && n >= 8u && !memcmp(p, llc_length_header, sizeof(llc_length_header))) {
        if (be16(p + 6) != n - 8u)
            return OWLY_AWDL_MALFORMED;
        p += 8u;
        n -= 8u;
    }
    if (n < 8u + 8u + 40u || memcmp(p, awdl_snap, 8) != 0)
        return OWLY_AWDL_MALFORMED;
    if (p[8] != 0x03u || (p[9] != 0x00u && p[9] != 0x04u) || p[12] != 0 || p[13] != 0 ||
        p[14] != 0x86u || p[15] != 0xddu)
        return OWLY_AWDL_MALFORMED;
    ip = p + 16;
    if ((ip[0] >> 4) != 6)
        return OWLY_AWDL_MALFORMED;
    /* Jumbograms (payload_length=0) need HBH Jumbo option processing. */
    if (ip[4] == 0 && ip[5] == 0)
        return OWLY_AWDL_UNSUPPORTED;
    iplen = 40u + (size_t)be16(ip + 4);
    if (iplen > n - 16u)
        return OWLY_AWDL_MALFORMED;
    extra = n - 16u - iplen;
    /* Some NICs append up to 3 zero padding bytes. Never mistake junk for IPv6. */
    if (extra > 3u)
        return OWLY_AWDL_MALFORMED;
    for (i = 0; i < extra; ++i)
        if (ip[iplen + i] != 0)
            return OWLY_AWDL_MALFORMED;
    memcpy(out->dst_mac, da, 6);
    memcpy(out->src_mac, sa, 6);
    out->packet = ip;
    out->packet_len = iplen;
    out->awdl_seq = le16(p + 10);
    return OWLY_AWDL_OK;
}

int owly_awdl_parse_80211(const uint8_t *frame, size_t n,
                           struct owly_awdl_batch *out)
{
    uint16_t fc;
    unsigned type, sub;
    size_t off, remaining;
    const uint8_t *p;
    int rc;
    if (!out)
        return OWLY_AWDL_MALFORMED;
    if (ranges_overlap(out, sizeof(*out), frame, n))
        return OWLY_AWDL_MALFORMED;
    memset(out, 0, sizeof(*out));
    if (!frame || n < 24u || n > OWLY_AWDL_MAX_FRAME)
        return OWLY_AWDL_MALFORMED;
    fc = le16(frame);
    type = (fc >> 2) & 3u;
    sub  = (fc >> 4) & 15u;
    if (type != 2u || memcmp(frame + 16, awdl_bssid, 6) != 0)
        return OWLY_AWDL_NOT_DATA;
    /* Only plain 3-address, complete Data/QoS-Data frames at this stage. */
    if ((fc & (0x0100u | 0x0200u | 0x0400u | 0x4000u)) ||
        (le16(frame + 22) & 15u) || (sub != 0u && sub != 8u))
        return OWLY_AWDL_UNSUPPORTED;
    off = (sub == 8u) ? 26u : 24u;
    if (n < off)
        return OWLY_AWDL_MALFORMED;
    if (sub == 8u && (fc & 0x8000u)) /* HT Control */
        off += 4u;
    if (n < off)
        return OWLY_AWDL_MALFORMED;
    p = frame + off;
    remaining = n - off;
    if (sub != 8u || !(frame[24] & 0x80u)) {
        rc = decode_msdu(p, remaining, frame + 4, frame + 10, sub == 8u,
                         &out->parts[0]);
        if (rc < 0)
            return rc;
        out->count = 1;
        return OWLY_AWDL_OK;
    }
    /* A-MSDU: do all checks before exposing any entries to caller. */
    while (remaining) {
        size_t msdulen, consumed, pad, i;
        if (out->count >= OWLY_AWDL_MAX_MSDU) {
            memset(out, 0, sizeof(*out));
            return OWLY_AWDL_TOO_MANY;
        }
        if (remaining < 14u) goto bad;
        msdulen = be16(p + 12);
        if (msdulen < 56u || msdulen > remaining - 14u) goto bad;
        rc = decode_msdu(p + 14, msdulen, p, p + 6, true,
                         &out->parts[out->count]);
        if (rc != OWLY_AWDL_OK) {
            memset(out, 0, sizeof(*out));
            return rc;
        }
        out->count++;
        consumed = 14u + msdulen;
        remaining -= consumed;
        p += consumed;
        if (!remaining) break;
        pad = (4u - (consumed & 3u)) & 3u;
        if (remaining < pad) goto bad;
        for (i = 0; i < pad; ++i) if (p[i]) goto bad;
        p += pad;
        remaining -= pad;
        /* Last subframe's trailing zero padding is permitted. */
        if (remaining == 0) break;
        if (remaining < 14u) goto bad;
    }
    if (!out->count) goto bad;
    return OWLY_AWDL_OK;
bad:
    memset(out, 0, sizeof(*out));
    return OWLY_AWDL_MALFORMED;
}

int owly_awdl_pack_ipv6(const uint8_t *ipv6, size_t iplen,
                        const uint8_t dst_mac[6], const uint8_t src_mac[6],
                        uint16_t wifi_sequence, uint16_t awdl_sequence,
                        uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t n;
    uint16_t seqctl;
    /* The failure-length output must not overwrite any input, nor land in
     * the caller's frame buffer. Leave it untouched on invalid aliasing. */
    if (!out_len ||
        ranges_overlap(out_len, sizeof(*out_len), ipv6, iplen) ||
        ranges_overlap(out_len, sizeof(*out_len), dst_mac, 6u) ||
        ranges_overlap(out_len, sizeof(*out_len), src_mac, 6u) ||
        ranges_overlap(out_len, sizeof(*out_len), out, out_cap))
        return -1;
    if (out_len) *out_len = 0;
    if (!ipv6 || !dst_mac || !src_mac || !out || !out_len ||
        iplen < 41u || iplen > OWLY_AWDL_MAX_FRAME - 42u ||
        (ipv6[0] >> 4) != 6 || (ipv6[4] == 0 && ipv6[5] == 0) ||
        iplen != 40u + (size_t)be16(ipv6 + 4))
        return -1;
    n = 42u + iplen;
    if (out_cap < n) return -1;
    if (ranges_overlap(out, n, ipv6, iplen) ||
        ranges_overlap(out, n, dst_mac, 6u) ||
        ranges_overlap(out, n, src_mac, 6u))
        return -1;
    memset(out, 0, 26);
    out[0] = 0x88u; /* Data + QoS, no ToDS/FromDS */
    memcpy(out + 4, dst_mac, 6);
    memcpy(out + 10, src_mac, 6);
    memcpy(out + 16, awdl_bssid, 6);
    seqctl = (uint16_t)((wifi_sequence & 0x0fffu) << 4);
    out[22] = (uint8_t)seqctl;
    out[23] = (uint8_t)(seqctl >> 8);
    memcpy(out + 26, awdl_snap, sizeof(awdl_snap));
    out[34] = 0x03u; out[35] = 0x04u;
    out[36] = (uint8_t)awdl_sequence;
    out[37] = (uint8_t)(awdl_sequence >> 8);
    out[38] = 0; out[39] = 0;
    out[40] = 0x86u; out[41] = 0xddu;
    memcpy(out + 42, ipv6, iplen);
    *out_len = n;
    return 0;
}
