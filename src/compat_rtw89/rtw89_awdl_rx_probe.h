// SPDX-License-Identifier: GPL-2.0
// Phase L: optional, signature-only AWDL RX observation.
// Strictly source-side. No TX, RX-filter, channel or skb ownership changes.
#ifndef RTW89_AWDL_RX_PROBE_H
#define RTW89_AWDL_RX_PROBE_H
#include <stddef.h>

enum rtw89_awdl_rx_kind {
    RTW89_AWDL_RX_OTHER = 0,
    RTW89_AWDL_RX_ACTION = 1,
    RTW89_AWDL_RX_IPV6 = 2
};

static inline int rtw89_awdl_equal(const unsigned char *a,
                                   const unsigned char *b, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

/* The third MAC address (offset 16) is only available in management/data
 * frames with a >=24-byte 3-address MAC header. The BSSID check deliberately
 * accepts malformed/unrecognized AWDL payloads, so the counters distinguish
 * frame delivery from signature-parser misses. This is not peer validation. */
static inline int rtw89_awdl_rx_has_bssid(const unsigned char *f, size_t n)
{
    static const unsigned char bssid[6] = {0x00, 0x25, 0x00, 0xff, 0x94, 0x73};
    unsigned short fc;
    unsigned int type;

    if (!f || n < 24 || n > 4096)
        return 0;
    fc = (unsigned short)(f[0] | ((unsigned short)f[1] << 8));
    type = (fc >> 2) & 3u;
    if (type != 0 && type != 2)
        return 0;
    return rtw89_awdl_equal(f + 16, bssid, sizeof(bssid));
}

/* Raw 802.11 without radiotap or FCS. Heuristic signature ONLY, not an
 * authenticated peer, a validated session, nor AWDL negotiation.
 * QoS A-MSDU is intentionally NOT parsed here; its BSSID still counts.
 * The real AWDL data receiver must parse bounded A-MSDU subframes. */
static inline enum rtw89_awdl_rx_kind
rtw89_awdl_rx_classify(const unsigned char *f, size_t n)
{
    static const unsigned char oui[3] = {0x00, 0x17, 0xf2};
    static const unsigned char snap[8] = {0xaa, 0xaa, 0x03, 0x00, 0x17, 0xf2, 0x08, 0x00};
    unsigned short fc;
    unsigned char type, subtype;
    size_t off;
    int qos;

    if (!rtw89_awdl_rx_has_bssid(f, n))
        return RTW89_AWDL_RX_OTHER;
    fc = (unsigned short)(f[0] | ((unsigned short)f[1] << 8));
    type = (unsigned char)((fc >> 2) & 3u);
    subtype = (unsigned char)((fc >> 4) & 15u);
    /* No ToDS, FromDS or Protected bit for this narrow AWDL signature. */
    if (fc & (0x0100u | 0x0200u | 0x4000u))
        return RTW89_AWDL_RX_OTHER;

    if (type == 0 && subtype == 13) {
        /* Vendor action, Apple OUI, AWDL type, PSF/MIF subtype. */
        if (n >= 40 && f[24] == 127 &&
            rtw89_awdl_equal(f + 25, oui, sizeof(oui)) && f[28] == 8 &&
            (f[30] == 0 || f[30] == 3))
            return RTW89_AWDL_RX_ACTION;
        return RTW89_AWDL_RX_OTHER;
    }
    if (type != 2 || (subtype & 4u))  /* Null / QoS Null has no MSDU */
        return RTW89_AWDL_RX_OTHER;

    qos = (subtype & 8u) != 0;
    off = qos ? 26u : 24u;
    if (n < off)
        return RTW89_AWDL_RX_OTHER;
    if (qos) {
        if (f[24] & 0x80u)   /* A-MSDU bit: observe BSSID, not its payload */
            return RTW89_AWDL_RX_OTHER;
        if (fc & 0x8000u)   /* QoS + Order bit => HT Control (4 bytes) */
            off += 4u;
    }
    if (n < off + sizeof(snap) + 9u ||
        !rtw89_awdl_equal(f + off, snap, sizeof(snap)))
        return RTW89_AWDL_RX_OTHER;
    f += off + sizeof(snap);
    if (f[0] == 0x03 && f[1] == 0x04 && f[4] == 0 && f[5] == 0 &&
        f[6] == 0x86 && f[7] == 0xdd && (f[8] >> 4) == 6)
        return RTW89_AWDL_RX_IPV6;
    return RTW89_AWDL_RX_OTHER;
}
#endif
