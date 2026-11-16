/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_GATEC3_SCAN_SIGNATURE_H
#define OWLY_GATEC3_SCAN_SIGNATURE_H
/* Minimal, pure signature check shared with C++ frontend. NOT peer validation. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define OWLY_C3_SCAN_FRAME_LIMIT 1024u
static inline bool owly_c3_scan_frequency_allowed(unsigned int f)
{
    /* 5775 MHz may be reported for a 149/80 MHz receive. */
    return f == 2437u || f == 5220u || f == 5745u || f == 5775u;
}
static inline bool owly_c3_scan_signature(const uint8_t *f, size_t n)
{
    static const uint8_t bssid[6] = {0,0x25,0,0xff,0x94,0x73};
    static const uint8_t vendor[5] = {127,0,0x17,0xf2,8};
    if (!f || n < 31u || n > OWLY_C3_SCAN_FRAME_LIMIT) return false;
    if (f[0] != 0xd0u || (f[1] & (0x01u|0x02u|0x40u)) != 0u) return false;
    if (memcmp(f+16,bssid,6) || memcmp(f+24,vendor,5)) return false;
    return f[30] == 0u || f[30] == 3u;
}
#endif
