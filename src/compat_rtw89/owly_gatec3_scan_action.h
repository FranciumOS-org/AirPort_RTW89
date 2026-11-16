/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_GATEC3_SCAN_ACTION_H
#define OWLY_GATEC3_SCAN_ACTION_H
/* Read-only parser used from C glue only; frontend needs signature header. */
#include "owly_gatec3_scan_signature.h"
#include "rtw89_awdl_action_decode.h"
enum owly_c3_scan_class {
    OWLY_C3_SCAN_REJECT = 0,
    OWLY_C3_SCAN_SIGNATURE_ONLY = 1,
    OWLY_C3_SCAN_DECODED_INCOMPLETE = 2,
    OWLY_C3_SCAN_DECODED_COMPLETE = 3
};
static inline enum owly_c3_scan_class owly_c3_scan_classify(
    const uint8_t *f, size_t n, unsigned int freq,
    bool crc_ok, bool scanning, bool aux_ready)
{
    struct owly_action_info d = {0};
    enum owly_action_result rc;
    if (!crc_ok || !scanning || !aux_ready || !owly_c3_scan_frequency_allowed(freq) ||
        !owly_c3_scan_signature(f,n)) return OWLY_C3_SCAN_REJECT;
    rc = owly_decode_action(f,n,&d);
    if (rc != OWLY_ACTION_DECODED) return OWLY_C3_SCAN_SIGNATURE_ONLY;
    return d.complete ? OWLY_C3_SCAN_DECODED_COMPLETE : OWLY_C3_SCAN_DECODED_INCOMPLETE;
}
#endif
