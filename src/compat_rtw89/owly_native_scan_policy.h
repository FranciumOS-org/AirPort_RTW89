/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_NATIVE_SCAN_POLICY_H
#define OWLY_NATIVE_SCAN_POLICY_H
#include <stdbool.h>
#include <stdint.h>
#define OWLY_NATIVE_SCAN_GAP_NS 30000000000ull
#define OWLY_NATIVE_SCAN_CHANNELS 4u
#define OWLY_NATIVE_DATA_HOLD_US 2000000ull
/* Cache scan requests during real unicast traffic. When only a fresh peer is
 * present, permit bounded scans so new APs can still be discovered. */
static inline bool owly_native_scan_cached(bool protected_link,bool data_busy,
                                           uint64_t now,uint64_t last_scan)
{
    if(!protected_link)return false;
    if(data_busy)return true;
    return last_scan && now>=last_scan && now-last_scan<OWLY_NATIVE_SCAN_GAP_NS;
}
#endif
