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

/* A joined station (issues #12, #18): macOS asks for a background scan about
 * every 30 s, and each one takes the radio off the network's channel for up
 * to a second, which on a busy link shows as stalls and slow speed tests.
 * While the link carries traffic (at least RTW89_SCAN_BUSY_FPS data frames a
 * second since the previous request) a request is answered from the cache,
 * up to RTW89_SCAN_BUSY_MAX_NS after the last real scan, as a Mac's own card
 * does. An idle link still scans every OWLY_NATIVE_SCAN_GAP_NS. */
#define RTW89_SCAN_BUSY_FPS 50u
#define RTW89_SCAN_BUSY_MAX_NS 300000000000ull
static inline bool rtw89_station_scan_busy(uint64_t now, uint64_t prev_at,
                                           uint64_t frames, uint64_t prev_frames)
{
    if(!prev_at || now<=prev_at || frames<prev_frames)return false;
    /* frames per second, without overflow for any plausible count */
    return (frames-prev_frames)*1000000000ull/(now-prev_at)>=RTW89_SCAN_BUSY_FPS;
}
static inline bool rtw89_station_scan_cached(bool busy, uint64_t now, uint64_t last_scan)
{
    if(!last_scan || now<last_scan)return false;
    if(now-last_scan<OWLY_NATIVE_SCAN_GAP_NS)return true;
    return busy && now-last_scan<RTW89_SCAN_BUSY_MAX_NS;
}
#endif
