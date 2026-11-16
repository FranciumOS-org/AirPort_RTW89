/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_RADIO_TIMING_H
#define OWLY_RADIO_TIMING_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Non-QoS data and management from one transmitter share a sequence space.
 * Allocate at the final serialized radio submission, not in two builders. */
struct owly_radio_sequence { uint8_t own[6]; uint16_t next; bool valid; };
static inline bool owly_radio_assign_sequence(struct owly_radio_sequence *s,
                                               uint8_t *f, size_t n)
{
    static const uint8_t bssid[6]={0,0x25,0,0xff,0x94,0x73};
    if(!s || !f || n<24 || (f[0]!=8 && f[0]!=0xd0) || (f[1]&0x47) ||
       (f[22]&15) || (f[10]&1) || !memcmp(f+10,"\0\0\0\0\0\0",6) ||
       memcmp(f+16,bssid,6))return false;
    if(!s->valid || memcmp(s->own,f+10,6)) {
        memcpy(s->own,f+10,6);s->next=0;s->valid=true;
    }
    const uint16_t seq=(uint16_t)((s->next++ & 4095u)<<4);
    f[22]=(uint8_t)seq;f[23]=(uint8_t)(seq>>8);
    return true;
}

/* Project a bounded TU snapshot to the actual action serialization time.
 * Input countdown is rounded up to TU: uncertainty stays below one TU. */
static inline bool owly_radio_project_window(uint64_t sampled, uint16_t sequence,
        uint16_t until_tu, uint64_t now, uint16_t *seq, uint16_t *remaining)
{
    if(!seq || !remaining || !until_tu || until_tu>16 || now<sampled ||
       now-sampled>=16384u)return false;
    const uint64_t age=now-sampled, boundary=(uint64_t)until_tu*1024u;
    if(age<boundary) {
        *seq=sequence;*remaining=(uint16_t)((boundary-age+1023u)/1024u);
    } else {
        const uint64_t elapsed=age-boundary;
        *seq=(uint16_t)(sequence+1u+elapsed/16384u);
        *remaining=(uint16_t)((16384u-elapsed%16384u+1023u)/1024u);
    }
    return true;
}

/* Map the RX descriptor's 32-bit microsecond counter to CLOCK_BOOTTIME.
 * Only the RX thread updates this structure. Minimum offsets over adjacent
 * five-second windows remove variable ring/PPDU dispatch delay. The minimum
 * processing delay remains an estimate, not a measured RF/TSF alignment.
 * Missing timestamps and discontinuities fall back to host receipt time. */
struct owly_radio_rx_clock {
    uint64_t epoch_us,last_host_us;
    uint32_t current,previous;
    bool valid,previous_valid;
};
static inline uint64_t owly_radio_rx_time(struct owly_radio_rx_clock *c,
                                          uint64_t host_us, uint32_t hardware_us,
                                          bool valid)
{
    if(!c || !valid)return host_us;
    const uint32_t offset=(uint32_t)host_us-hardware_us;
    if(!c->valid || host_us<c->last_host_us || host_us-c->last_host_us>5000000u) {
        c->epoch_us=host_us;c->current=offset;c->valid=true;c->previous_valid=false;
    } else {
        const int32_t change=(int32_t)(offset-c->current);
        if(change < -1000000 || change>1000000) {
            c->epoch_us=host_us;c->current=offset;c->previous_valid=false;
        }
        if(host_us-c->epoch_us>=5000000u) {
            c->previous=c->current;c->previous_valid=true;
            c->current=offset;c->epoch_us=host_us;
        } else if((int32_t)(offset-c->current)<0)c->current=offset;
    }
    c->last_host_us=host_us;
    uint32_t base=c->current;
    if(c->previous_valid && (int32_t)(c->previous-base)<0)base=c->previous;
    const int32_t late=(int32_t)(offset-base);
    return late>0 && late<=1000000 && (uint64_t)late<=host_us ?
        host_us-(uint32_t)late : host_us;
}
#endif
