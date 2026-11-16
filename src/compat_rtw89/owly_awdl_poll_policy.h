/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_AWDL_POLL_POLICY_H
#define OWLY_AWDL_POLL_POLICY_H
#include <stdbool.h>
#include <stdint.h>
/* Data and directed MI keep the existing 1 ms service interval. An empty
 * transmitter sleeps toward the next real action deadline, capped at one AW.
 * A newly queued native frame must reschedule the worker immediately. */
static inline uint32_t owly_awdl_poll_delay_us(uint64_t now,uint64_t psf,uint64_t mif,
                                               bool queued,bool directed,bool held,uint16_t next_aw_tu)
{
    if(queued || directed)return 1000;
    /* A due broadcast waiting for the peer's channel must not turn an idle
     * radio into a permanent 1 kHz poll. Recheck at its next AW boundary. */
    if(held && next_aw_tu) {
        const uint32_t boundary=(uint32_t)next_aw_tu*1024u;
        return boundary<1000 ? 1000 : boundary>16384 ? 16384 : boundary;
    }
    uint64_t due=psf;
    if(!due || (mif && mif<due))due=mif;
    if(due && due<=now)return 1000;
    const uint64_t delay=due ? due-now : 16384;
    return delay<1000 ? 1000 : delay>16384 ? 16384 : (uint32_t)delay;
}
#endif
