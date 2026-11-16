/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_ABI6_RX_GATE_H
#define OWLY_ABI6_RX_GATE_H
#include <stdbool.h>
#include <stdint.h>
/*
 * This POD has no internal synchronization. EVERY operation must be done
 * under the same owner lock (IOLock in kext; pthread_mutex in host tests).
 * It guards callback admission / drain, NOT the lifetime of a callback
 * function's owner beyond the owning driver and glue removal barrier.
 */
struct owly_abi6_rx_gate {
    uint32_t in_flight;
    bool closing;
};
static inline void owly_abi6_gate_init(struct owly_abi6_rx_gate *s)
{
    s->in_flight = 0;
    s->closing = true;
}
static inline bool owly_abi6_gate_open(struct owly_abi6_rx_gate *s)
{
    if (s->in_flight != 0) return false;
    s->closing = false;
    return true;
}
static inline bool owly_abi6_gate_enter(struct owly_abi6_rx_gate *s)
{
    if (s->closing || s->in_flight == UINT32_MAX) return false;
    s->in_flight++;
    return true;
}
static inline bool owly_abi6_gate_leave(struct owly_abi6_rx_gate *s)
{
    if (!s->in_flight) return false;
    s->in_flight--;
    return true;
}
static inline void owly_abi6_gate_close(struct owly_abi6_rx_gate *s)
{
    s->closing = true;
}
static inline bool owly_abi6_gate_drained(const struct owly_abi6_rx_gate *s)
{
    return s->closing && s->in_flight == 0;
}
#endif
