/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OWLY_STATUS_HPP
#define OWLY_STATUS_HPP
#include <stdint.h>
class IORegistryEntry;
namespace OwlyStatus {
/* Bounded static journal; recorders allocate nothing and never call IOKit.
 * Text values must remain valid for the lifetime of the module (literals).
 * No recorders are called from the event-ring spin lock/ISR. */
void text(const char *key, const char *value);
void number(const char *key, uint64_t value);
void flag(const char *key, bool value);
/* Only the IOKit service start/timer/stop path may publish the journal. */
void flush(IORegistryEntry *target);
}
#endif
