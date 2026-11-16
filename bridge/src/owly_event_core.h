/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OWLY_EVENT_CORE_H
#define OWLY_EVENT_CORE_H

#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Pinned IO80211 A7096833-3C8D-3E48-8B79-E7492EF7A804, x86_64.
 * This is Apple's observed two-mapping event ring, NOT IODataQueueMemory.
 * Memory type 1: bytes. Memory type 2: consumer head at +0, producer tail +4.
 */
enum {
    OWLY_EVENT_HEADER_SIZE = 48,
    OWLY_EVENT_MAX_PAYLOAD = 4096,
    OWLY_EVENT_RING_MIN = 64,
    OWLY_EVENT_RING_MAX = 1024 * 1024,
    OWLY_EVENT_MAGIC = 0x57,
    OWLY_EVENT_PAD_MAGIC = 0x50,
    OWLY_IOUC_SANITY_INPUT_SIZE = 0x3c30,
    OWLY_IOUC_SANITY_REQUEST_OFFSET = 0x3c08,
    OWLY_IOUC_SANITY_OUTPUT_SIZE = 0x180
};

enum owly_event_result {
    OWLY_EVENT_OK = 0,
    OWLY_EVENT_BAD_ARGUMENT,
    OWLY_EVENT_NOT_READY,
    OWLY_EVENT_FULL,
    OWLY_EVENT_CORRUPT,
    OWLY_EVENT_BUSY,
    OWLY_EVENT_UNSUPPORTED
};

struct owly_event_control {
    uint32_t head;
    uint32_t tail;
};

struct owly_event_stats {
    uint64_t enqueued;
    uint64_t full;
    uint64_t rejected;
    uint64_t corrupt;
};

/* Caller serializes producers and lifecycle; head/tail synchronize with the
 * user-space consumer through acquire/release atomics. No allocation or wait.
 */
struct owly_event_core {
    uint8_t *bytes;
    struct owly_event_control *control;
    uint32_t capacity;
    uint32_t trusted_tail;
    char interface_name[16];
    uint8_t started;
    uint8_t registered;
    uint8_t closed;
    uint8_t faulted;
    struct owly_event_stats stats;
};

enum owly_event_result owly_event_init(struct owly_event_core *, void *, uint32_t,
                                      struct owly_event_control *, const char *);
enum owly_event_result owly_event_start(struct owly_event_core *);
enum owly_event_result owly_event_register(struct owly_event_core *);
void owly_event_halt(struct owly_event_core *);
void owly_event_close(struct owly_event_core *);
enum owly_event_result owly_event_push(struct owly_event_core *, uint32_t,
                                      const void *, size_t);

/* 1/7 deliberately report no IOUC ioctl transport / extended ioctl format.
 * Existing BSD ioctl routing remains the control path. Selector 5 reports
 * event support only when the real kernel producer hook is installed.
 */
enum owly_event_result owly_event_query(uint32_t selector, int producer_ready,
                                       uint8_t *answer);

typedef int (*owly_event_read_input)(void *, size_t, void *, size_t);
enum owly_event_result owly_event_sanity(owly_event_read_input, void *, size_t,
                                        const char *, void *, size_t *);

#ifdef __cplusplus
}
#endif
#endif
