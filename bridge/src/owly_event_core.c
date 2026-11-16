/* SPDX-License-Identifier: GPL-2.0-only */
#include "owly_event_core.h"

static void zero_bytes(void *dst, size_t n)
{
    uint8_t *p = (uint8_t *)dst;
    while (n--) *p++ = 0;
}

static void copy_bytes(void *dst, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int valid_name(const char *name, size_t *length)
{
    size_t n;
    if (!name) return 0;
    for (n = 0; n < 16; n++) {
        const uint8_t c = (uint8_t)name[n];
        if (!c) { *length = n; return n != 0; }
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_')) return 0;
    }
    return 0;
}

enum owly_event_result owly_event_init(struct owly_event_core *c, void *bytes,
    uint32_t capacity, struct owly_event_control *control, const char *name)
{
    size_t n;
    if (!c || !bytes || !control || ((uintptr_t)bytes & 3) ||
        ((uintptr_t)control & 3) || capacity < OWLY_EVENT_RING_MIN ||
        capacity > OWLY_EVENT_RING_MAX || (capacity & 3) ||
        !valid_name(name, &n)) return OWLY_EVENT_BAD_ARGUMENT;
    zero_bytes(c, sizeof(*c));
    c->bytes = (uint8_t *)bytes;
    c->control = control;
    c->capacity = capacity;
    copy_bytes(c->interface_name, name, n);
    zero_bytes(bytes, capacity);
    __atomic_store_n(&control->head, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&control->tail, 0, __ATOMIC_RELEASE);
    return OWLY_EVENT_OK;
}

enum owly_event_result owly_event_start(struct owly_event_core *c)
{
    if (!c || !c->bytes || !c->control) return OWLY_EVENT_BAD_ARGUMENT;
    if (c->closed || c->faulted) return OWLY_EVENT_NOT_READY;
    if (c->started) return OWLY_EVENT_BUSY;
    c->trusted_tail = 0;
    zero_bytes(c->bytes, c->capacity);
    __atomic_store_n(&c->control->head, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&c->control->tail, 0, __ATOMIC_RELEASE);
    c->registered = 0;
    c->started = 1;
    return OWLY_EVENT_OK;
}

enum owly_event_result owly_event_register(struct owly_event_core *c)
{
    if (!c || !c->started || c->closed || c->faulted)
        return OWLY_EVENT_NOT_READY;
    c->registered = 1;
    return OWLY_EVENT_OK;
}

void owly_event_halt(struct owly_event_core *c)
{
    if (c) { c->registered = 0; c->started = 0; }
}

void owly_event_close(struct owly_event_core *c)
{
    if (c) { owly_event_halt(c); c->closed = 1; }
}

static void ring_copy(struct owly_event_core *c, uint32_t *offset,
                      const uint8_t *source, size_t length)
{
    size_t first = c->capacity - *offset;
    if (first > length) first = length;
    if (first) copy_bytes(c->bytes + *offset, source, first);
    if (length > first) copy_bytes(c->bytes, source + first, length - first);
    *offset = (uint32_t)((*offset + length) % c->capacity);
}

enum owly_event_result owly_event_push(struct owly_event_core *c,
    uint32_t event, const void *payload, size_t length)
{
    uint32_t head, tail, used, free_space, remaining, prefix, total, next;
    uint16_t padding;
    uint8_t header[OWLY_EVENT_HEADER_SIZE], zeros[3] = {0, 0, 0};
    if (!c || !c->bytes || !c->control) return OWLY_EVENT_BAD_ARGUMENT;
    if (!c->started || !c->registered || c->closed || c->faulted)
        return OWLY_EVENT_NOT_READY;
    if (length > OWLY_EVENT_MAX_PAYLOAD || (length && !payload)) {
        c->stats.rejected++;
        return OWLY_EVENT_BAD_ARGUMENT;
    }
    head = __atomic_load_n(&c->control->head, __ATOMIC_ACQUIRE);
    tail = c->trusted_tail;
    if (head >= c->capacity || (head & 3) || tail >= c->capacity ||
        __atomic_load_n(&c->control->tail, __ATOMIC_ACQUIRE) != tail) {
        c->faulted = 1;
        c->registered = 0;
        c->stats.corrupt++;
        return OWLY_EVENT_CORRUPT;
    }
    used = tail >= head ? tail - head : c->capacity - head + tail;
    free_space = c->capacity - used - 4; /* never alias full and empty */
    remaining = c->capacity - tail;
    prefix = remaining < OWLY_EVENT_HEADER_SIZE ? remaining : 0;
    padding = (uint16_t)((4 - (length & 3)) & 3);
    total = OWLY_EVENT_HEADER_SIZE + (uint32_t)length + padding;
    if (total > free_space || prefix > free_space - total) {
        c->stats.full++;
        return OWLY_EVENT_FULL; /* no writes, no published partial event */
    }
    next = tail;
    if (prefix) {
        while (next < c->capacity) {
            put32(c->bytes + next, OWLY_EVENT_PAD_MAGIC);
            next += 4;
        }
        next = 0;
    }
    zero_bytes(header, sizeof(header));
    put32(header, OWLY_EVENT_MAGIC);
    put16(header + 24, (uint16_t)length);
    put16(header + 26, padding);
    put32(header + 28, event);
    copy_bytes(header + 32, c->interface_name, 16);
    ring_copy(c, &next, header, sizeof(header));
    if (length) ring_copy(c, &next, (const uint8_t *)payload, length);
    if (padding) ring_copy(c, &next, zeros, padding);
    c->trusted_tail = next;
    __atomic_store_n(&c->control->tail, next, __ATOMIC_RELEASE);
    c->stats.enqueued++;
    return OWLY_EVENT_OK;
}

enum owly_event_result owly_event_query(uint32_t selector, int ready,
                                       uint8_t *answer)
{
    if (!answer) return OWLY_EVENT_BAD_ARGUMENT;
    switch (selector) {
        case 1: case 7: *answer = 0; return OWLY_EVENT_OK;
        case 5: *answer = ready != 0; return OWLY_EVENT_OK;
        default: return OWLY_EVENT_UNSUPPORTED;
    }
}

enum owly_event_result owly_event_sanity(owly_event_read_input read, void *cookie,
    size_t input_size, const char *name, void *output, size_t *output_size)
{
    uint8_t command[4], number[4], interface_name[16], expected[16];
    static const char version[] = "Owly AirLink EventBridge EB1 / event-only IOUC";
    size_t n, i;
    if (!read || !output || !output_size || !valid_name(name, &n) ||
        input_size != OWLY_IOUC_SANITY_INPUT_SIZE ||
        *output_size < OWLY_IOUC_SANITY_OUTPUT_SIZE)
        return OWLY_EVENT_BAD_ARGUMENT;
    if (!read(cookie, 0, command, 4) ||
        !read(cookie, OWLY_IOUC_SANITY_REQUEST_OFFSET, interface_name, 16) ||
        !read(cookie, OWLY_IOUC_SANITY_REQUEST_OFFSET + 16, number, 4))
        return OWLY_EVENT_BAD_ARGUMENT;
    zero_bytes(expected, sizeof(expected));
    copy_bytes(expected, name, n);
    for (i = 0; i < 16; i++)
        if (interface_name[i] != expected[i]) return OWLY_EVENT_BAD_ARGUMENT;
    if (get32(command) != UINT32_C(0xc02869c9) || get32(number) != 43)
        return OWLY_EVENT_UNSUPPORTED;
    zero_bytes(output, OWLY_IOUC_SANITY_OUTPUT_SIZE);
    copy_bytes(output, version, sizeof(version));
    *output_size = OWLY_IOUC_SANITY_OUTPUT_SIZE;
    return OWLY_EVENT_OK;
}
