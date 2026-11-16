/* SPDX-License-Identifier: GPL-2.0 */
/* Borrowed primary-channel lease for an on-demand auxiliary VIF.
 * The caller serializes ALL operations (including inspection) with wiphy.
 * No allocation, channel selection, packet TX, or pointer ownership here.
 * assign() MUST roll back software state on failure. Hardware recovery is
 * not assumed: a failed assign blocks further attempts until radio reset.
 */
#ifndef OWLY_AWDL_RADIO_LIFECYCLE_H
#define OWLY_AWDL_RADIO_LIFECYCLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum owly_radio_result {
    OWLY_RADIO_OK = 0,
    OWLY_RADIO_WAIT = 1,
    OWLY_RADIO_BLOCKED = 2,
    OWLY_RADIO_BUSY = 3,
    OWLY_RADIO_INVALID = 4
};

struct owly_radio_lease {
    void *vif;
    void *channel;
    bool blocked;
    bool transitioning;
    int last_error;
    uint32_t attempts;
    uint32_t binds;
    uint32_t releases;
};

struct owly_radio_ops {
    int (*assign)(void *opaque, void *vif, void *channel);
    void (*unassign)(void *opaque, void *vif, void *channel);
};

static inline bool owly_radio_is_bound(const struct owly_radio_lease *s)
{
    return s && s->vif && s->channel && !s->transitioning;
}

static inline enum owly_radio_result
owly_radio_bind(struct owly_radio_lease *s, void *vif, void *channel,
                bool ready, const struct owly_radio_ops *ops, void *opaque)
{
    int rc;
    if (!s || !vif || !ops || !ops->assign || !ops->unassign)
        return OWLY_RADIO_INVALID;
    if (s->transitioning)
        return OWLY_RADIO_BUSY;
    if (s->vif || s->channel) {
        if (s->vif == vif && s->channel == channel)
            return OWLY_RADIO_OK; /* duplicate create/notification: no driver call */
        return OWLY_RADIO_BUSY;   /* never silently replace a borrowed context */
    }
    if (s->blocked)
        return OWLY_RADIO_BLOCKED;
    if (!ready || !channel)
        return OWLY_RADIO_WAIT;   /* pending is not a failed RF transaction */
    s->transitioning = true;
    s->attempts++;
    rc = ops->assign(opaque, vif, channel);
    if (rc) {
        s->last_error = rc;
        s->blocked = true;
        s->transitioning = false;
        return OWLY_RADIO_BLOCKED;
    }
    s->vif = vif;
    s->channel = channel;
    s->binds++;
    s->last_error = 0;
    s->transitioning = false;
    return OWLY_RADIO_OK;
}

/* expected_channel == NULL: release for VIF removal/radio shutdown.
 * Otherwise release only the exact primary context about to be freed.
 * The caller must finish this before remove_interface()/free(primary).
 */
static inline enum owly_radio_result
owly_radio_unbind(struct owly_radio_lease *s, void *expected_channel,
                  const struct owly_radio_ops *ops, void *opaque)
{
    if (!s || !ops || !ops->unassign)
        return OWLY_RADIO_INVALID;
    if (s->transitioning)
        return OWLY_RADIO_BUSY;
    if (!s->vif && !s->channel)
        return OWLY_RADIO_OK;
    if (!s->vif || !s->channel)
        return OWLY_RADIO_INVALID;
    if (expected_channel && expected_channel != s->channel)
        return OWLY_RADIO_INVALID;
    s->transitioning = true;
    ops->unassign(opaque, s->vif, s->channel);
    s->vif = NULL;
    s->channel = NULL;
    s->releases++;
    s->transitioning = false;
    return OWLY_RADIO_OK;
}

/* A reset is valid only after complete unassignment, never as cleanup for
 * a live reference. In production this is called at a new radio-up. */
static inline enum owly_radio_result
owly_radio_reset(struct owly_radio_lease *s)
{
    if (!s)
        return OWLY_RADIO_INVALID;
    if (s->transitioning || s->vif || s->channel)
        return OWLY_RADIO_BUSY;
    s->blocked = false;
    s->last_error = 0;
    s->attempts = s->binds = s->releases = 0;
    return OWLY_RADIO_OK;
}

#endif
