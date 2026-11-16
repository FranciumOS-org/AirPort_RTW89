/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The seam between the two kexts of the native Wi-Fi driver.
 *
 * The front (AirPortRTW89Front) is the IO80211Controller macOS sees. It links
 * against IO80211FamilyLegacy, which OpenCore injects, so it has to be
 * injected as well and only changes with a restart. It knows nothing about
 * the chip and decides nothing: every request is passed to the back.
 *
 * The back is the rtw89 driver proper, loaded and unloaded at run time like
 * any kext. It finds the front in the registry by class name (no link
 * dependency) and hands over a table of functions through
 * callPlatformFunction(); the front answers with its own table. Both tables
 * are plain C, so the back needs the IO80211 headers only for the request
 * structures.
 *
 * Calls into the back are made under a lock that disconnecting takes for
 * writing: once RTW89_FRONT_DISCONNECT returns, no call is in progress and
 * none will follow. Calls into the front are valid from connect until
 * disconnect returns.
 */
#ifndef RTW89_FRONT_API_H
#define RTW89_FRONT_API_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/kernel_types.h>   /* mbuf_t */

#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
#include "owly_abi6_packet.h"
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
#include "owly_native_link.h"
#endif
#endif
/* 10: RTLAirLink's native AWDL bridge on top of 9 (the front's log line). */
#define RTW89_FRONT_API_VERSION 10
#define RTW89_FRONT_CLASS       "AirPortRTW89Front"
/* callPlatformFunction(name, true, back ops, front ops out, 0, 0) */
#define RTW89_FRONT_CONNECT     "RTW89FrontConnect"
#define RTW89_FRONT_DISCONNECT  "RTW89FrontDisconnect"


/* OWLY_NATIVE_IDENTITY_BRIDGE_BEGIN
 * AirLink (role 6 on the observed Tahoe IO80211Legacy path) is not a
 * promise of native AWDL support. VIF pointers are identity tokens only.
 * No data packet and no ownership of a VIF is transferred by this callback.
 */
#define RTW89_FRONT_ROLE_AIRLINK_OBSERVED 6u
#define RTW89_FRONT_VIF_CREATED  1u
#define RTW89_FRONT_VIF_ENABLED  2u
#define RTW89_FRONT_VIF_DISABLED 3u
#define RTW89_FRONT_VIF_DESTROYED 4u
/* A read-only query through the existing private callback, NOT a transition.
 * Old backends reject the unknown event. No table size or API version changes.
 * Requires the exact already-ACKed cookie and no request MAC payload. */
#define RTW89_FRONT_VIF_SERVICE_READY 5u
/* OWLY_NATIVE_IDENTITY_BRIDGE_END */
/* Identity tracking only: no packet ownership or Apple object dereference. */
/* OWLY ABI4: identity tokens only; neither side owns the Apple object.
 * The caller must serialize transitions (see _owlyVifLock in the frontend).
 * Do not infer AWDL TX/RX capability from enabled=true.
 */
struct rtw89_front_native_vif_state {
    void *cookie;
    uint32_t role;
    bool enabled;
};
static inline void rtw89_front_native_vif_reset(struct rtw89_front_native_vif_state *s)
{
    if (!s) return;
    s->cookie = NULL;
    s->role = 0;
    s->enabled = false;
}
static inline bool rtw89_front_native_vif_update(struct rtw89_front_native_vif_state *s,
                                                 void *cookie, uint32_t role, uint32_t event)
{
    if (!s || !cookie || role != RTW89_FRONT_ROLE_AIRLINK_OBSERVED)
        return false;
    switch (event) {
    case RTW89_FRONT_VIF_CREATED:
        /* Same identity is idempotent: never demote an enabled interface.
         * Another identity cannot replace a live interface. */
        if (s->cookie == cookie && s->role == role) return true;
        if (s->cookie) return false; /* no replacement before DESTROYED */
        s->cookie = cookie;
        s->role = role;
        s->enabled = false;
        return true;
    case RTW89_FRONT_VIF_ENABLED:
        if (s->cookie != cookie || s->role != role) return false;
        s->enabled = true;
        return true;
    case RTW89_FRONT_VIF_DISABLED:
        if (s->cookie != cookie || s->role != role) return false;
        s->enabled = false;
        return true;
    case RTW89_FRONT_VIF_DESTROYED:
        /* A live interface may not be forgotten before it is disabled. */
        if (s->cookie != cookie || s->role != role || s->enabled) return false;
        rtw89_front_native_vif_reset(s);
        return true;
    default:
        return false;
    }
}
/* No Skywalk dequeue/RX support exists: fail closed regardless of VIF state. */
static inline bool rtw89_front_native_awdl_tx_ready(const struct rtw89_front_native_vif_state *s)
{
    (void)s;
    return false;
}

#ifdef __cplusplus
extern "C" {
#endif

/* What the front does for the back. @ctx is the first argument of each. */
struct rtw89_front_ops {
    uint32_t version;
    void *ctx;
    void *interface;        /* the IO80211Interface, for requests that name it */

    /* interface->postMessage(): tell IO80211 that something happened */
    void (*post_message)(void *ctx, unsigned int msg, void *data, size_t len);
    /* Link state towards the network stack and IO80211. @reason: the 802.11
     * reason code when it goes down. */
    void (*set_link)(void *ctx, bool up, uint64_t bits_per_second, unsigned int reason);
    /* A packet buffer of the controller's, and handing a received Ethernet
     * frame to the stack (takes the mbuf). */
    mbuf_t (*alloc_packet)(void *ctx, unsigned int len);
    void (*input_packet)(void *ctx, mbuf_t m);
    /* The back has room again after output() returned a stall. */
    void (*tx_wake)(void *ctx);
    /* The family's own handling of a request the back does not want. */
    int (*super_ioctl)(void *ctx, void *interface, void *virtual_interface, void *ifnet,
                       unsigned long cmd, void *data);
    int (*super_ioctl_set)(void *ctx, void *interface, void *virtual_interface,
                           void *skywalk_interface, void *data);
    /* Who does the key handshake of the next join: IO80211's own supplicant
     * (true; networks with 802.1X sign-in) or the driver (false). With true,
     * received EAPOL frames are handed to IO80211 and the keys come back as
     * APPLE80211_IOC_CIPHER_KEY requests. */
    void (*set_apple_rsn)(void *ctx, bool on);
#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
    /* Synchronous borrowed pointer to an already owned packet. Return true
     * ONLY after a real Apple native P2P consumer has consumed it. */
    bool (*owly_rx_handoff)(void *ctx, const struct owly_abi6_packet *pkt);
#endif
};

/* What the back does for the front. */
struct rtw89_back_ops {
    uint32_t version;
    void *ctx;

    void (*get_mac)(void *ctx, uint8_t mac[6]);
    int (*set_mac)(void *ctx, const uint8_t mac[6]);
    /* IO80211Controller::apple80211Request(): one get or set of one item */
    int (*request)(void *ctx, unsigned int type, int number, void *interface, void *data);
    /* The two ioctl entry points above it. *@handled false: the front goes on
     * to the family's handling. */
    int (*ioctl)(void *ctx, void *interface, void *virtual_interface, void *ifnet,
                 unsigned long cmd, void *data, bool *handled);
    int (*ioctl_set)(void *ctx, void *interface, void *virtual_interface,
                     void *skywalk_interface, void *data, bool *handled);
    /* The interface is brought up or taken down by the stack. */
    int (*enable)(void *ctx, bool on);
    /* An Ethernet frame to send. Returns an IOOutputQueue status
     * (kIOReturnOutputSuccess, ...Stall, ...Dropped); the mbuf is the back's
     * unless it stalls. */
    uint32_t (*output)(void *ctx, mbuf_t m);
    /* The system goes to sleep (false) or has woken (true). */
    void (*power)(void *ctx, bool on);
    /*
     * One already-formatted line for the driver's log ring, the one
     * `rtw89ctl log` reads.
     *
     * The front's own IOLog goes nowhere. Loaded from the EFI it does not
     * reach the unified log, and the kernel message buffer is too small to
     * hold it -- an hour of running produced not one front line anywhere,
     * the one written at probe included. That is why the driver has a ring
     * at all (src/kext/rtw89_logring.cpp); the front borrows it, so that
     * both halves of one event can be read in one place and in order.
     */
    void (*log)(void *ctx, const char *line);
    /* OWLY_NATIVE_IDENTITY_BRIDGE_BEGIN: ABI v4: acknowledged AirLink VIF lifecycle. */
    bool (*vif_event)(void *ctx, void *vif_identity, uint32_t role, uint32_t event,
                      const uint8_t request_mac[6]); /* non-NULL only for CREATED */
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    uint32_t (*native_output)(void *ctx,mbuf_t m);
    int (*native_window)(void *ctx,struct owly_link_window *window);
#endif
    /* OWLY_NATIVE_IDENTITY_BRIDGE_END */
};

#ifdef __cplusplus
}
#endif
#endif
