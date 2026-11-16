// SPDX-License-Identifier: GPL-2.0
/* Gate14 RC3: default fail-closed. Native VIF must be explicitly armed via
 * both Makefile switches. Set these before the class header is parsed. */
#ifndef OWLY_GATE14_REAL_VIF
#define OWLY_GATE14_REAL_VIF 0
#endif
#ifndef RTW89_AWDL_NATIVE_FRONT_OBSERVE
#define RTW89_AWDL_NATIVE_FRONT_OBSERVE 0
#endif
#if OWLY_GATE14_REAL_VIF && RTW89_AWDL_NATIVE_FRONT_OBSERVE != 1
#error "Gate14 RC3: real VIF requires native lifecycle build enabled"
#endif
#ifndef OWLY_ABI6_NATIVE_P2P_FACTORY
#define OWLY_ABI6_NATIVE_P2P_FACTORY 0
#endif
#if OWLY_ABI6_NATIVE_P2P_FACTORY && !OWLY_GATE14_REAL_VIF
#error "ABI6 P2P subclass must only run with Gate14 armed"
#endif
#include "AirPortRTW89Front.hpp"
#if defined(OWLY_AWDL_SERVICE_LIFECYCLE) && OWLY_AWDL_SERVICE_LIFECYCLE
#include "../kext/OwlyAwdlEntitlement.hpp"
#include <mach/task.h>
#endif
#include "owly_gatec_l2.h"
#include "owly_native_config.h"
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
#include "OwlyLegacyP2PABI.hpp"
#else
#include <IOKit/80211/IO80211P2PInterface.h>
#endif
#include "../kext/rtw89_chips.h"

#include <IOKit/80211/apple80211_var.h>

#include <IOKit/IOCommandGate.h>
#include <IOKit/IOLib.h>
#include <libkern/version.h>
#include <IOKit/network/IOBasicOutputQueue.h>
#include <IOKit/network/IONetworkMedium.h>
#include <sys/errno.h>
#include <sys/kpi_mbuf.h>
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
#include "rtw89_awdl_action_decode.h"
#endif

/*
 * Every front line goes to the driver's log ring, because the front's own
 * IOLog reaches nothing: not the unified log, not dmesg for longer than a
 * few seconds. Before the driver connects there is nowhere to put a line but
 * IOLog, so that is still the fallback, and those early lines are the ones
 * that may well be lost.
 */
#define LOG(fmt, ...) rtw89FrontLog("AirPortRTW89Front: " fmt, ##__VA_ARGS__)
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
#include "OwlyNativeP2P.inc"
#endif

#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
#include "owly_gatec2_inspect.h"
#if defined(OWLY_ABI6_C3_SCAN_OBSERVER) && OWLY_ABI6_C3_SCAN_OBSERVER
#include "owly_gatec3_scan_signature.h"
static volatile SInt32 gOwlyC3ScanSignaturesFront = 0;
static volatile SInt32 gOwlyC3ScanRejectedFront = 0;
#endif
/* We count packets reaching FRONT after the real backend RX demux, NOT
 * packets injected into Apple's AWDL peer manager. Bounded publication. */
static volatile SInt32 gOwlyC2Actions = 0;
static volatile SInt32 gOwlyC2L2IPv6 = 0;
static volatile SInt32 gOwlyC2Rejected = 0;
static volatile SInt32 gOwlyC2NotReady = 0;
static void owlyGateC2Note(IORegistryEntry *front, const char *key, volatile SInt32 *counter)
{
    const SInt32 prev = OSIncrementAtomic(counter);
    if (prev < 0) return; /* never publish an overflowed count */
    const UInt32 value = (UInt32)prev + 1U;
    if (value <= 16U || (value <= 65536U && (value & (value - 1U)) == 0U))
        front->setProperty(key, (unsigned long long)value, 32);
}
#endif

/* OWLY_GATE09_BEGIN: bounded, error-only telemetry; no VIF or packet changes. */
static volatile SInt32 gOwlyG09IoctlErrors = 0;
static volatile SInt32 gOwlyG09SetErrors = 0;
static volatile SInt32 gOwlyG09SuperErrors = 0;
static volatile SInt32 gOwlyG09Request94 = 0;
/* OWLY_GATE09_END */

/* OWLY_GATE12_TRACE_BEGIN: fail-closed diagnostic; no request payload reads. */
#define OWLY_GATE12_TRACE_ONLY 1
/* GATE14: The functional role-6 path is DISABLED by default. Do not arm
 * without the measured Gate13C request version and a sacrificial USB EFI.
 * The old M2.3 copyin/copyout envelope is NEVER invoked by this gate.
 */
/* OWLY_GATE14_REAL_VIF is opt-in via compiler; default is 0. */
#ifndef OWLY_GATE14_REQ94_VERSION
#define OWLY_GATE14_REQ94_VERSION 0U
#endif
#if OWLY_GATE14_REAL_VIF
#ifndef RTW89_AWDL_NATIVE_FRONT_OBSERVE
#define RTW89_AWDL_NATIVE_FRONT_OBSERVE 1
#endif
#if !RTW89_AWDL_NATIVE_FRONT_OBSERVE
#error "Gate14 requires backend/native lifecycle integration"
#endif
#if OWLY_GATE14_REQ94_VERSION == 0xFFFFFFFFU
#error "Gate14 refuses an unverified 94 version; supply observed Gate13C value"
#endif
#endif
static volatile SInt32 gOwlyG12Ioctl = 0;
static volatile SInt32 gOwlyG12Set = 0;
static volatile SInt32 gOwlyG12Request = 0;
static volatile SInt32 gOwlyG12VifFactory = 0;
/* OWLY_GATE12_TRACE_END */

/* OWLY_GATE12F_MATRIX_BEGIN: passive legacy dispatch counters.
 * Never dereference IOCTL buffers, alter results, create VIFs or change ABI.
 * The low-frequency publication is bounded: first 24 hits, then each 64th
 * to 4096 and each 1024th to 65536. Values after 24 are checkpoints,
 * NOT guaranteed exact totals. Run a before/after session for correlation.
 */
static volatile SInt32 gOwlyFIOCTLAny = 0;
static volatile SInt32 gOwlyFIOCTLSetCmd = 0;
static volatile SInt32 gOwlyFIOCTLSetCallback = 0;
static volatile SInt32 gOwlyFSuperIOCTL = 0;
static volatile SInt32 gOwlyFSuperSet = 0;
static volatile SInt32 gOwlyFBackendIOCTL = 0;
static volatile SInt32 gOwlyFBackendSet = 0;
static volatile SInt32 gOwlyFFallbackIOCTL = 0;
static volatile SInt32 gOwlyFFallbackSet = 0;
static volatile SInt32 gOwlyFRequestAny = 0;
static volatile SInt32 gOwlyFRequest94 = 0;
static volatile SInt32 gOwlyFRequest95 = 0;
static volatile SInt32 gOwlyFRole6 = 0;
/* ABI5 factory/attach telemetry: bounded counters; no VIF behaviour changes.
 * Four outcome categories below are mutually exclusive for each role-6 call.
 * The last outcome is advisory only if another role-6 call races it.
 * Allocation/init outcome is never inferred from an Apple attach failure.
 */
static volatile SInt32 gOwlyDiagFNoMac = 0;
static volatile SInt32 gOwlyDiagFAllocFail = 0;
static volatile SInt32 gOwlyDiagFInitFail = 0;
static volatile SInt32 gOwlyDiagFReady = 0;
static inline void owlyGate12FHit(IORegistryEntry *entry, const char *key,
                                 volatile SInt32 *counter)
{
    const SInt32 old = OSIncrementAtomic(counter);
    if (old < 0) return; /* overflow guard; do not publish a wrapped count */
    const UInt32 value = (UInt32)old + 1U;
    if (value <= 24U ||
        (value <= 4096U && (value % 64U) == 0U) ||
        (value <= 65536U && (value % 1024U) == 0U))
        entry->setProperty(key, (unsigned long long)value, 32);
}
/* OWLY_GATE12F_MATRIX_END */

/* OWLY_GATE13A_SHAPE_BEGIN: metadata-only, never dereference IOCTL94 data.
 * These compile-time assertions verify the PROJECT'S 32-byte layout only.
 * They do NOT prove the Apple dispatcher uses this layout or that its
 * data pointer refers to a readable kernel-resident object.
 */
struct OwlyGate13AExpectedCreateLayout {
    uint32_t version;
    uint8_t mac[6];
    uint16_t reserved;
    uint32_t role;
    uint8_t bsd_name[16];
} __attribute__((packed));
static_assert(sizeof(OwlyGate13AExpectedCreateLayout) == 32, "Gate13A local create layout must be 32 bytes");
static_assert(__builtin_offsetof(OwlyGate13AExpectedCreateLayout, version) == 0, "version offset");
static_assert(__builtin_offsetof(OwlyGate13AExpectedCreateLayout, mac) == 4, "mac offset");
static_assert(__builtin_offsetof(OwlyGate13AExpectedCreateLayout, reserved) == 10, "reserved offset");
static_assert(__builtin_offsetof(OwlyGate13AExpectedCreateLayout, role) == 12, "role offset");
static_assert(__builtin_offsetof(OwlyGate13AExpectedCreateLayout, bsd_name) == 16, "bsd_name offset");
static volatile SInt32 gOwly13A94Seen = 0;
static volatile SInt32 gOwly13A94TypeSet = 0;
static volatile SInt32 gOwly13A94TypeOther = 0;
static volatile SInt32 gOwly13A94Primary = 0;
static volatile SInt32 gOwly13A94NotPrimary = 0;
static volatile SInt32 gOwly13A94DataNonNull = 0;
static volatile SInt32 gOwly13A94DataNull = 0;
static volatile SInt32 gOwly13A94DataAligned8 = 0;
static volatile SInt32 gOwly13A94DataUnaligned8 = 0;
/* OWLY_GATE13A_SHAPE_END */

/* OWLY_GATE13B_PAYLOAD_BEGIN: experimental read-only request94 probe.
 * REQUIRES pinned IO80211FamilyLegacy image + loaded UUID verification before
 * USB-only installation. The matched Apple setVirtualInterfaceCreate function
 * calls IO80211Controller::copyIn into its own 32-byte stack local and
 * passes &local to apple80211RequestIoctl(0x803069c8, 94, primary, &local).
 * This is NOT a universal contract for arbitrary direct callback callers.
 * This probe reads ONLY 4 bytes of version and 4 bytes of role, not MAC/name.
 * No userspace copyin, IORegistry pointer, VIF attach, or return-code change.
 */
#define OWLY_GATE13B_PAYLOAD_PROBE 1
static volatile SInt32 gOwly13B94_eligible = 0;
static volatile SInt32 gOwly13B94_version_expected = 0;
static volatile SInt32 gOwly13B94_version_other = 0;
static volatile SInt32 gOwly13B94_role6 = 0;
static volatile SInt32 gOwly13B94_role_other = 0;
static volatile SInt32 gOwly13B94_combo_expected = 0;
/* OWLY_GATE13B_PAYLOAD_END */


/* Until the driver proper has read the real address from the chip. */
static const IOEthernetAddress kPlaceholderMac = {{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 }};

enum { kPowerStateOff = 0, kPowerStateOn = 1, kPowerStateCount = 2 };
static IOPMPowerState gPowerStates[kPowerStateCount] = {
    { kIOPMPowerStateVersion1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { kIOPMPowerStateVersion1, kIOPMDeviceUsable, kIOPMPowerOn, kIOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0 },
};

/* ------------------------------------------------------------------ */
/*  The interface                                                       */
/* ------------------------------------------------------------------ */

OSDefineMetaClassAndStructors(AirPortRTW89FrontInterface, IO80211Interface)

/* One card, one front: set through rtw89_front_ops.set_apple_rsn(). */
static volatile bool gAppleRsn;

/* The front whose back takes the log lines; see LOG above. */
static AirPortRTW89Front *gLogFront;

static void rtw89FrontLog(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void rtw89FrontLog(const char *fmt, ...)
{
    AirPortRTW89Front *front = gLogFront;
    char line[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    if (front && front->logLine(line))
        return;
    IOLog("%s\n", line);
}

UInt32 AirPortRTW89FrontInterface::inputPacket(mbuf_t packet, UInt32 length, IOOptionBits options,
                                               void *param)
{
    if (gAppleRsn && packet && mbuf_len(packet) >= 14) {
        const uint8_t *eth = static_cast<const uint8_t *>(mbuf_data(packet));

        /* EAPOL: for the supplicant inside IO80211, as AirportItlwm does */
        if (eth[12] == 0x88 && eth[13] == 0x8e)
            return IO80211Interface::inputPacket(packet, (UInt32)mbuf_pkthdr_len(packet), 0, param);
    }
    return IOEthernetInterface::inputPacket(packet, length, options, param);
}

/* ------------------------------------------------------------------ */
/*  Start and stop                                                      */
/* ------------------------------------------------------------------ */

#define super IO80211Controller
OSDefineMetaClassAndStructors(AirPortRTW89Front, IO80211Controller)

/* IONetworkController::start() asks for this before our start() goes on. An
 * IO80211WorkLoop keeps the family's requests and our own calls on one loop. */
bool AirPortRTW89Front::createWorkLoop()
{
    if (!_workLoop)
        _workLoop = IO80211WorkLoop::workLoop();
    return _workLoop != nullptr;
}

IOWorkLoop *AirPortRTW89Front::getWorkLoop() const
{
    return _workLoop;
}

bool AirPortRTW89Front::start(IOService *provider)
{
    _pci = OSDynamicCast(IOPCIDevice, provider);
    if (!_pci)
        return false;
    _backLock = IOLockAlloc();
    if (!_backLock)
        return false;
    _owlyVifLock = IOLockAlloc();
    if (!_owlyVifLock) {
        IOLockFree(_backLock);
        _backLock = nullptr;
        return false;
    }
    _mac = kPlaceholderMac;

    if (!super::start(provider)) {
        LOG("IO80211Controller::start failed");
        return false;
    }
    _superStarted = true;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    if(!owlyNativeStart())return false;
#endif

    /* The network interface is attached when the driver proper connects for
     * the first time: only it can read the card's address. Until then this
     * is a controller without an interface, which the driver finds by class. */
    setProperty("RTW89 Front API", RTW89_FRONT_API_VERSION, 32);
    setProperty("RTW89 Back Connected", kOSBooleanFalse);
    setProperty("OWLY Gate09 Trace", "ABI4.1 diagnostic; no AWDL TX or RX");
    setProperty("OWLY Gate12 Trace", "trace-only; no IOCTL94/95 bridge; role6 factory refused");
    setProperty("OWLY Gate12F Trace", "legacy-entry-matrix; no IOCTL94/95 bridge; VIF disabled");
    setProperty("OWLY Gate12F ioctl_any", 0ULL, 32);
    setProperty("OWLY Gate12F ioctl_set_command", 0ULL, 32);
    setProperty("OWLY Gate12F ioctl_set_callback", 0ULL, 32);
    setProperty("OWLY Gate12F super_ioctl", 0ULL, 32);
    setProperty("OWLY Gate12F super_ioctl_set", 0ULL, 32);
    setProperty("OWLY Gate12F backend_ioctl", 0ULL, 32);
    setProperty("OWLY Gate12F backend_ioctl_set", 0ULL, 32);
    setProperty("OWLY Gate12F fallback_ioctl", 0ULL, 32);
    setProperty("OWLY Gate12F fallback_ioctl_set", 0ULL, 32);
    setProperty("OWLY Gate12F request_any", 0ULL, 32);
    setProperty("OWLY Gate12F request94", 0ULL, 32);
    setProperty("OWLY Gate12F request95", 0ULL, 32);
    setProperty("OWLY Gate12F role6_factory", 0ULL, 32);
    /* OWLY_GATE13A_PROPERTIES_BEGIN: no payload bytes, raw pointer or MAC stored. */
    setProperty("OWLY Gate13A Trace", "request94-shape-only; no data dereference; 94/95 fail-closed");
    setProperty("OWLY Gate13A local_layout_bytes", 32ULL, 32);
    setProperty("OWLY Gate13A 94_seen", 0ULL, 32);
    setProperty("OWLY Gate13A 94_type_set", 0ULL, 32);
    setProperty("OWLY Gate13A 94_type_other", 0ULL, 32);
    setProperty("OWLY Gate13A 94_primary", 0ULL, 32);
    setProperty("OWLY Gate13A 94_not_primary", 0ULL, 32);
    setProperty("OWLY Gate13A 94_data_nonnull", 0ULL, 32);
    setProperty("OWLY Gate13A 94_data_null", 0ULL, 32);
    setProperty("OWLY Gate13A 94_data_aligned8", 0ULL, 32);
    setProperty("OWLY Gate13A 94_data_unaligned8", 0ULL, 32);
    /* OWLY_GATE13A_PROPERTIES_END */
    /* OWLY_GATE13B_PROPERTIES_BEGIN: aggregate flags, no payload values. */
    setProperty("OWLY Gate13B Trace", "pinned-legacy-stack-payload; read-version-role-only; 94/95 fail-closed");
    setProperty("OWLY Gate13C Trace", "last-version-value-only; same Gate13B 8-byte read; 94/95 fail-closed");
    setProperty("OWLY Gate13B 94_eligible", 0ULL, 32);
    setProperty("OWLY Gate13B 94_version_expected", 0ULL, 32);
    setProperty("OWLY Gate13B 94_version_other", 0ULL, 32);
    setProperty("OWLY Gate13B 94_role6", 0ULL, 32);
    setProperty("OWLY Gate13B 94_role_other", 0ULL, 32);
    setProperty("OWLY Gate13B 94_combo_expected", 0ULL, 32);
    /* Gate13C: no value recorded yet (sentinel 0xFFFFFFFF). */
    setProperty("OWLY Gate13C 94_version_value", 0xFFFFFFFFULL, 32);
#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
    __atomic_store_n(&_owlyGateC2Ready, 0, __ATOMIC_RELEASE);
    setProperty("OWLY C2 native_vif_ready", 0ULL, 32);
    setProperty("OWLY C2 action_front", 0ULL, 32);
    setProperty("OWLY C2 ipv6_l2_front", 0ULL, 32);
    setProperty("OWLY C2 rejected", 0ULL, 32);
    setProperty("OWLY C2 not_ready", 0ULL, 32);
    setProperty("OWLY C2 apple_rx_delivered", 0ULL, 32);
#if defined(OWLY_ABI6_C3_SCAN_OBSERVER) && OWLY_ABI6_C3_SCAN_OBSERVER
    setProperty("OWLY C3 scan_signature_front", 0ULL, 32);
    setProperty("OWLY C3 scan_rejected_front", 0ULL, 32);
#endif
#endif
    setProperty("OWLY Gate14 path", OWLY_GATE14_REAL_VIF ?
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        "native role6; observed-peer action/IPv6 RX; queued radio TX; AirDrop unproven" :
#else
#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
        "native role6; Gate C2 RX observer ONLY; no Apple RX/TX" :
#else
        "opt-in real role6 attach; no TX/RX datapath" :
#endif
#endif
        "disabled; Gate13C semantics");
    setProperty("OWLY Gate14 attach_attempt", 0ULL, 32);
    setProperty("OWLY Gate14 attach_succeeded", 0ULL, 32);
    setProperty("OWLY Gate14 bsd_name_ready", 0ULL, 32);
    setProperty("OWLY Gate14 backend_ack", 0ULL, 32);
    setProperty("OWLY Gate14 pending_bsd", 0ULL, 32);
    setProperty("OWLY Gate14 pending_rechecks", 0ULL, 32);
    setProperty("OWLY Gate14 mac_valid", 0ULL, 32);
    setProperty("OWLY Gate14 rollback_ok", 0ULL, 32);
    /* ABI5 diagnostics: read-only IORegistry state; no MAC/pointers recorded.
     * Factory: 0=never, 1=no MAC, 2=allocation failed, 3=init failed,
     * 4=object returned. Attach: 0=not attempted, 1=true+object,
     * 2=false+null, 3=false+object, 4=true+null.
     * Counters are bounded publication checkpoints, not live atomic values.
     */
    setProperty("OWLY ABI5Diag version", 1ULL, 32);
    setProperty("OWLY ABI5Diag factory_no_mac", 0ULL, 32);
    setProperty("OWLY ABI5Diag factory_alloc_fail", 0ULL, 32);
    setProperty("OWLY ABI5Diag factory_init_fail", 0ULL, 32);
    setProperty("OWLY ABI5Diag factory_ready", 0ULL, 32);
    setProperty("OWLY ABI5Diag factory_last", 0ULL, 32);
    setProperty("OWLY ABI5Diag attach_last", 0ULL, 32);
    /* Role-6 virtual GET(12) bridge: sentinel distinguishes never called
     * from backend returning success (0). No data payload is exposed. */
    setProperty("OWLY ABI5Cap12 request_seen", 0ULL, 32);
    setProperty("OWLY ABI5Cap12 backend_rc", 0xFFFFFFFFULL, 32);
    setProperty("OWLY ABI5Cap12 success", 0ULL, 32);
    /* OWLY_GATE13B_PROPERTIES_END */
    registerService();
    LOG("OWLY Gate09: trace ready, ABI4.1 lifecycle unchanged");
    LOG("started; waiting for the driver");
    return true;
}

/* M2.2: Stop never waits on a timed IOSleep loop. All IOCTL94/95 work,
 * identity callbacks and stop-side VIF cleanup share IO80211's workloop gate.
 * The gate is recursive: a backend callback can reenter stop() on the same
 * thread. Defer that nested stop until the enclosing operation finishes. */
void AirPortRTW89Front::stop(IOService *provider)
{
#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
    /* Shutdown admission before Apple starts detaching its P2P object.
     * RX callbacks use only copied bytes and controller-held counters. */
    __atomic_store_n(&_owlyGateC2Ready, 0, __ATOMIC_RELEASE);
    setProperty("OWLY C2 native_vif_ready", 0ULL, 32);
#endif
#if defined(RTW89_AWDL_NATIVE_FRONT_OBSERVE) && RTW89_AWDL_NATIVE_FRONT_OBSERVE
    if (_owlyVifLock) {
        const bool nested = (_workLoop && _workLoop->inGate())
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
            || _owlyNativeOwnerThread==current_thread()
#endif
            ;
        IOLockLock(_owlyVifLock);
        _owlyAWDLStopping = true;
        const bool active = _owlyAWDLRequestBusy || _owlyVifBusy || _owlyVifMethodBusy;
        if (nested && active) {
            /* Cannot wait for ourselves or tear down an object which Apple
             * is still attaching. Keep provider alive for the deferred stop. */
            if (!_owlyDeferredStopProvider && provider) {
                provider->retain();
                _owlyDeferredStopProvider = provider;
            }
            IOLockUnlock(_owlyVifLock);
            LOG("OWLY M2.2: nested stop deferred until callback unwinds");
            return;
        }
        if (_owlyStopFinalizing) {
            IOLockUnlock(_owlyVifLock);
            return; /* another thread is already finishing stop */
        }
        _owlyStopFinalizing = true;
        IOLockUnlock(_owlyVifLock);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        owlyNativeStop();
#endif
        if (_workLoop) {
            const IOReturn rc = _workLoop->runAction(
                [](OSObject *owner, void *, void *, void *, void *) -> IOReturn {
                    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(owner);
                    self->owlyStopVifOnGate();
                    return kIOReturnSuccess;
                }, this);
            if (rc != kIOReturnSuccess)
                LOG("OWLY M2.2: gated VIF stop failed rc=0x%x", (unsigned)rc);
        } else {
            LOG("OWLY M2.2: no workloop; refusing unsafe VIF detach");
        }
    }
#endif
    disconnectBack();
    if (_owlyVifLock) {
        IOLockLock(_owlyVifLock);
        rtw89_front_native_vif_reset(&_owlyAirlink);
        IOLockUnlock(_owlyVifLock);
    }
    if (_netif) {
        detachInterface(_netif, true);
        _netif->release();
        _netif = nullptr;
    }
    if (_superStarted) {
        _superStarted = false;
        super::stop(provider);
    }
}

#if defined(RTW89_AWDL_NATIVE_FRONT_OBSERVE) && RTW89_AWDL_NATIVE_FRONT_OBSERVE
void AirPortRTW89Front::owlyStopVifOnGate()
{
    /* Only called with the workloop gate held. Requests cannot run in
     * parallel; reentrant stop was deferred before entering this routine. */
    if (!_owlyVifLock) return;
    IOLockLock(_owlyVifLock);
    const bool busy = _owlyAWDLRequestBusy || _owlyVifBusy || _owlyVifMethodBusy;
    IO80211VirtualInterface *vif = busy ? nullptr : _owlyAttachedAWDL;
    IOLockUnlock(_owlyVifLock);
    if (busy) {
        LOG("OWLY M2.2: active VIF transaction during stop; quarantine");
        IOLockLock(_owlyVifLock);
        _owlyAWDLQuarantined = true;
        IOLockUnlock(_owlyVifLock);
        return;
    }
    if (!vif) return;
    const bool tracked = owlyVifIsTracked(vif);
    const bool detached = detachVirtualInterface(vif, true);
    bool ack = !tracked;
    if (detached && tracked) {
        const bool disabled = owlyVifEvent(vif, RTW89_FRONT_ROLE_AIRLINK_OBSERVED,
                                             RTW89_FRONT_VIF_DISABLED);
        const bool destroyed = disabled && owlyVifEvent(
            vif, RTW89_FRONT_ROLE_AIRLINK_OBSERVED, RTW89_FRONT_VIF_DESTROYED);
        ack = disabled && destroyed;
    }
    IOLockLock(_owlyVifLock);
    if (detached) {
        _owlyAttachedAWDL = nullptr;
        _owlyAWDLPendingBSD = false;
        _owlyAWDLPendingChecks = 0;
        for (unsigned i = 0; i < 6; ++i) _owlyAWDLRequestMac[i] = 0;
        for (unsigned i = 0; i < 16; ++i) _owlyAWDLBSDName[i] = 0;
    }
    if (!detached || !ack) _owlyAWDLQuarantined = true;
    IOLockUnlock(_owlyVifLock);
    if (detached) vif->release(); /* matched own retain at create */
    if (!detached) LOG("OWLY M2.2: stop-side detach failed; VIF still Apple-owned");
}

void AirPortRTW89Front::owlyFinishDeferredStop()
{
    if (!_owlyVifLock) return;
    IOService *provider = nullptr;
    IOLockLock(_owlyVifLock);
    if (!_owlyAWDLRequestBusy && !_owlyVifBusy && !_owlyVifMethodBusy) {
        provider = _owlyDeferredStopProvider;
        _owlyDeferredStopProvider = nullptr;
    }
    IOLockUnlock(_owlyVifLock);
    if (provider) {
        /* Call only after releasing the workloop gate; stop may destroy its
         * command gate. The caller holds a self-reference while returning. */
        stop(provider);
        provider->release();
    }
}
#endif

void AirPortRTW89Front::free()
{
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    owlyNativeStop();
    if(_owlyNativeCall) {thread_call_free(_owlyNativeCall);_owlyNativeCall=nullptr;}
#endif
#if defined(RTW89_AWDL_NATIVE_FRONT_OBSERVE) && RTW89_AWDL_NATIVE_FRONT_OBSERVE
    if (_owlyDeferredStopProvider) {
        _owlyDeferredStopProvider->release();
        _owlyDeferredStopProvider = nullptr;
    }
    if (_owlyAttachedAWDL) {
        /* Detach may have failed or Apple may have detached externally.
         * Drop only our explicit retain, never a borrowed Apple reference. */
        _owlyAttachedAWDL->release();
        _owlyAttachedAWDL = nullptr;
    }
#endif
    if (_owlyVifLock) {
        IOLockFree(_owlyVifLock);
        _owlyVifLock = nullptr;
    }
    if (_backLock) {
        IOLockFree(_backLock);
        _backLock = nullptr;
    }
    OSSafeReleaseNULL(_workLoop);
    super::free();
}

IOReturn AirPortRTW89Front::registerWithPolicyMaker(IOService *policyMaker)
{
    return policyMaker->registerPowerDriver(this, gPowerStates, kPowerStateCount);
}

IOReturn AirPortRTW89Front::setPowerState(unsigned long powerStateOrdinal, IOService *whatDevice)
{
    const bool there = backEnter();
    if (there && _back.power)
        _back.power(_back.ctx, powerStateOrdinal != kPowerStateOff);
    backLeave();
    return IOPMAckImplied;
}

/* ------------------------------------------------------------------ */
/*  The driver proper comes and goes                                    */
/* ------------------------------------------------------------------ */

/*
 * Around every call into the driver proper. Not a read/write lock: IO80211
 * calls back in from inside such a call (postMessage() asks for the BSSID),
 * and a second read lock taken while disconnectBack() waits for the write
 * lock would never be granted. Counting instead, the call that comes in
 * during a disconnect is told nobody is there, and the outer one returns.
 */
bool AirPortRTW89Front::backEnter()
{
    OSIncrementAtomic(&_backCalls);
    return _connected;
}

void AirPortRTW89Front::backLeave()
{
    OSDecrementAtomic(&_backCalls);
}

/*
 * The family's AWDL state every five seconds, as properties, and the link put
 * back up when it is found down.
 *
 * IO80211AWDLPeerManager::updateLocalRequests() is where wifip2pd's service
 * records (AirDrop's SRV and TXT among them) arrive, and it drops each one
 * with "Received service request but link is down" while the interface's
 * link state at 0xfc is not 2, or "but not configured" while bit 1 of the
 * peer manager's state flags at 0x8528 is clear. Past those two checks it
 * rebuilds the sync frame template with the records in it and hands it to
 * us. On 2026-11-11 no new template ever arrived while AirDrop advertised,
 * awdl0 read "status: inactive", and our own log has seen 0xfc read back 1
 * after we set it up. The driver's log ring is too small to keep these
 * readings, hence the registry. Offsets are IO80211FamilyLegacy's, as
 * elsewhere in this file; everything here only reads them, except the
 * setLinkState() call, which is the one awdlEnableThread() already makes.
 */

bool AirPortRTW89Front::logLine(const char *line)
{
    bool done = false;

    const bool there = backEnter();
    if (there && _back.log) {
        _back.log(_back.ctx, line);
        done = true;
    }
    backLeave();
    return done;
}

IOReturn AirPortRTW89Front::callPlatformFunction(const OSSymbol *functionName, bool waitForFunction,
                                                 void *param1, void *param2, void *param3,
                                                 void *param4)
{
    if (functionName && functionName->isEqualTo(RTW89_FRONT_CONNECT))
        return connectBack(static_cast<const struct rtw89_back_ops *>(param1),
                           static_cast<struct rtw89_front_ops *>(param2));
    if (functionName && functionName->isEqualTo(RTW89_FRONT_DISCONNECT))
        return disconnectBack();
    return super::callPlatformFunction(functionName, waitForFunction, param1, param2, param3,
                                       param4);
}

bool AirPortRTW89Front::publishMedium()
{
    OSDictionary *dict = OSDictionary::withCapacity(1);
    IONetworkMedium *medium = IONetworkMedium::medium(kIOMediumIEEE80211Auto, 11000000);
    bool ok = dict && medium && IONetworkMedium::addMedium(dict, medium) &&
              publishMediumDictionary(dict) && setCurrentMedium(medium) &&
              setSelectedMedium(medium);

    if (ok)
        _medium = medium;       /* kept alive by the published dictionary */
    OSSafeReleaseNULL(medium);
    OSSafeReleaseNULL(dict);
    return ok;
}

IOReturn AirPortRTW89Front::connectBack(const struct rtw89_back_ops *back,
                                        struct rtw89_front_ops *front)
{
    if (!back || !front || back->version != RTW89_FRONT_API_VERSION || !back->get_mac ||
        !back->request || !back->output)
        return kIOReturnBadArgument;

    IOLockLock(_backLock);
    if (_connected) {
        IOLockUnlock(_backLock);
        return kIOReturnExclusiveAccess;
    }
    _back = *back;
    _connected = true;
    IOLockUnlock(_backLock);

    back->get_mac(back->ctx, _mac.bytes);
    _haveMac = true;
    setProperty(kIOMACAddress, _mac.bytes, kIOEthernetAddressSize);

    if (!_netif) {
        /* medium first, then the interface, as AirportItlwm does */
        if (!publishMedium() || !attachInterface((IONetworkInterface **)&_netif, true) || !_netif) {
            LOG("could not attach the network interface");
            disconnectBack();
            return kIOReturnNoResources;
        }
        IO80211Controller::setLinkStatus(kIONetworkLinkValid);
        _netif->registerService();
        LOG("network interface attached");
    }

    front->version = RTW89_FRONT_API_VERSION;
    front->ctx = this;
    front->interface = _netif;
    front->post_message = opPostMessage;
    front->set_link = opSetLink;
    front->alloc_packet = opAllocPacket;
    front->input_packet = opInputPacket;
    front->tx_wake = opTxWake;
    front->super_ioctl = opSuperIoctl;
    front->super_ioctl_set = opSuperIoctlSet;
    front->set_apple_rsn = opSetAppleRsn;
#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
    front->owly_rx_handoff = opOwlyRxHandoff;
#endif

    gLogFront = this;
    setProperty("RTW89 Back Connected", kOSBooleanTrue);
    LOG("driver connected, address %02x:%02x:%02x:%02x:%02x:%02x", _mac.bytes[0], _mac.bytes[1],
        _mac.bytes[2], _mac.bytes[3], _mac.bytes[4], _mac.bytes[5]);
    return kIOReturnSuccess;
}

IOReturn AirPortRTW89Front::disconnectBack()
{
    bool was;

    if (!_backLock)
        return kIOReturnSuccess;
    /* none start after this; wait for the ones in progress */
    IOLockLock(_backLock);
    was = _connected;
    _connected = false;
#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
    /* No further frontend packet admission when the backend disconnects. */
    __atomic_store_n(&_owlyGateC2Ready, 0, __ATOMIC_RELEASE);
#endif
    gAppleRsn = false;
    for (unsigned int ms = 1; _backCalls; ms++) {
        IOSleep(1);
        if (ms % 5000 == 0)
            LOG("still waiting for %d call(s) into the driver to return", (int)_backCalls);
    }
    bzero(&_back, sizeof(_back));
    if (_owlyVifLock) {
        IOLockLock(_owlyVifLock);
        rtw89_front_native_vif_reset(&_owlyAirlink);
        IOLockUnlock(_owlyVifLock);
    }
    IOLockUnlock(_backLock);

    if (was) {
        /* the last line that can still reach the ring */
        LOG("driver disconnected");
#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
        setProperty("OWLY C2 native_vif_ready", 0ULL, 32);
#endif
        setProperty("RTW89 Back Connected", kOSBooleanFalse);
        if (_netif)
            opSetLink(this, false, 0, 0);
    }
    gLogFront = nullptr;
    return kIOReturnSuccess;
}

/* ------------------------------------------------------------------ */
/*  For the driver: rtw89_front_ops                                     */
/* ------------------------------------------------------------------ */

void AirPortRTW89Front::opPostMessage(void *ctx, unsigned int msg, void *data, size_t len)
{
    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(ctx);

    if (self->_netif)
        self->_netif->postMessage(msg, data, len);
}

void AirPortRTW89Front::opSetLink(void *ctx, bool up, uint64_t bps, unsigned int reason)
{
    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(ctx);
    IOCommandGate *gate = self->getCommandGate();

    self->IO80211Controller::setLinkStatus(up ? (kIONetworkLinkValid | kIONetworkLinkActive) :
                                                kIONetworkLinkValid,
                                           self->_medium, bps, nullptr);
    if (!self->_netif || !gate)
        return;
    /* IO80211's own idea of the link, under its gate as AirportItlwm does */
    gate->runAction([](OSObject *owner, void *linkUp, void *why, void *, void *) -> IOReturn {
        AirPortRTW89Front *me = static_cast<AirPortRTW89Front *>(owner);

        if (!me->_netif)
            return kIOReturnNotReady;
        me->_netif->setLinkState(linkUp ? kIO80211NetworkLinkUp : kIO80211NetworkLinkDown,
                                 (unsigned int)(uintptr_t)why);
        if (linkUp)
            me->_netif->setLinkQualityMetric(100);
        return kIOReturnSuccess;
    }, (void *)(uintptr_t)up, (void *)(uintptr_t)(up ? 0 : reason));
}

void AirPortRTW89Front::opSetAppleRsn(void *ctx, bool on)
{
    gAppleRsn = on;
}

bool AirPortRTW89Front::useAppleRSNSupplicant(IO80211Interface *interface)
{
    return gAppleRsn;
}

mbuf_t AirPortRTW89Front::opAllocPacket(void *ctx, unsigned int len)
{
    return static_cast<AirPortRTW89Front *>(ctx)->allocatePacket(len);
}

void AirPortRTW89Front::opInputPacket(void *ctx, mbuf_t m)
{
    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(ctx);

    if (!self->_netif) {
        mbuf_freem(m);
        return;
    }
    self->_netif->inputPacket(m, (UInt32)mbuf_pkthdr_len(m), 0);
}

#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
bool AirPortRTW89Front::opOwlyRxHandoff(void *ctx, const struct owly_abi6_packet *pkt)
{
    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(ctx);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    if(self && pkt && pkt->kind!=OWLY_ABI6_PACKET_C3_SCAN_SIGNATURE)
        return self->owlyNativeReceive(pkt);
#endif
    /* Real cross-KEXT RX on the hardware thread, but NO packet touches
     * Apple's private inputPacket/actionFrameInput ABI. The controller is
     * held by the backend's front reference until RX gate drains. */
    if (!self || !pkt || pkt->length > OWLY_ABI6_PACKET_MAX) return false;
    if (__atomic_load_n(&self->_owlyGateC2Ready, __ATOMIC_ACQUIRE) != 1) {
        owlyGateC2Note(self, "OWLY C2 not_ready", &gOwlyC2NotReady);
        return false;
    }
#if defined(OWLY_ABI6_C3_SCAN_OBSERVER) && OWLY_ABI6_C3_SCAN_OBSERVER
    if (pkt->kind == OWLY_ABI6_PACKET_C3_SCAN_SIGNATURE) {
        /* Separate metric: does NOT imply complete TLVs, peer auth, or Apple RX. */
        if (owly_c3_scan_signature(pkt->bytes, pkt->length) &&
            memcmp(pkt->bytes+10,pkt->src,6)==0 &&
            memcmp(pkt->bytes+4,pkt->dst,6)==0) {
            owlyGateC2Note(self, "OWLY C3 scan_signature_front", &gOwlyC3ScanSignaturesFront);
        } else {
            owlyGateC2Note(self, "OWLY C3 scan_rejected_front", &gOwlyC3ScanRejectedFront);
        }
        return false; /* Intentionally NO Apple inputPacket; not an ACK. */
    }
#endif
    /* No large RX-thread stack buffers; heap allocations are bounded,
     * and only IPv6 packets require the Ethernet scratch. */
    uint8_t *l2 = nullptr;
    size_t l2_len = 0;
    if (pkt->kind == OWLY_ABI6_PACKET_IPV6) {
        l2 = static_cast<uint8_t *>(IOMalloc(OWLY_GATEC_ETH_FRAME_MAX));
        if (!l2) {
            owlyGateC2Note(self, "OWLY C2 rejected", &gOwlyC2Rejected);
            return false;
        }
    }
    const enum owly_gatec2_inspect_kind kind =
        owly_gatec2_inspect(pkt, l2, l2 ? OWLY_GATEC_ETH_FRAME_MAX : 0u, &l2_len);
    if (l2) IOFree(l2, OWLY_GATEC_ETH_FRAME_MAX);
    if (kind == OWLY_GATEC2_ACTION)
        owlyGateC2Note(self, "OWLY C2 action_front", &gOwlyC2Actions);
    else if (kind == OWLY_GATEC2_IPV6_L2)
        owlyGateC2Note(self, "OWLY C2 ipv6_l2_front", &gOwlyC2L2IPv6);
    else
        owlyGateC2Note(self, "OWLY C2 rejected", &gOwlyC2Rejected);

    return false; /* Apple did NOT consume a packet. No false ACK. */
}
#endif

void AirPortRTW89Front::opTxWake(void *ctx)
{
    IOOutputQueue *queue = static_cast<AirPortRTW89Front *>(ctx)->getOutputQueue();

    if (queue)
        queue->service(IOBasicOutputQueue::kServiceAsync);
}


#if defined(OWLY_AWDL_SERVICE_LIFECYCLE) && OWLY_AWDL_SERVICE_LIFECYCLE
/* Exact pinned Legacy BSD SET120 path only. The outer envelope is a kernel
 * local already parsed by the backend. Embedded userspace data is NEVER read
 * here; Apple's original handler retains all copyIn/validation/copyOut work.
 * This is not used for the ambiguous split ioctl_set callback. */
bool AirPortRTW89Front::owlyServiceIoctl(IO80211Interface *interface,
    IO80211VirtualInterface *vif, ifnet_t net, unsigned long command,
    void *envelope, int *result)
{
    if (!result || command != SIOCSA80211 || !vif || !envelope ||
        !_owlyVifLock || !_workLoop) return false;
    IOLockLock(_owlyVifLock);
    const bool ours = vif == _owlyAttachedAWDL && !_owlyAWDLPendingBSD;
    IOLockUnlock(_owlyVifLock);
    if (!ours) return false;
    const auto *request = static_cast<const apple80211req *>(envelope);
    if (request->req_type != APPLE80211_IOC_AWDL_PEER_SERVICE_REQUEST ||
        request->req_len < 20 || request->req_len > 4096) return false;
    /* Do not activate anything before authenticating the real caller. */
    if (current_task() != kernel_task) {
        OwlyEntitlement::Result auth;
        if (!OwlyEntitlement::authorize(current_task(), auth)) {
            *result = EPERM;
            return true;
        }
    }
    retain();
    IOWorkLoop *loop = _workLoop;
    loop->retain();
    OwlyServiceCall call = {interface, vif, net, command, envelope, ENXIO};
    const IOReturn rc = loop->runAction(
        [](OSObject *owner, void *opaque, void *, void *, void *) -> IOReturn {
            auto *self = static_cast<AirPortRTW89Front *>(owner);
            auto *args = static_cast<OwlyServiceCall *>(opaque);
            args->result = self->owlyServiceIoctlOnGate(args);
            return kIOReturnSuccess;
        }, this, &call);
    *result = rc == kIOReturnSuccess ? call.result : ENXIO;
    loop->release();
    /* Deferred stop is finished in apple80211_ioctl AFTER backLeave(). */
    release();
    return true;
}

int AirPortRTW89Front::owlyServiceIoctlOnGate(OwlyServiceCall *call)
{
    if (!call || !_owlyVifLock || !_workLoop || !_workLoop->inGate()) return ENXIO;
    IOLockLock(_owlyVifLock);
    if (_owlyAWDLStopping || _owlyAWDLQuarantined || _owlyAWDLRequestBusy ||
        _owlyVifBusy || _owlyVifMethodBusy || _owlyAWDLPendingBSD ||
        !call->vif || call->vif != _owlyAttachedAWDL ||
        _owlyAirlink.cookie != call->vif ||
        _owlyAirlink.role != RTW89_FRONT_ROLE_AIRLINK_OBSERVED) {
        IOLockUnlock(_owlyVifLock);
        return ENXIO;
    }
    _owlyVifMethodBusy = true; /* Protect from reentrant stop/delete. */
    call->vif->retain();
    IOLockUnlock(_owlyVifLock);

    const bool there = backEnter();
    const bool ready = there && _back.vif_event && _back.vif_event(_back.ctx,
        call->vif, RTW89_FRONT_ROLE_AIRLINK_OBSERVED,
        RTW89_FRONT_VIF_SERVICE_READY, nullptr);
    backLeave();
    IOLockLock(_owlyVifLock);
    bool stopping = _owlyAWDLStopping;
    IOLockUnlock(_owlyVifLock);
    const bool prepare = ready && !stopping;
    /* Qualified base call: exact exported Legacy implementation, no new
     * vtable layout/offset. Link-up enables the real Apple peer manager.
     * This describes a prepared interface, NOT a peer, sync or RF success.
     * RF remains controlled by the unmodified SET117/151 and SCC guards. */
    call->vif->IO80211VirtualInterface::setEnabledBySystem(prepare);
    call->vif->IO80211VirtualInterface::setLinkState(
        prepare ? kIO80211NetworkLinkUp : kIO80211NetworkLinkDown, 1);
    setProperty("OwlyServiceReadinessLast", ready ? 1ULL : 0ULL, 32);
    setProperty("OwlyServiceCarrierPrepared", prepare ? 1ULL : 0ULL, 32);
    setProperty("OwlyServiceSystemEnableRequested", prepare ? 1ULL : 0ULL, 32);
    IOLockLock(_owlyVifLock);
    stopping = _owlyAWDLStopping;
    IOLockUnlock(_owlyVifLock);
    int result = ENXIO;
    if (!stopping) {
        result = IO80211Controller::apple80211_ioctl(call->interface, call->vif,
            call->net, call->command, call->envelope);
        setProperty("OwlyServiceAppleResultLast",
            static_cast<unsigned long long>(static_cast<uint32_t>(result)), 32);
    } else {
        call->vif->IO80211VirtualInterface::setEnabledBySystem(false);
        call->vif->IO80211VirtualInterface::setLinkState(kIO80211NetworkLinkDown, 1);
        setProperty("OwlyServiceCarrierPrepared", 0ULL, 32);
        setProperty("OwlyServiceSystemEnableRequested", 0ULL, 32);
    }
    IOLockLock(_owlyVifLock);
    _owlyVifMethodBusy = false;
    IOLockUnlock(_owlyVifLock);
    call->vif->release();
    return result; /* Preserve Apple's actual service error or success. */
}
#endif

int AirPortRTW89Front::opSuperIoctl(void *ctx, void *interface, void *vif, void *ifnet,
                                    unsigned long cmd, void *data)
{
    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(ctx);
    owlyGate12FHit(self, "OWLY Gate12F super_ioctl", &gOwlyFSuperIOCTL);

#if defined(OWLY_AWDL_SERVICE_LIFECYCLE) && OWLY_AWDL_SERVICE_LIFECYCLE
    int serviceResult = ENXIO;
    if (self->owlyServiceIoctl(static_cast<IO80211Interface *>(interface),
            static_cast<IO80211VirtualInterface *>(vif), static_cast<ifnet_t>(ifnet),
            cmd, data, &serviceResult))
        return serviceResult;
#endif
    const int result = self->IO80211Controller::apple80211_ioctl(
        static_cast<IO80211Interface *>(interface), static_cast<IO80211VirtualInterface *>(vif),
        static_cast<ifnet_t>(ifnet), cmd, data);
    if (result != 0 && OSIncrementAtomic(&gOwlyG09SuperErrors) < 48)
        LOG("OWLY Gate09: inherited ioctl cmd=0x%lx rc=%d", cmd, result);
    return result;
}

int AirPortRTW89Front::opSuperIoctlSet(void *ctx, void *interface, void *vif, void *skywalk,
                                       void *data)
{
    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(ctx);
    owlyGate12FHit(self, "OWLY Gate12F super_ioctl_set", &gOwlyFSuperSet);

    const int result = self->IO80211Controller::apple80211_ioctl_set(
        static_cast<IO80211Interface *>(interface), static_cast<IO80211VirtualInterface *>(vif),
        static_cast<IO80211SkywalkInterface *>(skywalk), data);
    if (result != 0 && OSIncrementAtomic(&gOwlyG09SuperErrors) < 48)
        LOG("OWLY Gate09: inherited ioctl_set rc=%d", result);
    return result;
}

/* ------------------------------------------------------------------ */
/*  From the family: passed on                                          */
/* ------------------------------------------------------------------ */

SInt32 AirPortRTW89Front::apple80211_ioctl(IO80211Interface *interface, IO80211VirtualInterface *vif,
                                           ifnet_t net, unsigned long cmd, void *data)
{
    owlyGate12FHit(this, "OWLY Gate12F ioctl_any", &gOwlyFIOCTLAny);
    if (cmd == SIOCSA80211)
        owlyGate12FHit(this, "OWLY Gate12F ioctl_set_command", &gOwlyFIOCTLSetCmd);
    /* No dereference of data or request payload. Bounded trace on set IOCTLs. */
    const SInt32 gate12Seq = (cmd == SIOCSA80211) ?
        OSIncrementAtomic(&gOwlyG12Ioctl) : 1000;
    const bool gate12Log = gate12Seq < 64;
    if (gate12Log)
        LOG("OWLY Gate12: ioctl ENTER seq=%d set=1 primary=%u vif=%u data=%u cmd=0x%lx",
            (int)gate12Seq, interface == _netif ? 1U : 0U, vif ? 1U : 0U,
            data ? 1U : 0U, cmd);
    bool handled = false;
    SInt32 ret = 0;

#if 0 /* Gate14: old M2.3 envelope is prohibited */
    /* The legacy IOCTL envelope can arrive here, not only at
     * apple80211Request(). Intercept exclusively request 94/95 on our own
     * primary en1 interface; everything else preserves its old path. */
    if (cmd == SIOCSA80211) {
        ret = owlyBridgeVifSetEnvelope(interface, vif, data, &handled);
        if (handled) return ret;
    }
#endif

    const bool there = backEnter();
    if (there && _back.ioctl) {
        owlyGate12FHit(this, "OWLY Gate12F backend_ioctl", &gOwlyFBackendIOCTL);
        ret = _back.ioctl(_back.ctx, interface, vif, net, cmd, data, &handled);
    }
    backLeave();
    if (!handled)
        owlyGate12FHit(this, "OWLY Gate12F fallback_ioctl", &gOwlyFFallbackIOCTL);
    const SInt32 result = handled ? ret : super::apple80211_ioctl(interface, vif, net, cmd, data);
#if defined(OWLY_AWDL_SERVICE_LIFECYCLE) && OWLY_AWDL_SERVICE_LIFECYCLE
    /* The service callback ran inside _back.ioctl(). Wait until backLeave()
     * above before finishing a recursively deferred stop: disconnectBack()
     * must never wait for our own outstanding backend call. */
    owlyFinishDeferredStop();
#endif
    if (gate12Log)
        LOG("OWLY Gate12: ioctl EXIT seq=%d backend=%u handled=%u rc=%d",
            (int)gate12Seq, there ? 1U : 0U, handled ? 1U : 0U, (int)result);
    if (result != 0 && OSIncrementAtomic(&gOwlyG09IoctlErrors) < 48)
        LOG("OWLY Gate09: ioctl cmd=0x%lx backend=%u handled=%u rc=%d",
            cmd, there ? 1U : 0U, handled ? 1U : 0U, (int)result);
    return result;
}

SInt32 AirPortRTW89Front::apple80211_ioctl_set(IO80211Interface *interface,
                                               IO80211VirtualInterface *vif,
                                               IO80211SkywalkInterface *skywalk, void *data)
{
    owlyGate12FHit(this, "OWLY Gate12F ioctl_set_callback", &gOwlyFIOCTLSetCallback);
    /* The set callback has no explicit request number in its C++ signature.
     * Log only the envelope; never guess that data is apple80211req. */
    const SInt32 gate12Seq = OSIncrementAtomic(&gOwlyG12Set);
    const bool gate12Log = gate12Seq < 64;
    if (gate12Log)
        LOG("OWLY Gate12: ioctl_set ENTER seq=%d primary=%u vif=%u skywalk=%u data=%u",
            (int)gate12Seq, interface == _netif ? 1U : 0U, vif ? 1U : 0U,
            skywalk ? 1U : 0U, data ? 1U : 0U);
    bool handled = false;
    SInt32 ret = 0;

#if 0 /* Gate14: old M2.3 envelope is prohibited */
    ret = owlyBridgeVifSetEnvelope(interface, vif, data, &handled);
    if (handled) return ret;
#endif

    const bool there = backEnter();
    if (there && _back.ioctl_set) {
        owlyGate12FHit(this, "OWLY Gate12F backend_ioctl_set", &gOwlyFBackendSet);
        ret = _back.ioctl_set(_back.ctx, interface, vif, skywalk, data, &handled);
    }
    backLeave();
    if (!handled)
        owlyGate12FHit(this, "OWLY Gate12F fallback_ioctl_set", &gOwlyFFallbackSet);
    const SInt32 result = handled ? ret : super::apple80211_ioctl_set(interface, vif, skywalk, data);
    if (gate12Log)
        LOG("OWLY Gate12: ioctl_set EXIT seq=%d backend=%u handled=%u rc=%d",
            (int)gate12Seq, there ? 1U : 0U, handled ? 1U : 0U, (int)result);
    if (result != 0 && OSIncrementAtomic(&gOwlyG09SetErrors) < 48)
        LOG("OWLY Gate09: ioctl_set backend=%u handled=%u rc=%d",
            there ? 1U : 0U, handled ? 1U : 0U, (int)result);
    return result;
}

#if OWLY_GATE14_REAL_VIF
/* OWLY M2 REQUEST94 BEGIN
 * Apple IO80211FamilyLegacy setVirtualInterfaceCreate() copies <=32 bytes,
 * calls apple80211RequestIoctl(type=SIOCSA80211, number=94, data=stack copy),
 * then copies that structure back after successful request.  This mirrors the
 * apple80211_virt_if_create_data ABI used by MacKernelSDK.  The definition is
 * purposely local to make ABI assumptions explicit and compile-time checked.
 */
struct OwlyM2CreateRequest {
    uint32_t version;
    uint8_t mac[6];
    uint16_t unknown;
    uint32_t role;
    uint8_t bsd_name[16];
} __attribute__((packed));
struct OwlyM2DeleteRequest {
    uint32_t version;
    uint8_t bsd_name[16];
} __attribute__((packed));
static_assert(sizeof(OwlyM2CreateRequest) == 32, "IOCTL94 layout changed");
static_assert(sizeof(OwlyM2DeleteRequest) == 20, "IOCTL95 layout changed");

/* OWLY M2.3: 94/95 must also be received at the IOCTL envelope boundary.
 * On this IO80211 legacy family, apple80211_ioctl_set() is a distinct
 * virtual method from apple80211Request(); the Apple handler may never call
 * our apple80211Request override on some IOCTL paths. The envelope's payload
 * is a userspace address: use the kernel copyin/copyout functions.
 * No fabricated awdl0, no fake success, no AWDL RF TX/RX. */
#if 0 /* Gate14: never compile the old userspace envelope bridge */
SInt32 AirPortRTW89Front::owlyBridgeVifSetEnvelope(IO80211Interface *interface,
    IO80211VirtualInterface *vif, void *data, bool *handled)
{
    if (!handled) return EINVAL;
    *handled = false;
    if (!data || !interface || interface != _netif || vif)
        return 0; /* The Apple/Realtek legacy path handles other interfaces. */

    const apple80211req *req = static_cast<const apple80211req *>(data);
    const int number = req->req_type;
    if (number != APPLE80211_IOC_VIRTUAL_IF_CREATE &&
        number != APPLE80211_IOC_VIRTUAL_IF_DELETE)
        return 0;
    *handled = true;

    const bool create = number == APPLE80211_IOC_VIRTUAL_IF_CREATE;
    const unsigned expected = create ? sizeof(OwlyM2CreateRequest) :
                                        sizeof(OwlyM2DeleteRequest);
    if ((unsigned)req->req_len != expected || !req->req_data)
        return EINVAL;
    if (!_workLoop || !_owlyVifLock)
        return EBUSY;

    const uint64_t userAddress = (uint64_t)(uintptr_t)req->req_data;
    union { OwlyM2CreateRequest create; OwlyM2DeleteRequest remove; } payload = {};
    /* Copy from userspace with the kernel copyin() API (0 means success).
     * Never dereference req_data as a kernel address. */
    if (::copyin(userAddress, &payload, expected) != 0)
        return EFAULT;

    const SInt32 result = apple80211Request(SIOCSA80211, number, interface, &payload);
    if (result != kIOReturnSuccess) {
        LOG("OWLY M2.3: ioctl%u create/delete rejected role=%u version=%u rc=0x%x",
            (unsigned)number, create ? (unsigned)payload.create.role : 0U,
            create ? (unsigned)payload.create.version : (unsigned)payload.remove.version,
            (unsigned)result);
        return errnoFromReturn(result);
    }

    if (!create) return 0; /* Delete has no output payload. */

    /* The BSD name is produced by attachVirtualInterface. Return it to
     * wifip2pd exactly as the Apple handler would; otherwise it cannot
     * discover the actual interface. */
    if (::copyout(&payload.create, userAddress, expected) != 0) {
        /* A successfully attached but unnamed-to-user VIF must not remain
         * silently live. Request95 performs the existing gated cleanup. */
        OwlyM2DeleteRequest undo = {};
        undo.version = payload.create.version;
        for (unsigned i = 0; i < sizeof(undo.bsd_name); ++i)
            undo.bsd_name[i] = payload.create.bsd_name[i];
        const SInt32 undone = apple80211Request(
            SIOCSA80211, APPLE80211_IOC_VIRTUAL_IF_DELETE, interface, &undo);
        if (undone != kIOReturnSuccess)
            LOG("OWLY M2.3: copyOut failed; cleanup rejected rc=0x%x",
                (unsigned)undone);
        return EFAULT;
    }
    LOG("OWLY M2.3: IOCTL94 completed with a real Apple-attached VIF");
    return 0;
}

#endif /* old unsafe envelope bridge */

/* A BSD name may be published after the initial attach returns.  Only
 * accept the actual name supplied by the Apple object; never fabricate awdl0.
 * This helper runs on the IO80211 workloop; caller holds a VIF retain.
 * The copied name is bounded to the 16-byte request output slot. */
static bool owlyGate14CopyBSDName(IO80211VirtualInterface *vif, char out[16])
{
    if (!vif || !out) return false;
    const char *name = vif->getBSDName();
    if (!name || name[0] != 'a' || name[1] != 'w' ||
        name[2] != 'd' || name[3] != 'l') return false;
    unsigned n = 4;
    if (name[n] < '0' || name[n] > '9') return false;
    while (n < 15 && name[n] >= '0' && name[n] <= '9') ++n;
    if (name[n] != '\0') return false;
    for (unsigned i = 0; i < 16; ++i) out[i] = i < n ? name[i] : 0;
    return true;
}

SInt32 AirPortRTW89Front::owlyRequestAWDLCreate(unsigned int type, void *data)
{
    if (type != SIOCSA80211 || !data || !_owlyVifLock)
        return kIOReturnBadArgument;
    OwlyM2CreateRequest *req = static_cast<OwlyM2CreateRequest *>(data);
    if (req->version != OWLY_GATE14_REQ94_VERSION ||
        req->role != RTW89_FRONT_ROLE_AIRLINK_OBSERVED)
        return kIOReturnUnsupported;
    bool nonzero = false;
    for (unsigned i = 0; i < 6; ++i) nonzero |= req->mac[i] != 0;
    const bool validMac = nonzero && !(req->mac[0] & 1);
    setProperty("OWLY Gate14 mac_valid", validMac ? 1ULL : 0ULL, 32);
    if (!validMac) return kIOReturnBadArgument;

    IO80211VirtualInterface *newVif = nullptr;
    bool retryPending = false;
    unsigned checks = 0;
    IOLockLock(_owlyVifLock);
    if (_owlyAWDLStopping || _owlyAWDLRequestBusy || _owlyAWDLQuarantined
#if defined(OWLY_AWDL_SERVICE_LIFECYCLE) && OWLY_AWDL_SERVICE_LIFECYCLE
        || _owlyVifMethodBusy
#endif
    ) {
        IOLockUnlock(_owlyVifLock);
        return kIOReturnBusy;
    }
    if (_owlyAttachedAWDL) {
        if (!_owlyAWDLPendingBSD) {
            IOLockUnlock(_owlyVifLock);
            return kIOReturnBusy; /* Existing committed identity; do not replace. */
        }
        for (unsigned i = 0; i < 6; ++i) {
            if (_owlyAWDLRequestMac[i] != req->mac[i]) {
                IOLockUnlock(_owlyVifLock);
                return kIOReturnBusy; /* Another request must not inherit pending VIF. */
            }
        }
        retryPending = true;
        newVif = _owlyAttachedAWDL; /* explicit retained ownership */
        checks = ++_owlyAWDLPendingChecks;
    }
    _owlyAWDLRequestBusy = true;
    IOLockUnlock(_owlyVifLock);

    bool attached = retryPending;
    if (!retryPending) {
        struct ether_addr mac = {};
        for (unsigned i = 0; i < 6; ++i) mac.octet[i] = req->mac[i];
        setProperty("OWLY Gate14 attach_attempt", 1ULL, 32);
        attached = attachVirtualInterface(&newVif, &mac,
                              RTW89_FRONT_ROLE_AIRLINK_OBSERVED, true);
        /* Preserve both pieces of the raw Apple return. Never dereference
         * newVif on a failed attach: its lifetime belongs to Apple. */
        setProperty("OWLY ABI5Diag attach_last",
                    attached ? (newVif ? 1ULL : 4ULL)
                             : (newVif ? 3ULL : 2ULL), 32);
        setProperty("OWLY Gate14 attach_succeeded", attached && newVif ? 1ULL : 0ULL, 32);
        if (attached && newVif) newVif->retain(); /* own ref across detach */
    }

    char bsdSnapshot[16] = {};
    const bool validBSD = attached && newVif &&
                          owlyGate14CopyBSDName(newVif, bsdSnapshot);
    setProperty("OWLY Gate14 bsd_name_ready", validBSD ? 1ULL : 0ULL, 32);

    /* ABI5 transaction: a successful Apple attach is sufficient to ask the
     * hardware to register its second P2P-client VIF. BSD-name publication
     * is independent and may lag. Do not claim the CREATE ioctl succeeded
     * until a real awdlN BSD name is visible.
     *
     * On the pending retry, _owlyAirlink is the already-ACKed identity;
     * reusing it does not send a second hardware add_interface().
     */
    bool stopping = false;
    IOLockLock(_owlyVifLock);
    stopping = _owlyAWDLStopping;
    IOLockUnlock(_owlyVifLock);
#if OWLY_ABI6_NATIVE_P2P_FACTORY
    /* A base VIF is NOT a substitute for a native Apple P2P class. Reject
     * it before hardware ACK, so the existing detach/rollback path runs. */
    const bool appleP2PClass = newVif &&
        (OSDynamicCast(IO80211P2PInterface, newVif) != nullptr);
#else
    const bool appleP2PClass = true; /* original Gate14 base-class path */
#endif
    const bool trackedBefore = attached && newVif && owlyVifIsTracked(newVif);
    const bool acknowledged = attached && newVif && appleP2PClass && !stopping &&
        (trackedBefore ||
         (!retryPending && owlyVifEvent(newVif, RTW89_FRONT_ROLE_AIRLINK_OBSERVED,
                                        RTW89_FRONT_VIF_CREATED, req->mac)));
    setProperty("OWLY ABI5 hardware_vif_ack", acknowledged ? 1ULL : 0ULL, 32);
    setProperty("OWLY Gate14 backend_ack", acknowledged ? 1ULL : 0ULL, 32);
#if OWLY_ABI6_NATIVE_P2P_FACTORY
    setProperty("OWLY ABI6 P2P instance verified", appleP2PClass ? 1ULL : 0ULL, 32);
#endif

    if (acknowledged && !validBSD && (!retryPending || checks < 4U)) {
        /* Hardware ACKed, but Apple has not yet named its VIF. Keep one
         * retained object; return NotReady, not false success. This pending
         * state is NOT time-bounded if Apple never retries; stop() owns the
         * remaining cleanup. Experimental: no boot without lifecycle review. */
        IOLockLock(_owlyVifLock);
        _owlyAttachedAWDL = newVif;
        _owlyAWDLPendingBSD = true;
        if (!retryPending) {
            _owlyAWDLPendingChecks = 0;
            for (unsigned i = 0; i < 6; ++i) _owlyAWDLRequestMac[i] = req->mac[i];
        }
        _owlyAWDLRequestBusy = false;
        IOLockUnlock(_owlyVifLock);
        setProperty("OWLY Gate14 pending_bsd", 1ULL, 32);
        setProperty("OWLY Gate14 pending_rechecks", (unsigned long long)checks, 32);
        LOG("OWLY ABI5: hardware VIF registered, BSD name pending; request94 NotReady");
        return kIOReturnNotReady;
    }

    if (!acknowledged || !validBSD) {
        /* No successful IOCTL without both Apple BSD registration and
         * hardware ACK. An attached object retains an explicit reference
         * until detach completes. Backend removal happens ONLY after a
         * successful detach, and a failed remove quarantines this boot. */
        const bool ambiguous = !attached && newVif != nullptr;
        bool rolledBack = !attached && !ambiguous;
        bool backendGone = !trackedBefore && !acknowledged;
        if (attached && newVif) {
            const bool liveIdentity = owlyVifIsTracked(newVif);
            rolledBack = detachVirtualInterface(newVif, true);
            if (rolledBack && liveIdentity) {
                const bool disabled = owlyVifEvent(
                    newVif, RTW89_FRONT_ROLE_AIRLINK_OBSERVED,
                    RTW89_FRONT_VIF_DISABLED);
                const bool destroyed = disabled && owlyVifEvent(
                    newVif, RTW89_FRONT_ROLE_AIRLINK_OBSERVED,
                    RTW89_FRONT_VIF_DESTROYED);
                backendGone = disabled && destroyed;
            } else if (rolledBack && !liveIdentity) {
                backendGone = true;
            }
            if (rolledBack) newVif->release();
        } else if (attached && !newVif) {
            rolledBack = false;
        }
        IOLockLock(_owlyVifLock);
        if (rolledBack) {
            _owlyAttachedAWDL = nullptr;
            _owlyAWDLPendingBSD = false;
            _owlyAWDLPendingChecks = 0;
            for (unsigned i = 0; i < 6; ++i) _owlyAWDLRequestMac[i] = 0;
            for (unsigned i = 0; i < 16; ++i) _owlyAWDLBSDName[i] = 0;
        } else {
            _owlyAttachedAWDL = attached ? newVif : nullptr;
        }
        if (!rolledBack || !backendGone || ambiguous)
            _owlyAWDLQuarantined = true;
        _owlyAWDLRequestBusy = false;
        IOLockUnlock(_owlyVifLock);
        setProperty("OWLY Gate14 rollback_ok", rolledBack && backendGone ? 1ULL : 0ULL, 32);
        setProperty("OWLY Gate14 pending_bsd", 0ULL, 32);
        LOG("OWLY ABI5: create declined attach=%u BSD=%u HW=%u AppleRollback=%u backRemoved=%u",
            (unsigned)attached, (unsigned)validBSD, (unsigned)acknowledged,
            (unsigned)rolledBack, (unsigned)backendGone);
        return kIOReturnNotReady;
    }

    IOLockLock(_owlyVifLock);
    _owlyAttachedAWDL = newVif;
    _owlyAWDLPendingBSD = false;
    _owlyAWDLPendingChecks = 0;
    for (unsigned i = 0; i < 6; ++i) _owlyAWDLRequestMac[i] = 0;
    for (unsigned i = 0; i < 16; ++i) {
        _owlyAWDLBSDName[i] = bsdSnapshot[i];
        req->bsd_name[i] = (uint8_t)bsdSnapshot[i];
    }
    _owlyAWDLRequestBusy = false;
    IOLockUnlock(_owlyVifLock);
    setProperty("OWLY Gate14 pending_bsd", 0ULL, 32);
#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
    __atomic_store_n(&_owlyGateC2Ready, 1, __ATOMIC_RELEASE);
    setProperty("OWLY C2 native_vif_ready", 1ULL, 32);
#endif
    LOG("OWLY G14 RC3: VIF attached and backend ACKed (NO DATA PATH)");
    return kIOReturnSuccess;
}

SInt32 AirPortRTW89Front::owlyRequestAWDLDelete(unsigned int type, void *data)
{
    if (type != SIOCSA80211 || !data || !_owlyVifLock)
        return kIOReturnBadArgument;
    OwlyM2DeleteRequest *req = static_cast<OwlyM2DeleteRequest *>(data);
    if (req->version != OWLY_GATE14_REQ94_VERSION) return kIOReturnBadArgument;
    IOLockLock(_owlyVifLock);
    if (_owlyAWDLStopping || _owlyAWDLRequestBusy || !_owlyAttachedAWDL
#if defined(OWLY_AWDL_SERVICE_LIFECYCLE) && OWLY_AWDL_SERVICE_LIFECYCLE
        || _owlyVifMethodBusy
#endif
    ) {
        IOLockUnlock(_owlyVifLock);
        return kIOReturnNotReady;
    }
    /* Pending object is owned by us but not yet named or ACKed. Only an
     * all-zero request95 name may cancel it; never match another interface. */
    const bool pendingBSD = _owlyAWDLPendingBSD;
    if (!_owlyAWDLBSDName[0] && !pendingBSD) {
        IOLockUnlock(_owlyVifLock);
        return kIOReturnNotReady;
    }
    bool matches = true;
    for (unsigned i = 0; i < 16; i++)
        matches &= req->bsd_name[i] == (uint8_t)(pendingBSD ? 0 : _owlyAWDLBSDName[i]);
    if (!matches) {
        IOLockUnlock(_owlyVifLock);
        return kIOReturnBadArgument;
    }
#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
    __atomic_store_n(&_owlyGateC2Ready, 0, __ATOMIC_RELEASE);
    setProperty("OWLY C2 native_vif_ready", 0ULL, 32);
#endif
    _owlyAWDLRequestBusy = true;
    IO80211VirtualInterface *target = _owlyAttachedAWDL;
    IOLockUnlock(_owlyVifLock);

    /* Snapshot the identity before Apple may free the object. This is purely
     * an opaque token; no pointer dereference after detach. */
    const bool tracked = owlyVifIsTracked(target);
    const bool detached = detachVirtualInterface(target, true);
    bool ackOK = !tracked; /* pending (unACKed) identity needs no backend events */
    if (detached && tracked) {
        /* These callbacks only accept opaque identity tokens, not objects. */
        const bool disabled = owlyVifEvent(target, RTW89_FRONT_ROLE_AIRLINK_OBSERVED,
                                            RTW89_FRONT_VIF_DISABLED);
        const bool destroyed = disabled && owlyVifEvent(
            target, RTW89_FRONT_ROLE_AIRLINK_OBSERVED, RTW89_FRONT_VIF_DESTROYED);
        ackOK = disabled && destroyed;
    }
    IOLockLock(_owlyVifLock);
    if (detached) {
        _owlyAttachedAWDL = nullptr;
        _owlyAWDLPendingBSD = false;
        _owlyAWDLPendingChecks = 0;
        for (unsigned i = 0; i < 6; ++i) _owlyAWDLRequestMac[i] = 0;
        for (unsigned i = 0; i < 16; i++) _owlyAWDLBSDName[i] = 0;
        if (!ackOK) _owlyAWDLQuarantined = true;
    }
    _owlyAWDLRequestBusy = false;
    IOLockUnlock(_owlyVifLock);
    if (detached) target->release(); /* matched own retain at create */
    if (!detached)
        LOG("OWLY M2.1: request95 detach failed; VIF retained for a retry");
    else if (!ackOK)
        LOG("OWLY M2.1: request95 detached but lifecycle ACK incomplete; quarantined");
    return !detached ? kIOReturnError : (ackOK ? kIOReturnSuccess : kIOReturnNotReady);
}
/* OWLY M2 REQUEST94 END */
#endif

/* Apple IO80211FamilyLegacy 1200.12.2b1 calls this virtual dispatch
 * during role-6 IO80211VirtualInterface::init()->attachToBpf().
 * Its inherited implementation returns 0x66 (ENOTSUP) unconditionally;
 * it is DISTINCT from apple80211Request() and apple80211_ioctl().
 * Bridge only the GET(12) capabilities query to the already-working STA
 * nativeRequest() implementation. Never invent AWDL capabilities or ACK
 * any AWDL TX/RX/configuration request. The caller owns the kernel buffer. */
SInt32 AirPortRTW89Front::apple80211VirtualRequest(UInt type, int number,
                                                    IO80211VirtualInterface *vif, void *data)
{
#if OWLY_GATE14_REAL_VIF
    if (type == SIOCGA80211 && number == APPLE80211_IOC_CARD_CAPABILITIES &&
        vif && data && _netif &&
        vif->getInterfaceRole() == RTW89_FRONT_ROLE_AIRLINK_OBSERVED) {
        setProperty("OWLY ABI5Cap12 request_seen", 1ULL, 32);
        /* This calls the real backend with the original, initialized
         * Apple caller-owned capability buffer. No copyIn/copyOut here. */
        const SInt32 rc = apple80211Request(type, number, _netif, data);
        setProperty("OWLY ABI5Cap12 backend_rc",
                    static_cast<unsigned long long>(static_cast<uint32_t>(rc)), 32);
        setProperty("OWLY ABI5Cap12 success", rc == kIOReturnSuccess ? 1ULL : 0ULL, 32);
        return rc;
    }
#endif
#if defined(OWLY_AWDL_SOFTWARE_SYNC) && OWLY_AWDL_SOFTWARE_SYNC
    /* The virtual radio shares the station's power, regulatory channels and
     * hardware HT subset. The native peer manager queries these during
     * configure, before the VIF is tracked. Forward the backend answer and
     * buffer through the primary interface without starting a session. */
    if (type==SIOCGA80211 &&
        (number==APPLE80211_IOC_POWER || number==APPLE80211_IOC_SUPPORTED_CHANNELS ||
         number==APPLE80211_IOC_HT_CAPABILITY) &&
        vif && data && _netif &&
        vif->getInterfaceRole()==RTW89_FRONT_ROLE_AIRLINK_OBSERVED) {
        const SInt32 rc=apple80211Request(type,number,_netif,data);
        setProperty(number==APPLE80211_IOC_HT_CAPABILITY ? "OwlyAWDLHTCapabilityResult" :
                    number==APPLE80211_IOC_POWER ? "OwlyAWDLPowerQueryResult" :
                    "OwlyAWDLChannelsQueryResult",
                    static_cast<unsigned long long>(static_cast<uint32_t>(rc)),32);
        return rc;
    }
    const bool syncRequest =
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        (type==SIOCSA80211 && (number==APPLE80211_IOC_AWDL_OOB_AUTO_REQUEST ||
                             number==APPLE80211_IOC_AWDL_OOB_REQUEST)) ||
#endif
        number==APPLE80211_IOC_AWDL_SYNC_ENABLED ||
        number==APPLE80211_IOC_AWDL_SYNC_FRAME_TEMPLATE ||
        owly_cfg_known(static_cast<unsigned>(number));
    if (syncRequest && (type==SIOCGA80211 || type==SIOCSA80211) && vif && data &&
        _owlyVifLock && vif->getInterfaceRole()==RTW89_FRONT_ROLE_AIRLINK_OBSERVED) {
        IOLockLock(_owlyVifLock);
        const bool ours=!_owlyAWDLStopping && _owlyAttachedAWDL==vif && !_owlyAWDLPendingBSD;
        IOLockUnlock(_owlyVifLock);
        if (ours) {
            const bool there=backEnter();
            const SInt32 rc=there && _back.request ?
                _back.request(_back.ctx,type,number,vif,data) : kIOReturnNotReady;
            backLeave();
            if (owly_cfg_known(static_cast<unsigned>(number))) {
                setProperty("OwlyNativeConfigLastRequest",static_cast<unsigned long long>(number),32);
                setProperty("OwlyNativeConfigLastType",type==SIOCSA80211 ? 1ULL : 0ULL,32);
                setProperty("OwlyNativeConfigLastResult",static_cast<unsigned long long>(static_cast<uint32_t>(rc)),32);
            }
            return rc;  // Never fall back into the family after a backend refusal.
        }
        return kIOReturnNotReady;
    }
#elif defined(OWLY_ABI6_GET117_CONTRACT) && OWLY_ABI6_GET117_CONTRACT
    /* wifip2pd GET(117) against awdl0.  The current driver DOES NOT
     * synchronize the AWDL radio.  Answer the 12-byte status truthfully
     * (enabled=0); do not assert a live AWDL session, touch RF, or ACK SET.
     * This only repairs a missing status query in the virtual path.
     */
    if (type == SIOCGA80211 && number == APPLE80211_IOC_AWDL_SYNC_ENABLED &&
        vif && data && _owlyVifLock &&
        vif->getInterfaceRole() == RTW89_FRONT_ROLE_AIRLINK_OBSERVED) {
        IOLockLock(_owlyVifLock);
        const bool ours = !_owlyAWDLStopping && (_owlyAttachedAWDL == vif);
        IOLockUnlock(_owlyVifLock);
        if (ours) {
            static_assert(sizeof(apple80211_awdl_sync_enabled) == 12,
                          "Unexpected Apple80211 GET117 buffer ABI");
            auto *s = static_cast<apple80211_awdl_sync_enabled *>(data);
            s->version = APPLE80211_VERSION;
            s->unk1 = 0;
            s->enabled = 0; /* NO AWDL RF synchronization currently exists. */
            setProperty("OWLY GET117 truthful_disabled", 1ULL, 32);
            return kIOReturnSuccess;
        }
    }
#endif
    return super::apple80211VirtualRequest(type, number, vif, data);
}

/* The legacy family has separate virtual slots for Skywalk. Its two-argument
 * SET wrapper jumps straight to its own parser, bypassing our legacy-interface
 * override. Bridge only scans addressed to this station; preserve all other
 * Skywalk requests on the original family path. */
static bool stationScan(IO80211Interface *interface, const void *data)
{
    if (version_major < 23 || !interface || !data)
        return false;
    const auto *req = static_cast<const apple80211req *>(data);
    if (req->req_type != APPLE80211_IOC_SCAN_REQ &&
        req->req_type != APPLE80211_IOC_SCAN_REQ_MULTIPLE)
        return false;
    char name[IFNAMSIZ] = {};
    const char *prefix = interface->getNamePrefix();
    if (!prefix)
        return false;
    snprintf(name, sizeof(name), "%s%u", prefix, interface->getUnitNumber());
    return !strncmp(name, req->req_if_name, sizeof(name));
}

SInt32 AirPortRTW89Front::apple80211_ioctl(IO80211SkywalkInterface *skywalk,
                                           unsigned long cmd, void *data)
{
    if (cmd == SIOCSA80211 || cmd == 0x802869c8UL) {
        bool handled = false;
        SInt32 ret = 0;
        const bool there = backEnter();
        if (there && stationScan(_netif, data) && _back.ioctl)
            ret = _back.ioctl(_back.ctx, _netif, nullptr, nullptr, cmd, data, &handled);
        backLeave();
        if (handled && ret != EFAULT)
            return ret;
    }
    return super::apple80211_ioctl(skywalk, cmd, data);
}

SInt32 AirPortRTW89Front::apple80211_ioctl_set(IO80211SkywalkInterface *skywalk, void *data)
{
    bool handled = false;
    SInt32 ret = 0;
    const bool there = backEnter();
    if (there && stationScan(_netif, data) && _back.ioctl_set)
        ret = _back.ioctl_set(_back.ctx, _netif, nullptr, skywalk, data, &handled);
    backLeave();
    if (handled && ret != EFAULT)
        return ret;
    return super::apple80211_ioctl_set(skywalk, data);
}

SInt32 AirPortRTW89Front::apple80211Request(unsigned int type, int number,
                                            IO80211Interface *interface, void *data)
{
    owlyGate12FHit(this, "OWLY Gate12F request_any", &gOwlyFRequestAny);
    if (number == APPLE80211_IOC_VIRTUAL_IF_CREATE)
        owlyGate12FHit(this, "OWLY Gate12F request94", &gOwlyFRequest94);
    else if (number == APPLE80211_IOC_VIRTUAL_IF_DELETE)
        owlyGate12FHit(this, "OWLY Gate12F request95", &gOwlyFRequest95);
    /* OWLY_GATE13A_PROBE_BEGIN: request94 entry, no payload/req_data accesses.
     * A non-null, 8-byte-aligned address is NOT proof of kernel residency.
     */
    if (number == APPLE80211_IOC_VIRTUAL_IF_CREATE) {
        owlyGate12FHit(this, "OWLY Gate13A 94_seen", &gOwly13A94Seen);
        if (type == SIOCSA80211)
            owlyGate12FHit(this, "OWLY Gate13A 94_type_set", &gOwly13A94TypeSet);
        else
            owlyGate12FHit(this, "OWLY Gate13A 94_type_other", &gOwly13A94TypeOther);
        if (interface && _netif && interface == _netif)
            owlyGate12FHit(this, "OWLY Gate13A 94_primary", &gOwly13A94Primary);
        else
            owlyGate12FHit(this, "OWLY Gate13A 94_not_primary", &gOwly13A94NotPrimary);
        if (data) {
            owlyGate12FHit(this, "OWLY Gate13A 94_data_nonnull", &gOwly13A94DataNonNull);
            if ((reinterpret_cast<uintptr_t>(data) & 7U) == 0)
                owlyGate12FHit(this, "OWLY Gate13A 94_data_aligned8", &gOwly13A94DataAligned8);
            else
                owlyGate12FHit(this, "OWLY Gate13A 94_data_unaligned8", &gOwly13A94DataUnaligned8);
        } else {
            owlyGate12FHit(this, "OWLY Gate13A 94_data_null", &gOwly13A94DataNull);
        }
    }
    /* OWLY_GATE13A_PROBE_END */
    /* OWLY_GATE13B_PROBE_BEGIN: experimental limited kernel-stack read.
     * Instrument the exact matched IO80211FamilyLegacy 94 primary path ONLY.
     * Never call on a different Apple Legacy binary. Conditions alone do not
     * prove safety if another caller directly invokes apple80211Request().
     */
#if OWLY_GATE13B_PAYLOAD_PROBE
    if (number == APPLE80211_IOC_VIRTUAL_IF_CREATE &&
        type == SIOCSA80211 && interface && _netif && interface == _netif &&
        data && ((reinterpret_cast<uintptr_t>(data) & 7U) == 0U)) {
        owlyGate12FHit(this, "OWLY Gate13B 94_eligible", &gOwly13B94_eligible);
        const OwlyGate13AExpectedCreateLayout *req =
            static_cast<const OwlyGate13AExpectedCreateLayout *>(data);
        /* Read at offsets 0 and 12 only, within Apple's zeroed 32-byte local. */
        const uint32_t version = req->version;
        const uint32_t role = req->role;
        /* OWLY_GATE13C_VERSION_VALUE: publish only the already-read 32-bit
         * version, without any new payload dereference, pointer or MAC data.
         * IOCTL94 volume is very low; keep the last observed numeric value.
         * UINT32_MAX is the initialization sentinel, not a valid observation.
         */
        setProperty("OWLY Gate13C 94_version_value", static_cast<unsigned long long>(version), 32);
        const bool versionOK = version == APPLE80211_VERSION;
        const bool role6 = role == RTW89_FRONT_ROLE_AIRLINK_OBSERVED;
        if (versionOK)
            owlyGate12FHit(this, "OWLY Gate13B 94_version_expected", &gOwly13B94_version_expected);
        else
            owlyGate12FHit(this, "OWLY Gate13B 94_version_other", &gOwly13B94_version_other);
        if (role6)
            owlyGate12FHit(this, "OWLY Gate13B 94_role6", &gOwly13B94_role6);
        else
            owlyGate12FHit(this, "OWLY Gate13B 94_role_other", &gOwly13B94_role_other);
        if (versionOK && role6)
            owlyGate12FHit(this, "OWLY Gate13B 94_combo_expected", &gOwly13B94_combo_expected);
    }
#endif
    /* OWLY_GATE13B_PROBE_END */
#if OWLY_GATE12_TRACE_ONLY && !OWLY_GATE14_REAL_VIF
    if (number == APPLE80211_IOC_VIRTUAL_IF_CREATE ||
        number == APPLE80211_IOC_VIRTUAL_IF_DELETE) {
        const SInt32 seq = OSIncrementAtomic(&gOwlyG12Request);
        if (seq < 64)
            LOG("OWLY Gate12: request ENTER/REFUSE seq=%d number=%d primary=%u data=%u",
                (int)seq, number, interface == _netif ? 1U : 0U, data ? 1U : 0U);
        return kIOReturnUnsupported; /* No create, detach, copyin or copyout. */
    }
#endif
    /* The legacy Apple IOCTL94/95 handlers delegate to this virtual request.
     * Do not send these two operations into the hardware backend's ordinary
     * station request table; create/attach is owned by the IO80211 frontend. */
#if OWLY_GATE14_REAL_VIF
    if (number == APPLE80211_IOC_VIRTUAL_IF_CREATE ||
        number == APPLE80211_IOC_VIRTUAL_IF_DELETE) {
        /* Only Apple's measured primary-interface SET request route; refuse
         * unexpected dispatch; never inspect a userspace ioctl envelope. */
        if (type != SIOCSA80211 || !interface || interface != _netif ||
            !data || ((reinterpret_cast<uintptr_t>(data) & 7U) != 0U))
            return kIOReturnUnsupported;
        if (!_workLoop || !_owlyVifLock) return kIOReturnNotReady;
        struct RequestCall { unsigned type; int number; void *data; SInt32 result; };
        RequestCall call = { type, number, data, kIOReturnNotReady };
        retain(); /* stop/free cannot invalidate controller while gate is queued */
        IOWorkLoop *loop = _workLoop;
        loop->retain();
        const IOReturn rc = loop->runAction(
            [](OSObject *owner, void *opaque, void *, void *, void *) -> IOReturn {
                AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(owner);
                RequestCall *args = static_cast<RequestCall *>(opaque);
                args->result = args->number == APPLE80211_IOC_VIRTUAL_IF_CREATE ?
                    self->owlyRequestAWDLCreate(args->type, args->data) :
                    self->owlyRequestAWDLDelete(args->type, args->data);
                return kIOReturnSuccess;
            }, this, &call);
        loop->release();
        /* runAction has returned, so a nested stop can now finish without
         * destroying the workloop gate while its action is still running. */
        owlyFinishDeferredStop();
        release();
        return rc == kIOReturnSuccess ? call.result : (SInt32)rc;
    }
#endif
    SInt32 ret = ENXIO;     /* nobody there to ask */

    const bool there = backEnter();
    if (there)
        ret = _back.request(_back.ctx, type, number, interface, data);
    backLeave();
    /* Numeric 94 was observed as APPLE80211_IOC_VIRTUAL_IF_CREATE in Tahoe logs.
     * This probe does not dereference the request or modify its result. */
    if (number == 94 && OSIncrementAtomic(&gOwlyG09Request94) < 48)
        LOG("OWLY Gate09: apple80211Request type=0x%x number=94 backend=%u rc=%d",
            type, there ? 1U : 0U, (int)ret);
    return ret;
}

IOReturn AirPortRTW89Front::enable(IONetworkInterface *iface)
{
    IOReturn ret = kIOReturnSuccess;

    const bool there = backEnter();
    if (there && _back.enable)
        ret = _back.enable(_back.ctx, true) ? kIOReturnError : kIOReturnSuccess;
    backLeave();
    if (ret != kIOReturnSuccess)
        return ret;

    ret = super::enable(iface);
    if (ret == kIOReturnSuccess) {
        IOOutputQueue *queue = getOutputQueue();

        if (queue)
            queue->service(IOBasicOutputQueue::kServiceAsync);
    }
    return ret;
}

IOReturn AirPortRTW89Front::disable(IONetworkInterface *iface)
{
    IOReturn ret = super::disable(iface);

    const bool there = backEnter();
    if (there && _back.enable)
        _back.enable(_back.ctx, false);
    backLeave();
    IO80211Controller::setLinkStatus(kIONetworkLinkValid | kIONetworkLinkNoNetworkChange);
    return ret;
}

UInt32 AirPortRTW89Front::outputPacket(mbuf_t m, void *param)
{
    UInt32 ret;

    const bool there = backEnter();
    if (there) {
        ret = _back.output(_back.ctx, m);
    } else {
        if (m)
            mbuf_freem(m);
        ret = kIOReturnOutputDropped;
    }
    backLeave();
    return ret;
}

/* ------------------------------------------------------------------ */
/*  What a controller has to answer itself                              */
/* ------------------------------------------------------------------ */

const OSString *AirPortRTW89Front::newVendorString() const
{
    return OSString::withCString("Realtek");
}

const OSString *AirPortRTW89Front::newModelString() const
{
    /* Modified 2026-11-15: display branding; retain the detected Realtek chip. */
    char model[96];
    snprintf(model, sizeof(model), "RTLAirLink (%s)",
             rtw89_chip_name(_pci ? _pci->configRead16(kIOPCIConfigDeviceID) : 0));
    return OSString::withCString(model);
}

IONetworkInterface *AirPortRTW89Front::createInterface()
{
    AirPortRTW89FrontInterface *interface = OSTypeAlloc(AirPortRTW89FrontInterface);

    if (interface && !interface->init(this)) {
        interface->release();
        interface = nullptr;
    }
    return interface;
}

/* OWLY_NATIVEFRONT_VIF_OBSERVER_BEGIN
 * Passive native IO80211 VIF lifecycle interception (no new VIF is made here).
 * Intentionally no outputStart/requestPacketTx/Skywalk or backend P2P binding.
 * These are Apple callbacks; use the inherited implementation unchanged.
 */
/* OWLY_NATIVE_IDENTITY_BRIDGE_BEGIN */
#if defined(RTW89_AWDL_NATIVE_FRONT_OBSERVE) && RTW89_AWDL_NATIVE_FRONT_OBSERVE
/* ABI4.1: This checks only our previously ACKed opaque AirLink identity.
 * Do not guess a role for other Apple virtual interfaces. */
bool AirPortRTW89Front::owlyVifIsTracked(IO80211VirtualInterface *vif)
{
    if (!_owlyVifLock || !vif) return false;
    IOLockLock(_owlyVifLock);
    const bool tracked = _owlyAirlink.cookie == vif &&
                         _owlyAirlink.role == RTW89_FRONT_ROLE_AIRLINK_OBSERVED;
    IOLockUnlock(_owlyVifLock);
    return tracked;
}

/* The callback MUST NOT run under _owlyVifLock: a callback can reenter
 * IO80211 or disconnect. Reserve one in-flight transaction under the lock,
 * release it for the backend call, and commit only after ACK. Reentrancy
 * fails closed instead of blocking. backEnter() is done BEFORE taking the
 * local lock, so disconnectBack() can drain before resetting identity.
 * Neither this path nor ABI4 supplies a Skywalk/AWDL data path. */
bool AirPortRTW89Front::owlyVifEventOnGate(IO80211VirtualInterface *vif, UInt role, uint32_t event,
                                                const uint8_t request_mac[6])
{
    if (!_owlyVifLock || !vif) return false;
    const bool there = backEnter();
    if (!there) {
        backLeave();
        LOG("OWLY ABI4.1: backend disconnected, event=%u rejected", (unsigned int)event);
        return false;
    }
    IOLockLock(_owlyVifLock);
    if (_owlyVifBusy) {
        IOLockUnlock(_owlyVifLock);
        backLeave();
        LOG("OWLY ABI4.1: in-flight event, event=%u rejected", (unsigned int)event);
        return false;
    }
    struct rtw89_front_native_vif_state next = _owlyAirlink;
    if (!rtw89_front_native_vif_update(&next, vif, role, event)) {
        IOLockUnlock(_owlyVifLock);
        backLeave();
        LOG("OWLY ABI4.1: invalid VIF transition event=%u", (unsigned int)event);
        return false;
    }
    _owlyVifBusy = true;
    IOLockUnlock(_owlyVifLock);

    const bool accepted = _back.vif_event &&
                          _back.vif_event(_back.ctx, vif, role, event, request_mac);

    IOLockLock(_owlyVifLock);
    if (accepted) {
        _owlyAirlink = next;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        if (event==RTW89_FRONT_VIF_DISABLED && vif==_owlyNativePeerVif) {
            _owlyNativeEnabled=false;
            _owlyNativeEnableIssued=false;
            _owlyNativeHaveWindow=false;
        }
#endif
    }
    _owlyVifBusy = false;
    IOLockUnlock(_owlyVifLock);
    backLeave();
    if (!accepted)
        LOG("OWLY ABI4.1: backend NACK event=%u", (unsigned int)event);
    return accepted;
}

bool AirPortRTW89Front::owlyVifEvent(IO80211VirtualInterface *vif, UInt role, uint32_t event,
                                       const uint8_t request_mac[6])
{
    if (!_workLoop) return false;
    struct VifCall {
        IO80211VirtualInterface *vif;
        UInt role;
        uint32_t event;
        bool result;
        bool has_mac;
        uint8_t mac[6];
    };
    VifCall call = { vif, role, event, false, request_mac != nullptr, {} };
    if (request_mac)
        for (unsigned i = 0; i < 6; ++i) call.mac[i] = request_mac[i];
    /* The caller/IO80211 must already own the VIF. Never dereference a
     * detached object: callback uses only the opaque identity token. */
    const IOReturn rc = _workLoop->runAction(
        [](OSObject *owner, void *opaque, void *, void *, void *) -> IOReturn {
            AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(owner);
            VifCall *args = static_cast<VifCall *>(opaque);
            args->result = self->owlyVifEventOnGate(args->vif, args->role, args->event,
                                                 args->has_mac ? args->mac : nullptr);
            return kIOReturnSuccess;
        }, this, &call);
    return rc == kIOReturnSuccess && call.result;
}

IO80211VirtualInterface *AirPortRTW89Front::createVirtualInterface(struct ether_addr *address,
                                                                    UInt role)
{
    if (role == RTW89_FRONT_ROLE_AIRLINK_OBSERVED)
        owlyGate12FHit(this, "OWLY Gate12F role6_factory", &gOwlyFRole6);
#if OWLY_GATE12_TRACE_ONLY && !OWLY_GATE14_REAL_VIF
    if (role == RTW89_FRONT_ROLE_AIRLINK_OBSERVED) {
        const SInt32 seq = OSIncrementAtomic(&gOwlyG12VifFactory);
        if (seq < 32)
            LOG("OWLY Gate12: role6 factory REFUSED seq=%d mac_arg=%u",
                (int)seq, address ? 1U : 0U);
        return nullptr; /* Diagnostic must not allocate an AirLink VIF. */
    }
#endif
    IO80211VirtualInterface *vif = nullptr;
    if (role == RTW89_FRONT_ROLE_AIRLINK_OBSERVED) {
        /* Role 6 is AWDL. The original P2P subclass trials were made
         * BEFORE the Apple Virtual GET12 / Cap12 bridge was fixed. Their
         * init failures are not sufficient evidence the subclass is invalid.
         * CAP12 was subsequently observed working; retry the subclass ONLY
         * as a compile-time opt-in, with the existing init/attach/rollback.
         * A successful init remains INSUFFICIENT to prove AWDL RX/TX. */
        if (!address) {
            owlyGate12FHit(this, "OWLY ABI5Diag factory_no_mac", &gOwlyDiagFNoMac);
            setProperty("OWLY ABI5Diag factory_last", 1ULL, 32);
            LOG("OWLY M1: refusing AirLink VIF without MAC address");
            return nullptr;
        }
#if OWLY_ABI6_NATIVE_P2P_FACTORY
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        IO80211VirtualInterface *airlink = OSTypeAlloc(OwlyNativeP2PInterface);
#else
        IO80211VirtualInterface *airlink = OSTypeAlloc(IO80211P2PInterface);
#endif
#else
        IO80211VirtualInterface *airlink = OSTypeAlloc(IO80211VirtualInterface);
#endif
        if (airlink) {
            if (airlink->init(this, address, role, "awdl")) {
                vif = airlink;
                owlyGate12FHit(this, "OWLY ABI5Diag factory_ready", &gOwlyDiagFReady);
                setProperty("OWLY ABI5Diag factory_last", 4ULL, 32);
            } else {
                owlyGate12FHit(this, "OWLY ABI5Diag factory_init_fail", &gOwlyDiagFInitFail);
                setProperty("OWLY ABI5Diag factory_last", 3ULL, 32);
                airlink->release();
            }
        } else {
            owlyGate12FHit(this, "OWLY ABI5Diag factory_alloc_fail", &gOwlyDiagFAllocFail);
            setProperty("OWLY ABI5Diag factory_last", 2ULL, 32);
        }
#if OWLY_ABI6_NATIVE_P2P_FACTORY
        LOG("OWLY ABI6: role6 P2P SUBCLASS factory object=%s (NO NATIVE RX/TX)",
            vif ? "yes" : "no");
#else
        LOG("OWLY M1: role6 BASE factory object=%s", vif ? "yes" : "no");
#endif
    } else {
        /* All other Apple role behaviour remains exactly inherited. */
        vif = super::createVirtualInterface(address, role);
    }
    LOG("OWLY ABI4.1: createVirtualInterface role=%u object=%s",
        (unsigned int)role, vif ? "yes" : "no");
    /* M2: do NOT ACK a class object before Apple has attached it.  A failed
     * attach releases this object internally and must leave backend identity
     * empty.  The IOCTL create transaction ACKs after attach succeeds. */
    return vif;
}

/* Apple may enable/disable a VIF without a request95 transaction. Serialize
 * both operations with IOCTL94/95 and stop on the *same* workloop gate. */
SInt32 AirPortRTW89Front::enableVirtualInterface(IO80211VirtualInterface *interface)
{
    if (!_workLoop || !_owlyVifLock) return kIOReturnNotReady;
    retain();
    IOWorkLoop *loop = _workLoop;
    loop->retain();
    struct Args { IO80211VirtualInterface *vif; SInt32 result; } args = { interface, kIOReturnNotReady };
    const IOReturn rc = loop->runAction(
        [](OSObject *owner, void *opaque, void *, void *, void *) -> IOReturn {
            AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(owner);
            Args *a = static_cast<Args *>(opaque);
            a->result = self->owlyEnableVirtualInterfaceOnGate(a->vif);
            return kIOReturnSuccess;
        }, this, &args);
    loop->release();
    owlyFinishDeferredStop();
    release();
    return rc == kIOReturnSuccess ? args.result : (SInt32)rc;
}

SInt32 AirPortRTW89Front::disableVirtualInterface(IO80211VirtualInterface *interface)
{
    if (!_workLoop || !_owlyVifLock) return kIOReturnNotReady;
    retain();
    IOWorkLoop *loop = _workLoop;
    loop->retain();
    struct Args { IO80211VirtualInterface *vif; SInt32 result; } args = { interface, kIOReturnNotReady };
    const IOReturn rc = loop->runAction(
        [](OSObject *owner, void *opaque, void *, void *, void *) -> IOReturn {
            AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(owner);
            Args *a = static_cast<Args *>(opaque);
            a->result = self->owlyDisableVirtualInterfaceOnGate(a->vif);
            return kIOReturnSuccess;
        }, this, &args);
    loop->release();
    owlyFinishDeferredStop();
    release();
    return rc == kIOReturnSuccess ? args.result : (SInt32)rc;
}

SInt32 AirPortRTW89Front::owlyEnableVirtualInterfaceOnGate(IO80211VirtualInterface *interface)
{
    IOLockLock(_owlyVifLock);
    if (_owlyAWDLStopping || _owlyVifMethodBusy) {
        IOLockUnlock(_owlyVifLock);
        return kIOReturnNotReady;
    }
    _owlyVifMethodBusy = true;
    IOLockUnlock(_owlyVifLock);

    SInt32 ret = super::enableVirtualInterface(interface);
    LOG("OWLY M2.2: enableVirtualInterface inherited=0x%x", (unsigned int)ret);
    if (ret == kIOReturnSuccess && interface && owlyVifIsTracked(interface) &&
        !owlyVifEvent(interface, RTW89_FRONT_ROLE_AIRLINK_OBSERVED,
                      RTW89_FRONT_VIF_ENABLED)) {
        LOG("OWLY M2.2: AirLink enable NACK; rolling back Apple enable");
        SInt32 undo = super::disableVirtualInterface(interface);
        if (undo != kIOReturnSuccess)
            LOG("OWLY M2.2: Apple enable rollback failed rc=%d", (int)undo);
        ret = kIOReturnNotReady;
    }
    IOLockLock(_owlyVifLock);
    _owlyVifMethodBusy = false;
    IOLockUnlock(_owlyVifLock);
    return ret;
}

SInt32 AirPortRTW89Front::owlyDisableVirtualInterfaceOnGate(IO80211VirtualInterface *interface)
{
    IOLockLock(_owlyVifLock);
    /* Apple invokes disable while detachVirtualInterface is running,
     * including on the stop path. Do not block the teardown itself. */
    if (_owlyVifMethodBusy) {
        IOLockUnlock(_owlyVifLock);
        return kIOReturnNotReady;
    }
    _owlyVifMethodBusy = true;
    IOLockUnlock(_owlyVifLock);

#if defined(OWLY_AWDL_SERVICE_LIFECYCLE) && OWLY_AWDL_SERVICE_LIFECYCLE
    if (interface && owlyVifIsTracked(interface)) {
        interface->IO80211VirtualInterface::setEnabledBySystem(false);
        interface->IO80211VirtualInterface::setLinkState(kIO80211NetworkLinkDown, 1);
        setProperty("OwlyServiceCarrierPrepared", 0ULL, 32);
        setProperty("OwlyServiceSystemEnableRequested", 0ULL, 32);
    }
#endif
    if (interface && owlyVifIsTracked(interface) &&
        !owlyVifEvent(interface, RTW89_FRONT_ROLE_AIRLINK_OBSERVED,
                      RTW89_FRONT_VIF_DISABLED))
        LOG("OWLY M2.2: AirLink disable NACK; backend state unverified");
    SInt32 ret = super::disableVirtualInterface(interface);
    LOG("OWLY M2.2: disableVirtualInterface inherited=0x%x", (unsigned int)ret);
    IOLockLock(_owlyVifLock);
    _owlyVifMethodBusy = false;
    IOLockUnlock(_owlyVifLock);
    return ret;
}
#endif
/* OWLY_NATIVE_IDENTITY_BRIDGE_END */
/* OWLY_NATIVEFRONT_VIF_OBSERVER_END */

IOReturn AirPortRTW89Front::selectMedium(const IONetworkMedium *medium)
{
    if (!medium)
        return kIOReturnBadArgument;
    setSelectedMedium(medium);
    return kIOReturnSuccess;
}

IOReturn AirPortRTW89Front::getHardwareAddress(IOEthernetAddress *addr)
{
    if (!addr)
        return kIOReturnBadArgument;
    *addr = _mac;
    return kIOReturnSuccess;
}

IOReturn AirPortRTW89Front::setHardwareAddress(const IOEthernetAddress *addr)
{
    IOReturn ret = kIOReturnNotReady;

    if (!addr)
        return kIOReturnBadArgument;
    /* CoreWiFi sets a per-network private address before it asks to join */
    const bool there = backEnter();
    if (there && _back.set_mac)
        ret = _back.set_mac(_back.ctx, addr->bytes) ? kIOReturnError : kIOReturnSuccess;
    backLeave();
    if (ret == kIOReturnSuccess)
        _mac = *addr;
    return ret;
}

IOReturn AirPortRTW89Front::getHardwareAddressForInterface(IO80211Interface *iface,
                                                          IOEthernetAddress *addr)
{
    return getHardwareAddress(addr);
}

IOReturn AirPortRTW89Front::getPacketFilters(const OSSymbol *group, UInt32 *filters) const
{
    if (!group || !filters)
        return kIOReturnBadArgument;
    if (group == gIONetworkFilterGroup) {
        *filters = kIOPacketFilterMulticast | kIOPacketFilterPromiscuous;
        return kIOReturnSuccess;
    }
    return IOEthernetController::getPacketFilters(group, filters);
}

IOReturn AirPortRTW89Front::setMulticastMode(bool active)
{
    return kIOReturnSuccess;    /* the chip takes all multicast frames of the network */
}

IOReturn AirPortRTW89Front::setMulticastList(IOEthernetAddress *addrs, UInt32 count)
{
    return kIOReturnSuccess;
}

IOReturn AirPortRTW89Front::setPromiscuousMode(bool active)
{
    return kIOReturnSuccess;
}

SInt32 AirPortRTW89Front::stopDMA()
{
    /* Called at shutdown: the driver hears of it through power(false). */
    return kIOReturnSuccess;
}

UInt32 AirPortRTW89Front::hardwareOutputQueueDepth(IO80211Interface *interface)
{
    return 0;
}

SInt32 AirPortRTW89Front::performCountryCodeOperation(IO80211Interface *interface,
                                                      IO80211CountryCodeOp op)
{
    return kIOReturnSuccess;
}

SInt32 AirPortRTW89Front::enableFeature(IO80211FeatureCode feature, void *data)
{
    return feature == kIO80211Feature80211n ? kIOReturnSuccess : 102;
}

SInt32 AirPortRTW89Front::monitorModeSetEnabled(IO80211Interface *interface, bool enabled,
                                                UInt32 mode)
{
    return kIOReturnSuccess;
}
