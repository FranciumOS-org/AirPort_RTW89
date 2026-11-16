/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AirPort_RTW89: the IOKit side of the driver.
 *
 * Current scope: match the RTL8852BE, hand the platform services (config
 * space, BAR 2, DMA memory, the interrupt) to the Linux side through
 * rtw89_glue.h and let the driver's own probe() bring the chip up once. The
 * radio is started, a scan run and a network joined on request (setProperties,
 * used by tools/rtw89ctl).
 *
 * To the rest of macOS the card is an Ethernet controller: it publishes an
 * IOEthernetInterface (enX) whose link comes up once a network is joined and
 * its keys are in place. Frames are converted to and from 802.11 on the Linux
 * side (rtw89_data.c). Nothing here is Wi-Fi as far as the system can tell,
 * so there is no Wi-Fi menu; that needs IO80211Family and comes later.
 */
#pragma once

#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOService.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IONetworkMedium.h>
#include <IOKit/network/IOOutputQueue.h>
#include <IOKit/network/IONetworkStats.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <kern/thread_call.h>

#include "rtw89_glue.h"
#include "../front/rtw89_front_api.h"
#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
#include "owly_abi6_rx_gate.h"
#endif

struct apple80211req;

class AirPort_RTW89 : public IOEthernetController {
    OSDeclareDefaultStructors(AirPort_RTW89)

public:
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    void free() override;

    /* IONetworkController */
    bool createWorkLoop() override;
    IOWorkLoop *getWorkLoop() const override;
    bool configureInterface(IONetworkInterface *netif) override;
    IOReturn enable(IONetworkInterface *netif) override;
    IOReturn disable(IONetworkInterface *netif) override;
    UInt32 outputPacket(mbuf_t m, void *param) override;
    IOReturn outputStart(IONetworkInterface *netif, IOOptionBits options) override;
    const OSString *newVendorString() const override;
    const OSString *newModelString() const override;

    /* IOEthernetController */
    IOReturn getHardwareAddress(IOEthernetAddress *addr) override;
    IOReturn getPacketFilters(const OSSymbol *group, UInt32 *filters) const override;
    IOReturn setPromiscuousMode(bool active) override;
    IOReturn setMulticastMode(bool active) override;
    IOReturn setMulticastList(IOEthernetAddress *addrs, UInt32 count) override;

    /* { "RTW89Command" = "up" | "down" | "scan" | "results" | "leave" | "flush-on" | "flush-off" |
     *                    "ax-on" | "ax-off" | "rejoin-on" | "rejoin-off" | "probe" | "drop" }, or
     * { "RTW89Command" = "join", "RTW89SSID" = <data> [, "RTW89Passphrase" = <data>] }.
     * Administrators only. */
    IOReturn setProperties(OSObject *properties) override;

private:
    bool setupInterrupt();
    bool setupInterface();
    void interruptOccurred(IOInterruptEventSource *source, int count);
    void publishInfo();
    void publishScanResults();
    void publishLink();
    void teardown();

    /* rtw89_glue_platform callbacks; ctx is the AirPort_RTW89 instance. */
    static uint32_t cfgRead(void *ctx, unsigned int offset, unsigned int width);
    static void cfgWrite(void *ctx, unsigned int offset, unsigned int width,
                         uint32_t value);
    static void *dmaAlloc(void *ctx, size_t size, uint64_t *busAddr, void **cookie);
    static void dmaFree(void *ctx, void *cookie);
    static void irqEnable(void *ctx, bool enable);
    static void linkChanged(void *ctx);
    static void rxFrame(void *ctx, const uint8_t *frame, size_t len);
    static void txWake(void *ctx);
    bool transmit(mbuf_t m);

    /* Native Wi-Fi (AirPortRTW89Native.cpp): connected to AirPortRTW89Front
     * instead of publishing an Ethernet interface. */
    struct NativeState;
    bool connectFront();
    void disconnectFront();
    void nativeRxFrame(const uint8_t *frame, size_t len);
    void nativeTxWake();
    void nativeLink(const struct rtw89_glue_link &link);
    void nativeNotify(UInt32 events);
    void nativeEvents();
    static void nativeEventsCall(thread_call_param_t self, thread_call_param_t);
    void nativePost(unsigned int msg, void *data = nullptr, size_t len = 0);
    /* macOS asks again whether the radio is on */
    void nativePowerChanged();
    static bool frontExpected();
    int nativeRequest(bool isSet, int number, void *data);
    int nativeAwdlSyncRequest(bool isSet, int number, void *data);
    bool nativeAwdlGetEnvelope(void *interface, void *vif, unsigned long cmd,
                               void *data, int *result);
    int nativeAssociate(void *data);
    bool nativeJoinEnvelope(struct apple80211req *req, int *result);
    static void scanDone(void *ctx, bool aborted);
    static void backGetMac(void *ctx, uint8_t mac[6]);
    static int backSetMac(void *ctx, const uint8_t mac[6]);
    static int backRequest(void *ctx, unsigned int type, int number, void *interface, void *data);
    static int backIoctl(void *ctx, void *interface, void *vif, void *ifnet, unsigned long cmd,
                         void *data, bool *handled);
    static int backIoctlSet(void *ctx, void *interface, void *vif, void *skywalk, void *data,
                            bool *handled);
    static int backEnable(void *ctx, bool on);
    static uint32_t backOutput(void *ctx, mbuf_t m);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    static uint32_t backNativeOutput(void *ctx,mbuf_t m);
    static int backNativeWindow(void *ctx,struct owly_link_window *out);
    static bool nativeRx(void *ctx,uint32_t kind,const uint8_t *raw,size_t len,
                         const uint8_t src[6],const uint8_t dst[6],
                         uint8_t channel,int8_t rssi,uint64_t received_us);
#endif
    /* OWLY_NATIVE_IDENTITY_BRIDGE_BEGIN: backend receives only identity events. */
    static bool backVifEvent(void *ctx, void *vif, uint32_t role, uint32_t event,
                             const uint8_t request_mac[6]);
    /* OWLY_NATIVE_IDENTITY_BRIDGE_END */
#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
    static bool awdlRxAction(void *ctx, const uint8_t source[6],
                             unsigned int subtype, unsigned int social_mask,
                             const uint8_t *raw, size_t len);
#if defined(OWLY_ABI6_C3_SCAN_OBSERVER) && OWLY_ABI6_C3_SCAN_OBSERVER
    static bool awdlRxScanSignature(void *ctx, const uint8_t source[6],
                                    const uint8_t *raw, size_t len);
#endif
    static bool awdlRxIPv6(void *ctx, const uint8_t dst[6],
                            const uint8_t src[6], const uint8_t *ip6, size_t len);
    bool awdlHandoff(uint32_t kind, const uint8_t *raw, size_t len,
                     const uint8_t src[6], const uint8_t dst[6],
                     uint8_t channel=0,int8_t rssi=0,uint64_t received_us=0);
#endif
    static void backPower(void *ctx, bool on);
    /* The radio on, unless the machine is going down or asleep. */
    int radioUp() { return _halting ? -100 : _asleep ? -101 : rtw89_glue_up(); }
    static IOReturn powerEvent(void *target, void *refCon, UInt32 messageType,
                               IOService *provider, void *messageArgument, vm_size_t argSize);
    void sleepRadio();
    void wakeRadio();

    IONotifier *_powerNotifier = nullptr;
    volatile bool _halting = false;
    /* between kIOMessageSystemWillSleep and kIOMessageSystemHasPoweredOn */
    volatile bool _asleep = false;
    /* the radio was up when the machine went to sleep */
    bool _upBeforeSleep = false;

    bool _native = false;
    /* Link changes and finished scans reach IO80211 from a thread of their
     * own: the driver reports them with its locks held, and IO80211 may be
     * waiting for those very locks inside a request of its own. */
    thread_call_t _nativeCall = nullptr;
    volatile UInt32 _nativeEvents = 0;
    volatile bool _nativeClosing = false;
    volatile SInt32 _nativeRunning = 0;
#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
    /* One lock protects admission and the _ns->front callback lifetime. */
    IOLock *_owlyRxGateLock = nullptr;
    struct owly_abi6_rx_gate _owlyRxGate = {};
#endif
    IOService *_front = nullptr;
    NativeState *_ns = nullptr;

    IOPCIDevice *_pci = nullptr;
    uint16_t _deviceID = 0;            /* PCI device ID, for the chip name (rtw89_chips.h) */
    IOMemoryMap *_mmio = nullptr;
    IOWorkLoop *_workLoop = nullptr;    /* the interrupt's own thread */
    IOInterruptEventSource *_interrupt = nullptr;

    /* The network stack's calls (enable, disable, filters) are serialised on
     * this one. It is separate so that a call that waits for the chip cannot
     * hold up the interrupt it is waiting for. */
    IOWorkLoop *_netWorkLoop = nullptr;
    IOEthernetInterface *_netif = nullptr;
    IONetworkStats *_netStats = nullptr;
    OSDictionary *_mediumDict = nullptr;
    IONetworkMedium *_medium = nullptr;     /* owned by _mediumDict */
    IOEthernetAddress _mac = {};
    bool _netifEnabled = false;             /* the stack has the interface up */
    bool _linkActive = false;
    volatile bool _dataReady = false;       /* frames may pass between driver and stack */
    volatile SInt32 _txBusy = 0;            /* threads inside outputPacket() */
    IOLock *_commandLock = nullptr;     /* serialises setProperties and teardown */
    bool _pciOpen = false;
    bool _probed = false;
};
