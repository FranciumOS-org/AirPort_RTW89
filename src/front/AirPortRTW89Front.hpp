/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AirPortRTW89Front: the Wi-Fi device as macOS sees it. See rtw89_front_api.h
 * for why this is a kext of its own and what it leaves to the driver proper.
 * The IO80211Controller lifecycle follows AirPort_RTW88 (reference/), which
 * follows AirportItlwm.
 */
#pragma once

#include <IOKit/80211/IO80211Controller.h>
#include <IOKit/80211/IO80211Interface.h>
#include <IOKit/80211/IO80211WorkLoop.h>
#include <IOKit/IOLocks.h>
#include <IOKit/pci/IOPCIDevice.h>
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
#include <kern/thread_call.h>
#include <kern/thread.h>
#endif

#include "rtw89_front_api.h"

class AirPortRTW89FrontInterface : public IO80211Interface {
    OSDeclareDefaultStructors(AirPortRTW89FrontInterface)

public:
    /* Received frames are plain Ethernet by the time they get here. IO80211
     * only gets to see EAPOL frames, and only while its supplicant is the
     * one doing the key handshake. */
    UInt32 inputPacket(mbuf_t packet, UInt32 length = 0, IOOptionBits options = 0,
                       void *param = 0) override;
};

class AirPortRTW89Front : public IO80211Controller {
    OSDeclareDefaultStructors(AirPortRTW89Front)

public:
    /* IOService */
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    void free() override;
    IOReturn callPlatformFunction(const OSSymbol *functionName, bool waitForFunction,
                                  void *param1, void *param2, void *param3,
                                  void *param4) override;
    IOReturn registerWithPolicyMaker(IOService *policyMaker) override;
    IOReturn setPowerState(unsigned long powerStateOrdinal, IOService *whatDevice) override;

    /* IONetworkController / IOEthernetController */
    bool createWorkLoop() override;
    IOWorkLoop *getWorkLoop() const override;
    const OSString *newVendorString() const override;
    const OSString *newModelString() const override;
    IONetworkInterface *createInterface() override;

    /* OWLY_NATIVEFRONT_VIF_OBSERVER_BEGIN: observes Apple's requests only.
     * Never creates a VIF, publishes awdl0 or forwards packets on its own. */
#if defined(RTW89_AWDL_NATIVE_FRONT_OBSERVE) && RTW89_AWDL_NATIVE_FRONT_OBSERVE
    IO80211VirtualInterface *createVirtualInterface(struct ether_addr *address, UInt role) override;
    SInt32 enableVirtualInterface(IO80211VirtualInterface *interface) override;
    SInt32 disableVirtualInterface(IO80211VirtualInterface *interface) override;
#endif
    /* OWLY_NATIVEFRONT_VIF_OBSERVER_END */
    IOReturn enable(IONetworkInterface *iface) override;
    IOReturn disable(IONetworkInterface *iface) override;
    IOReturn selectMedium(const IONetworkMedium *medium) override;
    UInt32 outputPacket(mbuf_t m, void *param) override;
    IOReturn getHardwareAddress(IOEthernetAddress *addr) override;
    IOReturn setHardwareAddress(const IOEthernetAddress *addr) override;
    IOReturn getPacketFilters(const OSSymbol *group, UInt32 *filters) const override;
    IOReturn setMulticastMode(bool active) override;
    IOReturn setMulticastList(IOEthernetAddress *addrs, UInt32 count) override;
    IOReturn setPromiscuousMode(bool active) override;

    /* IO80211Controller */
    IOReturn getHardwareAddressForInterface(IO80211Interface *iface,
                                            IOEthernetAddress *addr) override;
    bool useAppleRSNSupplicant(IO80211Interface *) override;
    SInt32 apple80211_ioctl(IO80211Interface *interface, IO80211VirtualInterface *vif,
                            ifnet_t net, unsigned long cmd, void *data) override;
    SInt32 apple80211_ioctl_set(IO80211Interface *interface, IO80211VirtualInterface *vif,
                                IO80211SkywalkInterface *skywalk, void *data) override;
    /* Apple Legacy VIF init/attachToBpf calls the separate VIRTUAL request
     * dispatch, NOT apple80211Request(). Role-6 GET card capabilities only.
     * Every other virtual request remains inherited and fail-closed. */
    SInt32 apple80211VirtualRequest(UInt type, int number,
                                    IO80211VirtualInterface *vif, void *data) override;
    SInt32 apple80211Request(unsigned int type, int number, IO80211Interface *interface,
                             void *data) override;
    SInt32 stopDMA() override;
    UInt32 hardwareOutputQueueDepth(IO80211Interface *interface) override;
    SInt32 performCountryCodeOperation(IO80211Interface *interface,
                                       IO80211CountryCodeOp op) override;
    SInt32 enableFeature(IO80211FeatureCode feature, void *data) override;
    SInt32 monitorModeSetEnabled(IO80211Interface *interface, bool enabled, UInt32 mode) override;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    void owlyNativeCapture(IO80211VirtualInterface *,IO80211PeerManager *);
    UInt32 owlyNativeOutput(IO80211VirtualInterface *,mbuf_t);
#endif

private:
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    bool owlyNativeStart();
    void owlyNativeStop();
    void owlyNativeSchedule(uint64_t delay_us);
    static void owlyNativeTick(thread_call_param_t,thread_call_param_t);
    bool owlyNativeReceive(const struct owly_abi6_packet *);
    bool owlyNativeAcquire(IO80211VirtualInterface **,OSObject **);
    void owlyNativeRelease(IO80211VirtualInterface *,OSObject *);
    thread_call_t _owlyNativeCall=nullptr;
    thread_t _owlyNativeCallbackThread=nullptr;
    thread_t _owlyNativeOwnerThread=nullptr;
    OSObject *_owlyNativePeer=nullptr;
    IO80211VirtualInterface *_owlyNativePeerVif=nullptr;
    bool _owlyNativeClosed=true,_owlyNativePending=false,_owlyNativeEnabled=false;
    unsigned _owlyNativeUsers=0,_owlyNativeTicks=0;
    uint16_t _owlyNativeLastWindow=0;
    bool _owlyNativeHaveWindow=false;
    uint64_t _owlyNativeActionCalls=0,_owlyNativeDataCalls=0,_owlyNativeWindowCalls=0;
    bool _owlyNativeEnableIssued=false;
    uint8_t _owlyNativeProgrammedChannel=0;
    uint64_t _owlyNativeProgrammedGeneration=0;
    uint64_t _owlyNativeTXSamples=0;
    uint64_t _owlyNativeRepairAfterUS=0,_owlyNativeGateRecoveries=0,_owlyNativeGateBlocked=0;
    uint64_t _owlyNativePeerRebindings=0,_owlyNativeActionsProcessed=0,_owlyNativeActionsUnprocessed=0;
    uint64_t _owlyNativeActionAllocFailures=0;
    uint64_t _owlyNativeNextPeerAdmissionUS=0,_owlyNativePeerAddAttempts=0;
    uint64_t _owlyNativePeerAddVerified=0,_owlyNativePeerAddFailed=0,_owlyNativePeerResubmissions=0;
#endif
#if defined(RTW89_AWDL_NATIVE_FRONT_OBSERVE) && RTW89_AWDL_NATIVE_FRONT_OBSERVE
    bool owlyVifEvent(IO80211VirtualInterface *vif, UInt role, uint32_t event,
                      const uint8_t request_mac[6] = nullptr);
    bool owlyVifEventOnGate(IO80211VirtualInterface *vif, UInt role, uint32_t event,
                            const uint8_t request_mac[6]);
    void owlyStopVifOnGate();
    void owlyFinishDeferredStop();
    SInt32 owlyEnableVirtualInterfaceOnGate(IO80211VirtualInterface *vif);
    SInt32 owlyDisableVirtualInterfaceOnGate(IO80211VirtualInterface *vif);
    bool owlyVifIsTracked(IO80211VirtualInterface *vif);
#if defined(OWLY_AWDL_SERVICE_LIFECYCLE) && OWLY_AWDL_SERVICE_LIFECYCLE
    struct OwlyServiceCall {
        IO80211Interface *interface;
        IO80211VirtualInterface *vif;
        ifnet_t net;
        unsigned long command;
        void *envelope;
        int result;
    };
    bool owlyServiceIoctl(IO80211Interface *, IO80211VirtualInterface *,
                          ifnet_t, unsigned long, void *, int *);
    int owlyServiceIoctlOnGate(OwlyServiceCall *);
#endif
    SInt32 owlyBridgeVifSetEnvelope(IO80211Interface *interface,
        IO80211VirtualInterface *vif, void *data, bool *handled);
    SInt32 owlyRequestAWDLCreate(unsigned int type, void *data);
    SInt32 owlyRequestAWDLDelete(unsigned int type, void *data);
#endif
    IOReturn connectBack(const struct rtw89_back_ops *back, struct rtw89_front_ops *front);
    IOReturn disconnectBack();
    bool publishMedium();

    /* rtw89_front_ops */
    static void opPostMessage(void *ctx, unsigned int msg, void *data, size_t len);
    static void opSetLink(void *ctx, bool up, uint64_t bps, unsigned int reason);
    static mbuf_t opAllocPacket(void *ctx, unsigned int len);
    static void opInputPacket(void *ctx, mbuf_t m);
    static void opTxWake(void *ctx);
    static int opSuperIoctl(void *ctx, void *interface, void *vif, void *ifnet,
                            unsigned long cmd, void *data);
    static int opSuperIoctlSet(void *ctx, void *interface, void *vif, void *skywalk, void *data);
    static void opSetAppleRsn(void *ctx, bool on);
#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
    static bool opOwlyRxHandoff(void *ctx, const struct owly_abi6_packet *pkt);
#endif

    IOPCIDevice *_pci = nullptr;
    IO80211WorkLoop *_workLoop = nullptr;
    AirPortRTW89FrontInterface *_netif = nullptr;
    const IONetworkMedium *_medium = nullptr;
    IOEthernetAddress _mac = {};
    bool _haveMac = false;
    bool _superStarted = false;
    /* OWLY ABI4: lock protects local state and callback acknowledgement. */
    IOLock *_owlyVifLock = nullptr;
    struct rtw89_front_native_vif_state _owlyAirlink = {};
    bool _owlyVifBusy = false; /* protected by _owlyVifLock */
    /* Hold one explicit reference while tracked. Apple may detach externally;
     * its release must not leave our identity pointer dangling. */
    IO80211VirtualInterface *_owlyAttachedAWDL = nullptr;
    /* Gate14 RC3: pending BSD publication holds exactly one explicit retain.
     * Never commit backend CREATED without a real awdlN BSD name. */
    bool _owlyAWDLPendingBSD = false;
    UInt32 _owlyAWDLPendingChecks = 0;
    uint8_t _owlyAWDLRequestMac[6] = {};
    bool _owlyAWDLRequestBusy = false;
    bool _owlyVifMethodBusy = false;
    bool _owlyAWDLStopping = false;
    bool _owlyStopFinalizing = false;
    IOService *_owlyDeferredStopProvider = nullptr; /* retain until deferred stop */
    bool _owlyAWDLQuarantined = false; /* sticky until reboot after uncertain Apple/backend state */
#if defined(OWLY_ABI6_FRONT_BRIDGE) && OWLY_ABI6_FRONT_BRIDGE
    volatile SInt32 _owlyGateC2Ready = 0; /* published only after verified P2P+BSD+ACK */
#endif
    char _owlyAWDLBSDName[16] = {};
    /* OWLY_NATIVE_IDENTITY_BRIDGE_END */

    /* The back's table: read-locked around every call into it, write-locked
     * to change it. */
    bool backEnter();
    void backLeave();

    IOLock *_backLock = nullptr;         /* connecting and disconnecting */
    volatile SInt32 _backCalls = 0;     /* calls into the driver proper in progress */
    struct rtw89_back_ops _back = {};
    volatile bool _connected = false;
};
