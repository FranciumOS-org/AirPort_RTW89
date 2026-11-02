// SPDX-License-Identifier: GPL-2.0
#include "AirPortRTW89Front.hpp"
#include "../kext/rtw89_chips.h"

#include <IOKit/80211/apple80211_var.h>

#include <IOKit/IOCommandGate.h>
#include <IOKit/IOLib.h>
#include <IOKit/network/IOBasicOutputQueue.h>
#include <IOKit/network/IONetworkMedium.h>
#include <sys/errno.h>
#include <sys/kpi_mbuf.h>

#define LOG(fmt, ...) IOLog("AirPortRTW89Front: " fmt "\n", ##__VA_ARGS__)

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

/*
 * No subclass of the family's interface here, and that is deliberate. One was
 * tried: a class deriving from IO80211P2PInterface that overrode
 * outputPacket(). Overriding a single method drags in the whole of that
 * class's virtual table -- 55 symbols the front had never needed -- and the
 * front is an injected kext linking against an injected family. It did not
 * load, so there was no Wi-Fi at all: the driver came up, the front did not,
 * and nothing said why.
 *
 * So the packets are taken in the controller's own outputPacket() below,
 * which the front already overrides, told apart by the param the family
 * passes with them.
 */

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
    _mac = kPlaceholderMac;

    if (!super::start(provider)) {
        LOG("IO80211Controller::start failed");
        return false;
    }
    _superStarted = true;

    /* The network interface is attached when the driver proper connects for
     * the first time: only it can read the card's address. Until then this
     * is a controller without an interface, which the driver finds by class. */
    setProperty("RTW89 Front API", RTW89_FRONT_API_VERSION, 32);
    setProperty("RTW89 Back Connected", kOSBooleanFalse);
    registerService();
    LOG("started; waiting for the driver");
    return true;
}

void AirPortRTW89Front::stop(IOService *provider)
{
    disconnectBack();
    opDestroyVif(this);
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

void AirPortRTW89Front::free()
{
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
    front->create_vif = opCreateVif;
    front->destroy_vif = opDestroyVif;
    front->awdl_rx = opAwdlRx;

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
    gAppleRsn = false;
    for (unsigned int ms = 1; _backCalls; ms++) {
        IOSleep(1);
        if (ms % 5000 == 0)
            LOG("still waiting for %d call(s) into the driver to return", (int)_backCalls);
    }
    bzero(&_back, sizeof(_back));
    IOLockUnlock(_backLock);

    if (was) {
        setProperty("RTW89 Back Connected", kOSBooleanFalse);
        if (_netif)
            opSetLink(this, false, 0, 0);
        LOG("driver disconnected");
    }
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

/*
 * The old family's own IO80211Controller::createVirtualInterface() builds only
 * the P2P roles (3, 4, 5, as "p2p") and the soft-AP role (7, as "ap"); role 6,
 * AWDL, falls off the end of its range check and it returns nothing, which is
 * why awdl0 never appeared. AirPort_BrcmNIC overrides the method for exactly
 * this reason: it takes one role more and names that one "awdl". We do the
 * same, with the family's plain IO80211P2PInterface, since what Broadcom adds
 * on top of it is Broadcom's own firmware state.
 *
 * attachVirtualInterface() calls this through the vtable and then attaches and
 * publishes what comes back, so the rest of the path is the family's and is
 * the same one p2p already uses.
 */
IO80211VirtualInterface *AirPortRTW89Front::createVirtualInterface(ether_addr *addr, UInt role)
{
    IO80211P2PInterface *vif;

    if (role != APPLE80211_VIF_AWDL)
        return super::createVirtualInterface(addr, role);

    vif = OSTypeAlloc(IO80211P2PInterface);
    if (!vif) {
        LOG("out of memory for the AWDL interface");
        return nullptr;
    }
    /* A literal, not a buffer on the stack: Broadcom passes a stack buffer, so
     * init() copies the name, but a literal is right either way. */
    if (!vif->init(this, addr, role, "awdl")) {
        LOG("IO80211P2PInterface::init() refused role %u", (unsigned int)role);
        vif->release();
        return nullptr;
    }
    /* So that a later failure cannot be blamed on this method again */
    LOG("built the AWDL interface %s for role %u", vif->getBSDName() ? vif->getBSDName() : "(unnamed)",
        (unsigned int)role);
    return vif;
}

/*
 * The family builds the virtual interface, through the override above:
 * attachVirtualInterface() calls createVirtualInterface(), attaches what it
 * gets and gives it a BSD name (awdl0). We keep the one we were given; macOS
 * asks for a second one only for P2P.
 */
int AirPortRTW89Front::opCreateVif(void *ctx, const uint8_t mac[6], uint32_t role, char *bsd_name)
{
    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(ctx);
    IO80211VirtualInterface *vif = nullptr;
    ether_addr addr = {};
    const char *name;

    if (self->_vif)
        return EBUSY;
    memcpy(addr.octet, mac, sizeof(addr.octet));
    /* The three outcomes are told apart by the errno, because the driver's log
     * ring is the only one we can read back: EIO the family refusing the role
     * outright, ENODEV it claiming success without an interface, and success
     * with an empty name an interface that never reached BSD. */
    if (!self->attachVirtualInterface(&vif, &addr, role, true)) {
        /* Which of its two steps failed is in the log above: it calls
         * createVirtualInterface() first, which says when it has built one, and
         * then IO80211VirtualInterface::attach(), which is IOService::attach(). */
        LOG("attachVirtualInterface() failed for role %u", (unsigned int)role);
        return EIO;
    }
    if (!vif) {
        LOG("attachVirtualInterface() said yes to role %u but built nothing", (unsigned int)role);
        return ENODEV;
    }
    self->_vif = vif;
    name = vif->getBSDName();
    if (bsd_name) {
        bzero(bsd_name, IFNAMSIZ);
        if (name)
            strlcpy(bsd_name, name, IFNAMSIZ);
    }
    /*
     * Tell the family the interface can carry packets.  Nothing else does it
     * for a virtual interface: IO80211VirtualInterface::setLinkState() posts
     * the kernel event that ifconfig reports as "status: active" and that
     * userspace watches, and it takes a branch of its own once the state is
     * up.  Until it is called awdl0 stays inactive, sharingd sees no usable
     * AWDL interface and never asks for AWDL at all, so the engine sits idle
     * however many frames it is handed.
     *
     * Broadcom does the same for its AWDL interface, from setPOWER: it logs
     * "Indicate AWDL interface LINK UP" and calls setLinkState(2, 1).
     */
    if (role == APPLE80211_VIF_AWDL) {
        vif->setLinkState(kIO80211NetworkLinkUp, 1);
        LOG("told the family the AWDL interface's link is up");
    }
    LOG("virtual interface %s up, role %u", name && name[0] ? name : "(unnamed)",
        (unsigned int)role);
    return 0;
}

/*
 * IO80211VirtualInterface::bpfTapInput() is not in MacKernelSDK's header, so
 * it is declared here by its own symbol rather than by editing the vendored
 * SDK. It is not a virtual method -- it appears in neither
 * IO80211VirtualInterface's vtable nor IO80211P2PInterface's -- so a direct
 * call to the exported symbol is what the compiler would have emitted anyway,
 * and is what AirPort_BrcmNIC does: it imports this exact symbol.
 */
extern "C" UInt32
rtw89_vif_bpf_tap_input(IO80211VirtualInterface *vif, mbuf_t m, UInt dlt, void *header,
                        size_t header_len)
    __asm__("__ZN23IO80211VirtualInterface11bpfTapInputEP6__mbufjPvm");

/*
 * A received AWDL action frame, handed to the family's AWDL engine.
 *
 * IO80211VirtualInterface::bpfTapInput() is the way in: with DLT 12 it gives
 * the frame to the peer manager's actionFrameInput() and only falls through to
 * the ordinary bpf tap if that does not take it. The header it wants is an
 * apple80211_act_frm_hdr of 72 bytes, mapped out of
 * AirPort_BrcmNIC::wlEvent(), which builds one the same way: the transmitter's
 * address first, then an apple80211_channel at offset 12. Broadcom fills three
 * more words at 0x1c, 0x20 and 0x24 out of its own event, byte-swapped; what
 * they are is not known, so they are left zero.
 *
 * The mbuf stays ours: after its own bpfTapInput() Broadcom hands the packet
 * straight to its free routine, so the family does not take it.
 */
void AirPortRTW89Front::opAwdlRx(void *ctx, const uint8_t *frame, size_t len,
                                 const uint8_t peer[6], uint32_t channel)
{
    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(ctx);
    IO80211VirtualInterface *vif = self->_vif;
    uint8_t hdr[72] = {};
    uint32_t *chan = reinterpret_cast<uint32_t *>(hdr + 12);
    mbuf_t m;

    /* Say what became of the frames, thinly: the first one, then every
     * hundredth.  "recognised N frames" in the driver's log only means the
     * driver saw them, and every way this can fail from here is silent. */
    self->_awdlRxSeen++;
    if (!vif) {
        if (!self->_awdlRxNoVif++)
            LOG("an AWDL frame arrived with no interface to hand it to");
        return;
    }
    if (!frame || !len)
        return;
    m = self->allocatePacket((unsigned int)len);
    if (!m) {
        if (!self->_awdlRxNoBuf++)
            LOG("out of packets for an AWDL frame");
        return;
    }
    memcpy(mbuf_data(m), frame, len);

    memcpy(hdr, peer, 6);
    chan[0] = APPLE80211_VERSION;   /* apple80211_channel.version */
    chan[1] = channel;              /* .channel, the one updateAFStats reads */
    chan[2] = channel <= 14 ? APPLE80211_C_FLAG_2GHZ : APPLE80211_C_FLAG_5GHZ;

    /* The packet stays ours, and goes back to the pool it came from rather than
     * to mbuf_freem(): Broadcom pairs its own bpfTapInput() with freePacket()
     * the same way.  Nothing the family does with it conflicts.  Its action
     * frame ring, the one path that would keep the packet, is dead code -- the
     * flag that selects it is set to false at peer manager init and written
     * nowhere else -- so actionFrameInput() always takes the
     * actionFrameProcessInput() branch, which frees only a copy it made
     * itself, never the packet it was handed. */
    rtw89_vif_bpf_tap_input(vif, m, 12, hdr, sizeof(hdr));
    self->freePacket(m);
    if (self->_awdlRxFed++ % 100 == 0)
        LOG("handed AWDL frame %u to IO80211 (channel %u, from %02x:%02x:%02x:%02x:%02x:%02x)",
            self->_awdlRxFed, channel, peer[0], peer[1], peer[2], peer[3], peer[4], peer[5]);
}

void AirPortRTW89Front::opDestroyVif(void *ctx)
{
    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(ctx);
    IO80211VirtualInterface *vif = self->_vif;

    if (!vif)
        return;
    self->_vif = nullptr;
    self->detachVirtualInterface(vif, true);
    LOG("virtual interface down");
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

void AirPortRTW89Front::opTxWake(void *ctx)
{
    IOOutputQueue *queue = static_cast<AirPortRTW89Front *>(ctx)->getOutputQueue();

    if (queue)
        queue->service(IOBasicOutputQueue::kServiceAsync);
}

int AirPortRTW89Front::opSuperIoctl(void *ctx, void *interface, void *vif, void *ifnet,
                                    unsigned long cmd, void *data)
{
    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(ctx);

    return self->IO80211Controller::apple80211_ioctl(static_cast<IO80211Interface *>(interface),
                                                     static_cast<IO80211VirtualInterface *>(vif),
                                                     static_cast<ifnet_t>(ifnet), cmd, data);
}

int AirPortRTW89Front::opSuperIoctlSet(void *ctx, void *interface, void *vif, void *skywalk,
                                       void *data)
{
    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(ctx);

    return self->IO80211Controller::apple80211_ioctl_set(
        static_cast<IO80211Interface *>(interface), static_cast<IO80211VirtualInterface *>(vif),
        static_cast<IO80211SkywalkInterface *>(skywalk), data);
}

/* ------------------------------------------------------------------ */
/*  From the family: passed on                                          */
/* ------------------------------------------------------------------ */

SInt32 AirPortRTW89Front::apple80211_ioctl(IO80211Interface *interface, IO80211VirtualInterface *vif,
                                           ifnet_t net, unsigned long cmd, void *data)
{
    bool handled = false;
    SInt32 ret = 0;

    const bool there = backEnter();
    if (there && _back.ioctl)
        ret = _back.ioctl(_back.ctx, interface, vif, net, cmd, data, &handled);
    backLeave();
    return handled ? ret : super::apple80211_ioctl(interface, vif, net, cmd, data);
}

SInt32 AirPortRTW89Front::apple80211_ioctl_set(IO80211Interface *interface,
                                               IO80211VirtualInterface *vif,
                                               IO80211SkywalkInterface *skywalk, void *data)
{
    bool handled = false;
    SInt32 ret = 0;

    const bool there = backEnter();
    if (there && _back.ioctl_set)
        ret = _back.ioctl_set(_back.ctx, interface, vif, skywalk, data, &handled);
    backLeave();
    return handled ? ret : super::apple80211_ioctl_set(interface, vif, skywalk, data);
}

SInt32 AirPortRTW89Front::apple80211Request(unsigned int type, int number,
                                            IO80211Interface *interface, void *data)
{
    SInt32 ret = ENXIO;     /* nobody there to ask */

    const bool there = backEnter();
    if (there)
        ret = _back.request(_back.ctx, type, number, interface, data);
    backLeave();
    return ret;
}

/*
 * Requests on a virtual interface (awdl0). The family routes its own
 * apple80211_ioctl() here when the ioctl names a virtual interface; the
 * driver proper logs what AWDL asks for and answers what it can.
 */
SInt32 AirPortRTW89Front::apple80211VirtualRequest(UInt type, int number,
                                                   IO80211VirtualInterface *vif, void *data)
{
    SInt32 ret = ENXIO;
    bool there;

    there = backEnter();
    if (there && _back.virtual_request)
        ret = _back.virtual_request(_back.ctx, type, number, vif, data);
    else
        ret = EOPNOTSUPP;
    backLeave();
    if (ret == EOPNOTSUPP)
        return super::apple80211VirtualRequest(type, number, vif, data);
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

/* The same path as outputPacket() below, for awdl0 rather than en1. */
UInt32 AirPortRTW89Front::awdlOutput(mbuf_t m)
{
    UInt32 ret;

    const bool there = backEnter();
    if (there && _back.awdl_output) {
        ret = _back.awdl_output(_back.ctx, m);
    } else {
        if (m)
            mbuf_freem(m);
        ret = kIOReturnOutputDropped;
    }
    backLeave();
    return ret;
}

UInt32 AirPortRTW89Front::outputPacket(mbuf_t m, void *param)
{
    UInt32 ret;

    /*
     * Which interface the packet came from. The family passes the virtual
     * interface as the param for one of its own, so a packet carrying the
     * AWDL interface we were given is one awdl0 sent. Logged once either way:
     * whether vif packets reach the controller at all is the open question,
     * and the answer decides whether the data path can live here.
     */
    if (param && _vif && param == _vif)
        return awdlOutput(m);
    if (param && !_awdlParamLogged) {
        _awdlParamLogged = true;
        LOG("outputPacket carried a param (%p) that is not the AWDL interface (%p)",
            param, _vif);
    }

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
    return OSString::withCString(rtw89_chip_name(_pci ? _pci->configRead16(kIOPCIConfigDeviceID) : 0));
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
