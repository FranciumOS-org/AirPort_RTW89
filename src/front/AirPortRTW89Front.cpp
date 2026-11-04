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

/*
 * Every front line goes to the driver's log ring, because the front's own
 * IOLog reaches nothing: not the unified log, not dmesg for longer than a
 * few seconds. Before the driver connects there is nowhere to put a line but
 * IOLog, so that is still the fallback, and those early lines are the ones
 * that may well be lost.
 */
#define LOG(fmt, ...) rtw89FrontLog("AirPortRTW89Front: " fmt, ##__VA_ARGS__)

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
 * IO80211PeerManager::enable(), by its symbol for the same reason as
 * bpfTapInput() above: it is not in MacKernelSDK's headers and it is not a
 * virtual method, so a direct call is what the compiler would emit anyway.
 *
 * The family calls this itself from the link-up branch of setLinkState(), and
 * on this machine the result is that nothing is enabled: the peer manager's
 * _enabling byte stays 0, which means enableGated() -- four instructions,
 * the first of which sets that byte -- never ran. Calling it here says which
 * half is at fault, because the pointer chain it walks has been checked and
 * is whole.
 */
/*
 * The family's decompression buffers. All twelve guard checks in the family
 * compare these two bytes with 0xaa and panic otherwise, and nothing in it ever
 * writes them, so the first peer TLV it decompresses panics the machine. The
 * output is bounded to 0x200 by its callers, so the guards are never reached.
 */
extern "C" unsigned char bufout[];
#define RTW89_BUFOUT_GUARD_1    0x200
#define RTW89_BUFOUT_GUARD_2    0x410

extern "C" IOReturn rtw89_peer_manager_enable(void *peerManager, const char *why)
    __asm__("__ZN18IO80211PeerManager6enableEPKc");

/*
 * The two steps past enable() that actually switch the engine on, by their
 * symbols for the same reason as the call above.
 *
 * doEnable() ends by calling interfaceStateChange(7) -- the 7 is taken from
 * its own call site -- and only past that is enableAWDL(), which is the only
 * thing in the family that sets the bit actionFrameProcessInput() tests.
 * With the link up that chain should run on its own; if it does not, these
 * say so, and enableAWDL() is the step that matters.
 */
extern "C" void rtw89_awdl_interface_state_change(void *peerManager, unsigned int source)
    __asm__("__ZN22IO80211AWDLPeerManager20interfaceStateChangeE18StateChangedSource");
extern "C" int rtw89_awdl_enable_awdl(void *peerManager)
    __asm__("__ZN22IO80211AWDLPeerManager10enableAWDLEv");

/*
 * The other half of the gate on received frames, and the half that was still
 * shut. actionFrameProcessInput() looks at nothing unless both the state
 * flag bit above and the word at 0xcd4 are set, and 0xcd4 is written in
 * exactly one place in the family:
 *
 *   setAwdlSyncState(p):  ...  do_ioctl(SET, AWDL_SYNC_STATE, p)
 *                              if (ok) _syncState = p->state
 *                              do_ioctl(SET, AWDL_SYNC_ENABLED, { .enabled = 1 })
 *
 * and the only caller of that is the ioctl table -- so it happens when
 * userspace asks for it, which on this machine it never does, because the
 * engine was brought up here rather than along the family's own path. It
 * skips configure() when the configured bit is already set, which it is by
 * the time this runs, so the call is just the two settings and the write.
 */
struct rtw89_awdl_sync_state { unsigned int version; unsigned int state; };

extern "C" int rtw89_awdl_set_sync_state(void *peerManager,
                                         struct rtw89_awdl_sync_state *state)
    __asm__("__ZN22IO80211AWDLPeerManager16setAwdlSyncStateEP26apple80211_awdl_sync_state");

/*
 * Delivery to awdl0 itself, past the peer manager.
 *
 * inputPacket() is the obvious door and it does not open: it hands the packet
 * to IO80211AWDLPeerManager::inputPacket() first, and frees it when that
 * returns false. That filter looks the sender up with findPeer() and rejects
 * anything from a peer it has not built an object for, so the first frame
 * from a peer -- the only one that could start a conversation -- is always
 * the one thrown away. A data frame from a real iPhone reached that call 214
 * bytes long and awdl0's Ipkts stayed at 0.
 *
 * pushPacket() is the half that delivers: it sets the receive interface,
 * strips the 14-byte header it expects to find and calls ifnet_input(). What
 * is given up is the filter's own bookkeeping, which decides when the family
 * switches the schedule into data mode -- worth coming back to once a
 * transfer runs at all.
 */
extern "C" void rtw89_vif_push_packet(void *virtualInterface, mbuf_t m)
    __asm__("__ZN23IO80211VirtualInterface10pushPacketEP6__mbuf");

/*
 * Telling the family which availability window it is in.
 *
 * It keeps its own idea of the timeline and nothing we have done so far
 * touches it, which is the last input it has never had: its service
 * parameters TLV goes out as nine zero bytes, so we advertise no services and
 * a peer has nothing to display even once it adopts us.
 *
 * Event 41 is the window start, and apple80211_availability_window_start is
 * in no header here. The layout below is what the family reads out of it,
 * from reportDataPathEvents(), monitorTimeline() and logAWStart():
 *
 *   +0x00  the window number, as a word
 *   +0x04  the driver's synchronisation state
 *   +0x08  a six byte address, compared against the peer manager's own
 *   +0x0e  the master's address, which the peer manager adopts as its top
 *          master (reportDataPathEvents copies it to peerManager + 0x27fb and
 *          calls topMasterChanged() whenever it differs)
 *   +0x14  a word read big-endian and logged
 *   +0x18  a timestamp, kept as-is
 *   +0x20  a word, kept as-is
 *
 * The field at +0x04 is the one that decides whether anything we hand up is
 * looked at. reportDataPathEvents() stores it at peerManager + 0xcd4, and
 * actionFrameProcessInput() throws away every frame while that word is zero.
 * It was never filled in, so a zeroed buffer told the family we were not
 * synchronised on every single window: awdl0 came up, peers were discovered
 * over BLE, AirDrop opened, and not one action frame was ever processed. One
 * is the synchronised value the family's own code compares against
 * (setAwdlSyncState, logAWStart, updatePrimaryPayloadMI all test for 1).
 *
 * Every one of those is a scalar or an array read out of the buffer we pass
 * and none is a pointer followed, so a field misread here is a wrong value
 * rather than a fault. The buffer is larger than the struct and zeroed, so
 * anything read past what is understood reads zero.
 */
extern "C" int rtw89_awdl_report_event(void *peerManager, unsigned int event,
                                       void *payload, unsigned long len)
    __asm__("__ZN22IO80211AWDLPeerManager20reportDataPathEventsEjPvm");

#define RTW89_AWDL_EVENT_AW_START   41

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

/*
 * The one front, for the AWDL interface to hand its packets back to. The
 * interface is built by the family through createVirtualInterface() and has
 * no pointer of its own to the controller that owns it; there is one card and
 * one front, the same assumption gAppleRsn above already makes.
 */
static AirPortRTW89Front *gFront;

OSDefineMetaClassAndStructors(AirPortRTW89AwdlInterface, IO80211P2PInterface)

/*
 * Everything the family sends over awdl0: the mDNS that finds a peer and then
 * the TCP that carries the transfer. It arrives as a plain Ethernet frame,
 * the same shape the controller's own outputPacket() takes, and goes to the
 * driver to be put inside an AWDL data frame.
 *
 * This subclass is needed, not merely convenient. The family's own
 * IO80211VirtualInterface::outputPacket() hands a packet to the controller
 * only when the interface has no peer manager; awdl0 has one, so instead the
 * packet goes on a flow queue, and _outputStartGated() later pulls it back off
 * and calls outputPacket() again -- on this class. IO80211P2PInterface does
 * not override it, so without us the packet goes round that loop and never
 * leaves the machine. That is what "Waiting..." was.
 *
 * It was tried once before and the front then failed to load, with no Wi-Fi
 * and nothing to say why: subclassing puts the whole of IO80211P2PInterface's
 * vtable in ours, and three of its slots named methods the family does not
 * have. See the note in IO80211VirtualInterface.h; `make kext` now checks
 * every imported symbol against the family rather than finding out at boot.
 */
UInt32 AirPortRTW89AwdlInterface::outputPacket(mbuf_t m, void *param)
{
    AirPortRTW89Front *front = gFront;

    if (front)
        return front->awdlOutput(m);
    if (m)
        mbuf_freem(m);
    return kIOReturnOutputDropped;
}

OSDefineMetaClassAndStructors(IO80211P2PDaemonUserClient, IOUserClient)

/*
 * The framework's event ring, from Apple80211EventMonitoringHelper. ringState
 * holds the read offset at +0 and the write offset at +4. A record is a header
 * then payload then padding, with magic 0x57 at +0, payload length (u16) at
 * +0x18, padding (u16) at +0x1a and the APPLE80211_M_ code at +0x1c. The header
 * never wraps: a word of 0x50 is skipped by the reader, and so is the tail of
 * the ring when a header no longer fits. The payload may wrap.
 */
#define AWDL_RING_HDR_LEN   0x30
#define AWDL_RING_MAX_EVENT 0x1000

static IOSimpleLock *gEventLock;
static IO80211P2PDaemonUserClient *gEventClient;

void IO80211P2PDaemonUserClient::postEvent(unsigned int msg, const void *data, size_t len)
{
    UInt8 *ring;
    volatile UInt32 *state;
    size_t size, wr, rd, used, pad, tail;
    IOInterruptState is;

    if (!_ringBuffer || !_ringState || len > AWDL_RING_MAX_EVENT || (len && !data))
        return;
    ring = static_cast<UInt8 *>(_ringBuffer->getBytesNoCopy());
    state = static_cast<volatile UInt32 *>(_ringState->getBytesNoCopy());
    size = _ringBuffer->getCapacity();
    pad = (4 - (len & 3)) & 3;

    is = IOSimpleLockLockDisableInterrupt(gEventLock);
    rd = state[0];
    wr = state[1];
    if (rd < size && wr < size && !(wr & 3)) {
        used = (wr + size - rd) % size;
        tail = size - wr;
        /* one word kept free, or a full ring would read as empty */
        if (used + (tail < AWDL_RING_HDR_LEN ? tail : 0) + AWDL_RING_HDR_LEN + len + pad + 4 < size) {
            UInt8 hdr[AWDL_RING_HDR_LEN];
            UInt32 magic = 0x57, code = msg;
            UInt16 l = (UInt16)len, p = (UInt16)pad;

            if (tail < AWDL_RING_HDR_LEN) {
                UInt32 skip = 0x50;

                for (size_t i = 0; i < tail; i += 4)
                    memcpy(ring + wr + i, &skip, 4);
                wr = 0;
            }
            bzero(hdr, sizeof(hdr));
            memcpy(hdr, &magic, 4);
            memcpy(hdr + 0x18, &l, 2);
            memcpy(hdr + 0x1a, &p, 2);
            memcpy(hdr + 0x1c, &code, 4);
            memcpy(ring + wr, hdr, sizeof(hdr));
            wr = (wr + AWDL_RING_HDR_LEN) % size;
            tail = size - wr;
            if (len <= tail) {
                memcpy(ring + wr, data, len);
            } else {
                memcpy(ring + wr, data, tail);
                memcpy(ring, static_cast<const UInt8 *>(data) + tail, len - tail);
            }
            wr = (wr + len + pad) % size;
            OSSynchronizeIO();
            state[1] = (UInt32)wr;
        }
    }
    IOSimpleLockUnlockEnableInterrupt(gEventLock, is);
}

void IO80211P2PDaemonUserClient::wake()
{
    if (_haveAsyncRef)
        sendAsyncResult64(_asyncRef, kIOReturnSuccess, nullptr, 0);
}

/*
 * What BroadTek's route of IO80211VirtualInterface::IO80211InterfacePostMessage
 * calls. The family gives its events to the client at +0xa0, which stays null
 * (see below), and on AWDL routeEventViaBSD() is false, so without this they
 * reach nobody. It finds this function through the platform expert's
 * "rtw89-awdl-post" property, so the driver needs no Lilu.
 */
static void rtw89_awdl_post_event(void *vif, unsigned int msg, void *data, size_t len)
{
    static UInt32 logged[8];
    IO80211P2PDaemonUserClient *uc;
    IOInterruptState is;

    if (!gEventLock)
        return;
    is = IOSimpleLockLockDisableInterrupt(gEventLock);
    uc = gEventClient;
    if (uc)
        uc->retain();
    IOSimpleLockUnlockEnableInterrupt(gEventLock, is);
    if (!uc)
        return;
    if (uc->eventProvider() == vif) {
        if (msg < 256 && !(logged[msg / 32] & (1u << (msg % 32)))) {
            logged[msg / 32] |= 1u << (msg % 32);
            LOG("awdl: the family's first event %u, %u bytes, goes to the ring",
                msg, (unsigned int)len);
        }
        uc->postEvent(msg, data, len);
        uc->wake();
    }
    uc->release();
}

/*
 * The selectors the framework calls, decoded in HANDOFF.md. Named here so the
 * switch below reads as the protocol rather than as numbers.
 */
enum {
    kAwdlUCSanity        = 0,  /* struct in 0x3c30, struct out 0x180: a version */
    kAwdlUCEventRead     = 1,  /* one byte out, kept by the framework at +0x179 */
    kAwdlUCStartEvents   = 2,  /* async, carries the wake port */
    kAwdlUCArm           = 3,  /* no arguments */
    kAwdlUCUseEventPipe  = 5,  /* one byte out; false makes the framework give up */
    kAwdlUCPipeReady     = 7,  /* one byte out, kept at +0x17a */
};

/* What the framework asks for by memory type in IOConnectMapMemory64. */
enum {
    kAwdlUCRingBuffer = 1,
    kAwdlUCRingState  = 2,
};

/*
 * The entitlement the family's own IO80211AsyncEventUserClient::initWithTask
 * looks for on an AWDL interface: a table of four names indexed by the
 * interface type, which is 2 for role 6.
 *
 * It is recorded, not required. The family's initWithTask takes the missing
 * case (`je` to a branch that only zeroes the flag) straight back into the
 * rest of its initialisation; the one thing that does fail it is an
 * interfaceType of 4 or more. So this must not be a gate either -- making it
 * one is what had IOServiceOpen returning kIOReturnNotPermitted, which is this
 * file's own code, not the family's.
 */
#define RTW89_AWDL_EVENT_ENTITLEMENT "com.apple.wifi_awdl.event_monitor"

bool IO80211P2PDaemonUserClient::initWithTask(task_t owningTask, void *securityID, UInt32 type,
                                              OSDictionary *properties)
{
    OSObject *ent;
    OSBoolean *flag;

    if (!IOUserClient::initWithTask(owningTask, securityID, type, properties)) {
        LOG("awdl: IOUserClient::initWithTask() refused the event client");
        return false;
    }

    /* A cast and isTrue(), not a pointer comparison against kOSBooleanTrue:
     * copyClientEntitlement hands back a copy, and nothing promises it is the
     * singleton. */
    ent = IOUserClient::copyClientEntitlement(owningTask, RTW89_AWDL_EVENT_ENTITLEMENT);
    flag = OSDynamicCast(OSBoolean, ent);
    _entitled = flag && flag->isTrue();
    if (ent)
        ent->release();
    if (!_entitled)
        LOG("awdl: the event client's task does not hold "
            RTW89_AWDL_EVENT_ENTITLEMENT "; carrying on, as the family does");

    return true;
}

/*
 * The regions are allocated on the first request for each and then kept, so
 * that mapping the same type twice hands back the same memory -- which is what
 * ringBuffer and ringState have to be. Doing it here rather than in
 * initWithTask() keeps an allocation failure from failing the whole open,
 * which would come back to the framework as a refusal to create the client at
 * all and tell us nothing about why.
 */
IOBufferMemoryDescriptor *IO80211P2PDaemonUserClient::region(IOBufferMemoryDescriptor **slot)
{
    if (!*slot) {
        *slot = IOBufferMemoryDescriptor::inTaskWithOptions(
            kernel_task, kIOMemoryKernelUserShared | kIODirectionInOut, page_size, page_size);
        if (!*slot) {
            LOG("awdl: out of memory for an event ring region");
            return nullptr;
        }
        bzero((*slot)->getBytesNoCopy(), (*slot)->getCapacity());
    }
    return *slot;
}

/*
 * One thing this deliberately does not do: the family's own
 * startAsyncEventUserClientForTask() puts its client in the interface's
 * _asyncEventUserClient (+0xa0) and then calls back into it through its
 * vtable, so that the family can post events of its own. Ours is not of that
 * class, and leaving a foreign object there would have the family calling its
 * own slots on us. So +0xa0 stays null, which also means the family's "cannot
 * have more than one user client per interface" check no longer fires. If
 * events the family raises itself turn out to be needed in userspace, this is
 * where that thread starts.
 */
bool IO80211P2PDaemonUserClient::start(IOService *provider)
{
    if (!IOUserClient::start(provider))
        return false;
    LOG("awdl: the event user client is open%s",
        _entitled ? "" : " (unentitled)");
    return true;
}

void IO80211P2PDaemonUserClient::stop(IOService *provider)
{
    IOUserClient::stop(provider);
}

/*
 * clientClose() is the ordinary way out, but it is not the only one: a client
 * whose initWithTask() refuses the task is released without ever being closed,
 * and so is one torn down from below. The regions are let go here so that
 * neither path leaks a page pair.
 */
void IO80211P2PDaemonUserClient::free()
{
    if (_ringBuffer) {
        _ringBuffer->release();
        _ringBuffer = nullptr;
    }
    if (_ringState) {
        _ringState->release();
        _ringState = nullptr;
    }
    IOUserClient::free();
}

IOReturn IO80211P2PDaemonUserClient::clientClose()
{
    if (gEventLock) {
        IOInterruptState is = IOSimpleLockLockDisableInterrupt(gEventLock);

        if (gEventClient == this)
            gEventClient = nullptr;
        IOSimpleLockUnlockEnableInterrupt(gEventLock, is);
    }
    if (_wakePort != MACH_PORT_NULL) {
        /* Balances the port registerNotificationPort() was given. */
        IOUserClient::releaseNotificationPort(_wakePort);
        _wakePort = MACH_PORT_NULL;
    }
    /* The regions are released in free(), which every path reaches. */
    _armed = false;
    terminate();
    return kIOReturnSuccess;
}

IOReturn IO80211P2PDaemonUserClient::clientMemoryForType(UInt32 type, IOOptionBits *options,
                                                         IOMemoryDescriptor **memory)
{
    IOBufferMemoryDescriptor *md;

    switch (type) {
    case kAwdlUCRingBuffer: md = region(&_ringBuffer); break;
    case kAwdlUCRingState:  md = region(&_ringState);  break;
    default:
        LOG("awdl: the event client was asked for memory type %u, which it has no region for",
            (unsigned int)type);
        return kIOReturnBadArgument;
    }
    if (!md)
        return kIOReturnNoMemory;

    LOG("awdl: the framework mapped the %s",
        type == kAwdlUCRingBuffer ? "ring buffer" : "ring state");
    md->retain();   /* the caller releases what it is handed */
    *memory = md;
    *options = 0;
    return kIOReturnSuccess;
}

IOReturn IO80211P2PDaemonUserClient::registerNotificationPort(mach_port_t port, UInt32 type,
                                                              io_user_reference_t refCon)
{
    _wakePort = port;
    return kIOReturnSuccess;
}

IOReturn IO80211P2PDaemonUserClient::externalMethod(uint32_t selector,
                                                    IOExternalMethodArguments *args,
                                                    IOExternalMethodDispatch *dispatch,
                                                    OSObject *target, void *reference)
{
    if (!args)
        return kIOReturnBadArgument;

    switch (selector) {
    case kAwdlUCSanity:
        /*
         * The handshake. The framework hands over a 0x3c30 struct stamped
         * 0xc02869c9 -- which arrives as a descriptor rather than inline,
         * being well over a page -- and reads 0x180 bytes back. The only use
         * it makes of the answer is "%s" in its own "Sanity test passed.
         * Version - %s", so a string is the whole contract.
         */
        if (args->structureOutput && args->structureOutputSize) {
            bzero(args->structureOutput, args->structureOutputSize);
            strlcpy(static_cast<char *>(args->structureOutput), "AirPort_RTW89",
                    args->structureOutputSize);
        }
        return kIOReturnSuccess;

    case kAwdlUCUseEventPipe:
        /*
         * Answering false here is not a way out: the framework jumps straight
         * to its -3903 exit rather than falling back to anything older.
         */
    case kAwdlUCEventRead:
    case kAwdlUCPipeReady:
        if (args->structureOutput && args->structureOutputSize >= 1) {
            *static_cast<UInt8 *>(args->structureOutput) = 1;
            return kIOReturnSuccess;
        }
        if (args->scalarOutputCount >= 1) {
            args->scalarOutput[0] = 1;
            return kIOReturnSuccess;
        }
        return kIOReturnBadArgument;

    case kAwdlUCArm:
        _armed = true;
        return kIOReturnSuccess;

    case kAwdlUCStartEvents:
        /*
         * The async one. Nothing is posted yet, so the port and reference are
         * only kept: the framework waits on them and an empty ring simply
         * means no events, not an error.
         */
        if (args->asyncWakePort != MACH_PORT_NULL)
            _wakePort = args->asyncWakePort;
        if (args->asyncReference && gEventLock) {
            IOInterruptState is;

            bcopy(args->asyncReference, _asyncRef, sizeof(_asyncRef));
            _haveAsyncRef = true;
            is = IOSimpleLockLockDisableInterrupt(gEventLock);
            if (!gEventClient)
                gEventClient = this;
            IOSimpleLockUnlockEnableInterrupt(gEventLock, is);
        }
        LOG("awdl: wifip2pd is listening for events%s",
            _armed ? "" : " (before the arm, which is unexpected)");
        return kIOReturnSuccess;

    default:
        /*
         * Anything else is answered as "nothing to report" rather than
         * refused. The framework treats a non-zero return as fatal and gives
         * up on the interface, and every call it makes here is a query about
         * an event pipe that is legitimately empty, so success with a zeroed
         * answer is the truthful reply and a refusal is not. Each selector is
         * named once so the set the framework actually uses can be read off
         * the log instead of costing a boot apiece.
         */
        if (selector < 32 && !(_loggedSelectors & (1u << selector))) {
            _loggedSelectors |= 1u << selector;
            LOG("awdl: the event client answered selector %u as empty "
                "(%u bytes of struct out, %u scalars)",
                (unsigned int)selector, (unsigned int)args->structureOutputSize,
                (unsigned int)args->scalarOutputCount);
        }
        if (args->structureOutput && args->structureOutputSize)
            bzero(args->structureOutput, args->structureOutputSize);
        for (uint32_t i = 0; i < args->scalarOutputCount; i++)
            args->scalarOutput[i] = 0;
        return kIOReturnSuccess;
    }
}

/*
 * The user client wifip2pd needs, and the reason AirDrop got no further than a
 * peer in the list.
 *
 * Apple80211BindToInterfaceWithService() opens a user client on the interface
 * and keeps the connection at +0x17c of its handle. Every later event call
 * reads it, and Apple80211EventMonitoringInitIOUC() returns -3900 (Invalid
 * Parameters) the moment it finds it zero -- which is what
 * Apple80211RawP2PEventMonitoringInit() hands back to wifip2pd, so wifip2pd
 * throws, tears awdl0 down again and turns sharingd away.
 *
 * It was zero because the two halves of the stack disagree about one number.
 * The IO80211 framework on the system passes a hardcoded type 0 to
 * IOServiceOpen (`xorl %edx, %edx` right before the call), while
 * IO80211VirtualInterface::newUserClient() in the Ventura family we inject
 * takes type 4 for an AWDL role and 5 for NAN, and answers anything else with
 * kIOReturnBadArgument after logging "Invalid userClient type request". A real
 * Mac never meets this because its Wi-Fi comes with the matching family.
 *
 * Translating type 0 to the 4 the family wants was enough to get the client
 * created, and not enough to keep it: the framework then calls external
 * methods the family does not have, and closes the client when the first one
 * fails. So type 0 now gets IO80211P2PDaemonUserClient, which answers the
 * protocol the framework actually speaks. Every other type is still the
 * family's, reached by its symbol rather than by writing
 * IO80211VirtualInterface::newUserClient(), which clang compiles into
 * a jump through a slot of the imported IO80211VirtualInterface vtable. That
 * vtable is the one MacKernelSDK's header describes, and this header is known
 * to disagree with the family about three slots already (see the note above
 * outputPacket), so a slot that is off by one would land in some other method
 * of the family. The symbol is exported, `make kext` checks it against the
 * family, and a direct call is what a qualified call is meant to be anyway.
 */
extern "C" IOReturn
rtw89_vif_new_user_client(IO80211VirtualInterface *vif, task_t owningTask, void *securityID,
                          UInt type, OSDictionary *properties, IOUserClient **handler)
    __asm__("__ZN23IO80211VirtualInterface13newUserClientEP4taskPvjP12OSDictionaryPP12IOUserClient");

IOReturn AirPortRTW89AwdlInterface::newUserClient(task_t owningTask, void *securityID, UInt type,
                                                  OSDictionary *properties,
                                                  IOUserClient **handler)
{
    IO80211P2PDaemonUserClient *uc;

    /*
     * Type 0 is what the framework asks for, and what the family answers with
     * kIOReturnBadArgument. It is also the only type whose protocol the family
     * cannot speak, so this is where our own client goes; anything else is
     * still the family's business.
     */
    if (type != 0)
        return rtw89_vif_new_user_client(this, owningTask, securityID, type, properties, handler);

    if (!handler)
        return kIOReturnBadArgument;

    LOG("awdl: the framework is asking for an event user client");
    uc = OSTypeAlloc(IO80211P2PDaemonUserClient);
    if (!uc) {
        LOG("awdl: out of memory for the event user client");
        return kIOReturnNoMemory;
    }
    if (!uc->initWithTask(owningTask, securityID, type, properties)) {
        LOG("awdl: the event user client would not initialise");
        uc->release();
        return kIOReturnNotPermitted;
    }
    if (!uc->attach(this)) {
        LOG("awdl: the event user client would not attach");
        uc->release();
        return kIOReturnInternalError;
    }
    if (!uc->start(this)) {
        LOG("awdl: the event user client would not start");
        uc->detach(this);
        uc->release();
        return kIOReturnInternalError;
    }
    *handler = uc;
    return kIOReturnSuccess;
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
    bufout[RTW89_BUFOUT_GUARD_1] = 0xaa;
    bufout[RTW89_BUFOUT_GUARD_2] = 0xaa;
    if (!gEventLock)
        gEventLock = IOSimpleLockAlloc();
    {
        void *post = reinterpret_cast<void *>(rtw89_awdl_post_event);
        OSData *d = OSData::withBytes(&post, sizeof(post));
        IORegistryEntry *platform = IOService::getPlatform();

        if (d && platform)
            platform->setProperty("rtw89-awdl-post", d);
        OSSafeReleaseNULL(d);
    }
    _backLock = IOLockAlloc();
    if (!_backLock)
        return false;
    _awdlEnableCall = thread_call_allocate(awdlEnableThread, this);
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
    if (_awdlEnableCall) {
        /* Nothing new starts once this is set, and one already running is
         * waited for: thread_call_cancel() does not wait, and the interface
         * is about to be detached underneath it. Same reason, and the same
         * shape, as the AWDL clock's stop in the driver. */
        _awdlEnableAsked = true;
        thread_call_cancel(_awdlEnableCall);
        for (unsigned int ms = 0; _awdlEnableBusy && ms < 2000; ms++)
            IOSleep(1);
    }
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
    if (_awdlEnableCall) {
        thread_call_cancel(_awdlEnableCall);
        thread_call_free(_awdlEnableCall);
        _awdlEnableCall = nullptr;
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
 * Switch the family's AWDL engine on, once, when it will actually take.
 *
 * configure() -- which sets the flags actionFrameProcessInput() tests before
 * it will look at a received frame -- refuses in two ways that both matter
 * here. It wants the interface's enabled byte at 0x169 set, which happens
 * when awdl0 is brought up rather than when it is created; and it aborts if
 * it finds itself on the controller's workloop thread, which is where every
 * natural place to call this from runs. So the condition is polled from the
 * receive path and the call itself is made on a thread_call, which is
 * neither.
 */
void AirPortRTW89Front::awdlEnableThread(thread_call_param_t p0, thread_call_param_t p1)
{
    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(p0);
    IO80211VirtualInterface *vif;
    const uint8_t *pm;
    IOReturn ret;

    OSIncrementAtomic(&self->_awdlEnableBusy);
    vif = self->_vif;
    if (!vif) {
        OSDecrementAtomic(&self->_awdlEnableBusy);
        return;
    }
    pm = *reinterpret_cast<const uint8_t *const *>(reinterpret_cast<const uint8_t *>(vif) + 0xb0);
    if (!pm) {
        OSDecrementAtomic(&self->_awdlEnableBusy);
        return;
    }
    /*
     * The link has to be up before this, not after. doEnable() ends by
     * calling interfaceStateChange(), and that returns at its first branch --
     * "Interface link is down, nothing to do" -- while the interface's link
     * state at 0xfc is 1. Past that branch is the only call to enableAWDL(),
     * which is the only thing that sets the bit actionFrameProcessInput()
     * tests. So with the link down the engine enables itself and still looks
     * at nothing: _enabled 1 and state flags 0x21, bit 1 clear, every frame
     * dropped, which is exactly what was measured.
     *
     * Here rather than at interface creation also means the family has
     * everything else by now -- the interface is up and configure() has had
     * its settings taken -- and this is not the workloop thread.
     */
    vif->setLinkState(kIO80211NetworkLinkUp, 1);
    LOG("brought the AWDL link up before enabling: state %d",
        *reinterpret_cast<const int *>(reinterpret_cast<const uint8_t *>(vif) + 0xfc));

    ret = rtw89_peer_manager_enable(const_cast<uint8_t *>(pm), "rtw89 front");
    LOG("asked the family to enable AWDL: 0x%x, _enabling %u, _enabled %u, state flags 0x%x",
        ret, pm[0x2f5], pm[0x2f4], *reinterpret_cast<const unsigned int *>(pm + 0x8528));

    /*
     * Bit 1 of the state flags is the whole question for received frames, and
     * enable() alone has never set it: the flags come back 0x21, which is
     * what configure() leaves, with no sign of enableAWDL() having run. So
     * the two steps after it are taken here when they have not happened by
     * themselves. interfaceStateChange(7) first, since that is what doEnable()
     * calls and it does the surrounding work; enableAWDL() after, since that
     * is the step that sets the bit, and knowing which of the two was needed
     * is worth the line it costs.
     */
    if (!(*reinterpret_cast<const unsigned int *>(pm + 0x8528) & 2)) {
        rtw89_awdl_interface_state_change(const_cast<uint8_t *>(pm), 7);
        LOG("    after interfaceStateChange(7): state flags 0x%x",
            *reinterpret_cast<const unsigned int *>(pm + 0x8528));
    }
    if (!(*reinterpret_cast<const unsigned int *>(pm + 0x8528) & 2)) {
        int e = rtw89_awdl_enable_awdl(const_cast<uint8_t *>(pm));

        LOG("    after enableAWDL(): %d, state flags 0x%x, sync state %u", e,
            *reinterpret_cast<const unsigned int *>(pm + 0x8528),
            *reinterpret_cast<const unsigned int *>(pm + 0xcd4));
    }

    /*
     * The sync state is not set from here. It is the driver's own answer and
     * the family wants it in the availability window report, which is where
     * opAwdlWindow() now puts it: reportDataPathEvents() takes it out of the
     * event and stores it. setAwdlSyncState() reaches the same word, but it
     * is a full reconfigure on the way -- it clears the receive gate bit,
     * resets the election and lands on sync off -- so calling it per enable
     * undid the thing it was called for.
     */
    OSDecrementAtomic(&self->_awdlEnableBusy);
}

void AirPortRTW89Front::awdlEnableIfReady()
{
    IO80211VirtualInterface *vif = _vif;
    const uint8_t *vraw, *pm;

    if (_awdlEnableAsked || !vif || !_awdlEnableCall)
        return;
    vraw = reinterpret_cast<const uint8_t *>(vif);
    if (!vraw[0x169])           /* the interface is not up yet */
        return;
    pm = *reinterpret_cast<const uint8_t *const *>(vraw + 0xb0);
    if (!pm || pm[0x2f5] || pm[0x2f4])  /* already enabling, or enabled */
        return;
    _awdlEnableAsked = true;
    thread_call_enter(_awdlEnableCall);
}

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
    front->create_vif = opCreateVif;
    front->destroy_vif = opDestroyVif;
    front->awdl_rx = opAwdlRx;
    front->awdl_data_rx = opAwdlDataRx;
    front->awdl_window = opAwdlWindow;

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
    gAppleRsn = false;
    for (unsigned int ms = 1; _backCalls; ms++) {
        IOSleep(1);
        if (ms % 5000 == 0)
            LOG("still waiting for %d call(s) into the driver to return", (int)_backCalls);
    }
    bzero(&_back, sizeof(_back));
    IOLockUnlock(_backLock);

    if (was) {
        /* the last line that can still reach the ring */
        LOG("driver disconnected");
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
    AirPortRTW89AwdlInterface *vif;

    if (role != APPLE80211_VIF_AWDL)
        return super::createVirtualInterface(addr, role);

    /* Ours, not the family's plain one, only so that outputPacket() is a
     * method we own: everything else about it is IO80211P2PInterface. */
    vif = OSTypeAlloc(AirPortRTW89AwdlInterface);
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
    gFront = self;
    name = vif->getBSDName();
    if (bsd_name) {
        bzero(bsd_name, IFNAMSIZ);
        if (name)
            strlcpy(bsd_name, name, IFNAMSIZ);
    }
    /*
     * The AWDL link is brought up in awdlEnableThread(), not here.
     *
     * It belongs immediately before the enable, because the family reads it
     * there: doEnable() ends in interfaceStateChange(), which returns at
     * "Interface link is down, nothing to do" unless the link state is up,
     * and past that branch is the only call to enableAWDL() -- the only
     * thing that sets the bit actionFrameProcessInput() tests before it will
     * look at a received frame.
     *
     * At creation it is too early for any of that: the interface is not yet
     * up, so configure() refuses to take the settings, and the enable that
     * the link-up branch triggers is spent on an engine that cannot
     * configure itself. That was measured -- _enabled 1, state flags 0x21,
     * bit 1 clear, every frame still dropped.
     *
     * But it is still called here, because this call is what gets the
     * interface up in the first place. Taking it out stopped everything: no
     * enable, no frames handed over, nothing in the log at all. The link
     * state it writes does not stick -- it has read back 1 every time -- yet
     * setLinkState() also posts the kernel event userspace watches, and
     * without it nothing ever brings awdl0 up, so the enabled byte at 0x169
     * that awdlEnableIfReady() waits for is never set. The one before the
     * enable is the one the family reads; this one is the one that starts
     * the sequence.
     */
    if (role == APPLE80211_VIF_AWDL)
        vif->setLinkState(kIO80211NetworkLinkUp, 1);
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
 * Two fields in it are not decoration, and between them they are why the
 * family has never built a peer for anything we handed it:
 *
 *   - the frame itself must start at the action body, since isValidAF()
 *     checks mbuf_data()[1..5] for 00 17 f2 08 00 and getTlvPtrForType()
 *     counts TLVs from mbuf_data() + 16. The driver strips the 802.11 header
 *     now; before, the frame control sat where the OUI should be and every
 *     frame was rejected as "BAD OUI in AF".
 *   - the RSSI at 0x2c, as a signed int. determinePeerReachability() returns
 *     "unreachable" for zero whatever else is true, and addAWDLPeer() then
 *     logs "Unable to create peer" and returns nothing. Past that, the
 *     threshold at the peer manager's 0x6e84 is -70 dBm by default.
 *
 * The mbuf stays ours: after its own bpfTapInput() Broadcom hands the packet
 * straight to its free routine, so the family does not take it.
 */
void AirPortRTW89Front::opAwdlRx(void *ctx, const uint8_t *frame, size_t len,
                                 const uint8_t peer[6], uint32_t channel, int8_t rssi)
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
    /* The strength, which decides whether the peer is created at all. A chip
     * that gave us nothing would read as "unreachable", so an absent figure
     * is reported as a weak but usable one rather than as none. */
    *reinterpret_cast<int32_t *>(hdr + 0x2c) = rssi ? rssi : -60;

    /* The first frame's own first bytes, once: this is exactly what
     * isValidAF() reads, and it is the difference between the family looking
     * at our frames and discarding all of them. */
    if (!self->_awdlRxFed)
        LOG("the first AWDL frame handed over starts %02x %02x %02x %02x %02x %02x "
            "(IO80211 wants .. 00 17 f2 08 00), %u bytes, %d dBm",
            frame[0], len > 1 ? frame[1] : 0, len > 2 ? frame[2] : 0,
            len > 3 ? frame[3] : 0, len > 4 ? frame[4] : 0, len > 5 ? frame[5] : 0,
            (unsigned int)len, (int)rssi);

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
    self->awdlEnableIfReady();
    if (self->_awdlRxFed++ % 100 == 0) {
        /*
         * What becomes of the frame, as the family decides it.
         * actionFrameProcessInput() looks at a frame only when the AWDL peer
         * manager's 0xcd4 is non-zero and bit 1 of its 0x8528 is set; both
         * are set by configure(), which runs from enable(), which the link-up
         * branch of setLinkState() calls. The link state at 0xfc is what that
         * branch is chosen by, and it has been seen going back down to 1
         * after we set it up, which is why it is printed every time rather
         * than once. All three offsets are read-only and come from
         * IO80211FamilyLegacy's disassembly.
         */
        const uint8_t *vraw = reinterpret_cast<const uint8_t *>(vif);
        const uint8_t *pm = *reinterpret_cast<const uint8_t *const *>(vraw + 0xb0);

        LOG("handed AWDL frame %u to IO80211 (channel %u, from %02x:%02x:%02x:%02x:%02x:%02x)",
            self->_awdlRxFed, channel, peer[0], peer[1], peer[2], peer[3], peer[4], peer[5]);
        if (pm) {
            /*
             * The chain IO80211PeerManager::enable() walks before it will do
             * anything: getController() takes the interface from the peer
             * manager's 0xb8 and the controller from that interface's 0xc8,
             * and returns nothing if either is missing -- in which case
             * enable() skips its executeCommand() and returns in silence,
             * leaving exactly the zeroed flags seen here.
             */
            const void *pmIface = *reinterpret_cast<const void *const *>(pm + 0xb8);
            const void *ifCtrl = *reinterpret_cast<const void *const *>(vraw + 0xc8);

            LOG("    link state %d, sync state %u, state flags 0x%x -> frame %s",
                *reinterpret_cast<const int *>(vraw + 0xfc),
                *reinterpret_cast<const unsigned int *>(pm + 0xcd4),
                *reinterpret_cast<const unsigned int *>(pm + 0x8528),
                (*reinterpret_cast<const unsigned int *>(pm + 0xcd4) &&
                 (*reinterpret_cast<const unsigned int *>(pm + 0x8528) & 2)) ? "looked at" : "DROPPED");
            LOG("    peer manager's interface %s, that interface's controller %s us",
                pmIface == vif ? "is ours" : (pmIface ? "is SOMETHING ELSE" : "is MISSING"),
                ifCtrl == self ? "is" : (ifCtrl ? "is NOT" : "is MISSING;"));
            /*
             * enableGated() is four instructions: if _enabling at 0x2f5 is
             * already set it returns, otherwise it sets it and calls
             * doEnable(). So _enabling says whether executeCommand() ever
             * dispatched the action at all -- 0 means it did not, and the
             * fault is in our controller's command gate rather than anywhere
             * in the family; 1 with the flags still zero means doEnable()
             * ran and gave up inside. _enabled at 0x2f4 is the other half.
             */
            LOG("    peer manager _enabling %u, _enabled %u",
                *reinterpret_cast<const uint8_t *>(pm + 0x2f5),
                *reinterpret_cast<const uint8_t *>(pm + 0x2f4));
            /*
             * Whether any of this has produced a peer, which is the thing
             * everything else waits on: sharingd has nothing to talk to and
             * the service parameters TLV nothing to describe until the family
             * holds an IO80211AWDLPeer for the phone. The peer queue is at
             * the peer manager's 0x58 and its count at 0x34 of that --
             * addAWDLPeer() asserts on the first and enqueuePeerInOrder()
             * reads the second -- and 0x8ede is the running count of peers
             * added, bumped at the end of addAWDLPeer().
             */
            {
                const uint8_t *q = *reinterpret_cast<const uint8_t *const *>(pm + 0x58);

                LOG("    peers known %u, peers ever added %u",
                    q ? *reinterpret_cast<const unsigned int *>(q + 0x34) : 0,
                    *reinterpret_cast<const uint8_t *>(pm + 0x8ede));
            }
        }
    }
}

/*
 * A received AWDL data frame on its way to awdl0, which is where a transfer
 * lives. The action frames go to the peer manager through bpfTapInput(); a
 * data frame goes to the interface itself.
 *
 * IO80211VirtualInterface::inputPacket() sets the receive interface from the
 * virtual interface's own ifnet, lets the peer manager look at the frame --
 * it reads the destination and source out of the 802.3 header, which is why
 * the driver builds one -- and pushes it up. The packet becomes the family's
 * either way: it is pushed on or freed inside, and nothing comes back.
 *
 * The packet_info_tag is a structure with no layout in any header here. The
 * family only passes the pointer along and never reads through it on this
 * path, so a zeroed one of generous size is enough and is what is sent.
 */
void AirPortRTW89Front::opAwdlDataRx(void *ctx, const uint8_t *eth, size_t len)
{
    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(ctx);
    IO80211VirtualInterface *vif = self->_vif;
    mbuf_t m;

    self->_awdlDataInSeen++;
    if (!vif || !eth || !len)
        return;
    m = self->allocatePacket((unsigned int)len);
    if (!m)
        return;
    memcpy(mbuf_data(m), eth, len);
    rtw89_vif_push_packet(vif, m);
    if (!self->_awdlDataInUp++)
        LOG("the first data frame from a peer went up to awdl0, %u bytes",
            (unsigned int)len);
}

/*
 * One availability window, reported to the family. See the declaration of
 * rtw89_awdl_report_event() above for where the layout comes from and why a
 * misread field here cannot fault.
 */
void AirPortRTW89Front::opAwdlWindow(void *ctx, uint32_t aw_seq,
                                     const uint8_t master[6])
{
    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(ctx);
    IO80211VirtualInterface *vif = self->_vif;
    const uint8_t *vraw, *pm;
    uint8_t payload[64] = {};

    if (!vif || !master)
        return;
    vraw = reinterpret_cast<const uint8_t *>(vif);
    pm = *reinterpret_cast<const uint8_t *const *>(vraw + 0xb0);
    if (!pm)
        return;
    /* the engine has to be enabled, or this is reported into nothing */
    if (!(*reinterpret_cast<const unsigned int *>(pm + 0x8528) & 2))
        return;

    *reinterpret_cast<uint32_t *>(payload) = aw_seq;
    /* synchronised: the clock is running and this window is one of its own */
    *reinterpret_cast<uint32_t *>(payload + 0x04) = 1;
    memcpy(payload + 0x08, master, 6);
    /*
     * The master, not us. Our own address went here while a real device was
     * the master, so every window overwrote the peer manager's top master
     * with this machine and fired topMasterChanged() against the election's
     * own choice. When we keep our own time the compat side passes our
     * address as the master anyway, so this is right either way.
     */
    memcpy(payload + 0x0e, master, 6);
    *reinterpret_cast<uint32_t *>(payload + 0x14) = OSSwapHostToBigInt32(aw_seq);
    *reinterpret_cast<uint64_t *>(payload + 0x18) = mach_absolute_time();
    *reinterpret_cast<uint32_t *>(payload + 0x20) = 16;   /* the window, in TU */

    rtw89_awdl_report_event(const_cast<uint8_t *>(pm), RTW89_AWDL_EVENT_AW_START,
                            payload, 0x24);
    if (!self->_awdlWindows++)
        LOG("told the family about the first availability window (%u on the "
            "master's numbering)", aw_seq);
}

void AirPortRTW89Front::opDestroyVif(void *ctx)
{
    AirPortRTW89Front *self = static_cast<AirPortRTW89Front *>(ctx);
    IO80211VirtualInterface *vif = self->_vif;

    if (!vif)
        return;
    self->_vif = nullptr;
    /* before the detach, so no packet can arrive with nowhere to go */
    if (gFront == self)
        gFront = nullptr;
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

    /* awdl0 has started sending -- its Opkts moved off zero for the first
     * time once the link came up -- and whether any of it reaches here is a
     * separate question from whether it reaches the air. */
    if (!_awdlOutSeen++)
        LOG("the first packet from awdl0 reached the driver, %u bytes",
            m ? (unsigned int)mbuf_pkthdr_len(m) : 0);

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
