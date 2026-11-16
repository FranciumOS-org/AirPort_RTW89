/* SPDX-License-Identifier: GPL-2.0 */
/* Included in the frontend TU. The peer is captured at createPeerManager().
 * Method calls use exact exports. The narrowly pinned state reader below
 * is read-only and requires both the Bridge ABI guard and exact class size. */
#include "owly_native_peer_gate.h"
extern "C" IO80211Controller *owly_vif_controller(IO80211VirtualInterface *)
    __asm__("__ZN23IO80211VirtualInterface13getControllerEv");
/* The synchronous native processor borrows the original mbuf. Its bool is
 * a BPF disposition, not a peer-admission or file-transfer result. */
extern "C" bool owly_peer_process_action(void *,mbuf_t,UInt,void *,size_t)
    __asm__("__ZN22IO80211AWDLPeerManager23actionFrameProcessInputEP6__mbufjPvm");
extern "C" void owly_peer_lock(void *)
    __asm__("__ZN18IO80211PeerManager12lockDataPathEv");
extern "C" void owly_peer_unlock(void *)
    __asm__("__ZN18IO80211PeerManager14unlockDataPathEv");
extern "C" OSObject *owly_peer_find(void *,uint8_t *)
    __asm__("__ZN22IO80211AWDLPeerManager12findAWDLPeerEPh");
extern "C" OSObject *owly_peer_find_base(void *,uint8_t *)
    __asm__("__ZN18IO80211PeerManager8findPeerEPh");
extern "C" UInt32 owly_peer_mac_equal(void *,OSObject *,uint8_t *)
    __asm__("__ZN18IO80211PeerManager15macAddressEqualEP11IO80211PeerPh");
extern "C" OSObject *owly_peer_add(void *,const void *,mbuf_t)
    __asm__("__ZN22IO80211AWDLPeerManager11addAWDLPeerEPK22apple80211_act_frm_hdrP6__mbuf");
/* Legacy4C enable() ends in logDebug() and has no status return. Its RAX
 * contents must never gate the following native enableAWDL() transaction. */
extern "C" void owly_peer_enable(void *,const char *)
    __asm__("__ZN18IO80211PeerManager6enableEPKc");
extern "C" void owly_peer_changed(void *,unsigned)
    __asm__("__ZN22IO80211AWDLPeerManager20interfaceStateChangeE18StateChangedSource");
extern "C" int owly_peer_awdl_enable(void *)
    __asm__("__ZN22IO80211AWDLPeerManager10enableAWDLEv");
extern "C" int owly_peer_channel_sequence(void *,struct owly_cfg_sequence *)
    __asm__("__ZN22IO80211AWDLPeerManager22setAwdlChannelSequenceEP37apple80211_awdl_sync_channel_sequence");
extern "C" int owly_peer_master_channel(void *,struct owly_cfg_u32 *)
    __asm__("__ZN22IO80211AWDLPeerManager20setAwdlMasterChannelEP30apple80211_awdl_master_channel");
extern "C" void owly_peer_window(void *,unsigned,void *,unsigned long)
    __asm__("__ZN22IO80211AWDLPeerManager20reportDataPathEventsEjPvm");
extern "C" void owly_vif_input(IO80211VirtualInterface *,mbuf_t,packet_info_tag *)
    __asm__("__ZN23IO80211VirtualInterface11inputPacketEP6__mbufP15packet_info_tag");
extern "C" void owly_vif_push(IO80211VirtualInterface *,mbuf_t)
    __asm__("__ZN23IO80211VirtualInterface10pushPacketEP6__mbuf");
extern "C" unsigned char bufout[];
static bool owlyNativeDecompressionGuards()
{
    /* Legacy's exported decompression scratch has two mandatory 0xaa
     * sentinels. Match the public RTL port's initialization, only from zero;
     * never overwrite a nonzero corrupt/in-use value. No object offsets. */
    const unsigned offsets[2]={0x200u,0x410u};
    for(unsigned offset : offsets) {
        uint8_t value=__atomic_load_n(bufout+offset,__ATOMIC_ACQUIRE);
        if(value!=0 && value!=0xaa)return false;
    }
    for(unsigned offset : offsets) {
        uint8_t expected=0;
        if(!__atomic_compare_exchange_n(bufout+offset,&expected,static_cast<uint8_t>(0xaa),false,
                                       __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE) && expected!=0xaa)return false;
    }
    return true;
}
static uint64_t owlyNativeMacValue(const uint8_t mac[6])
{
    uint64_t value=0;
    for(unsigned i=0;i<6;i++)value=(value<<8)|mac[i];
    return value;
}
static bool owlyNativeReadPeerGate(OSObject *peer,struct owly_native_peer_gate *out)
{
    if(!peer || !out || !peer->metaCast("IO80211AWDLPeerManager"))return false;
    const auto *meta=peer->getMetaClass();
    if(!meta || meta->getClassSize()!=OWLY_NATIVE_PEER_CLASS_BYTES ||
       strcmp(meta->getClassName(),"IO80211AWDLPeerManager"))return false;
    const auto *bytes=reinterpret_cast<const uint8_t *>(peer);
    memcpy(&out->flags,bytes+OWLY_NATIVE_PEER_FLAGS_OFFSET,sizeof(out->flags));
    memcpy(&out->sync_state,bytes+OWLY_NATIVE_PEER_SYNC_STATE_OFFSET,sizeof(out->sync_state));
    memcpy(&out->rssi_floor,bytes+OWLY_NATIVE_PEER_RSSI_FLOOR_OFFSET,sizeof(out->rssi_floor));
    memcpy(out->own_mac,bytes+OWLY_NATIVE_PEER_OWN_MAC_OFFSET,6);
    memcpy(out->rx_af,bytes+OWLY_NATIVE_PEER_RX_AF_OFFSET,sizeof(out->rx_af));
    return true;
}
static OSObject *owlyNativeBoundPeer(IO80211VirtualInterface *vif)
{
    if(!vif)return nullptr;
    const auto *meta=vif->getMetaClass();
    if(!meta || meta->getClassSize()<OWLY_NATIVE_VIF_PEER_OFFSET+sizeof(void *) ||
       strcmp(meta->getClassName(),"OwlyNativeP2PInterface"))return nullptr;
    OSObject *peer=nullptr;
    memcpy(&peer,reinterpret_cast<const uint8_t *>(vif)+OWLY_NATIVE_VIF_PEER_OFFSET,sizeof(peer));
    return peer; /* Borrowed only while the retained VIF's workloop is gated. */
}
static mbuf_t owlyNativeAllocAction(size_t length)
{
    mbuf_t packet=nullptr;unsigned chunks=1;
    if(mbuf_allocpacket(MBUF_DONTWAIT,length,&chunks,&packet))return nullptr;
    if(!packet || mbuf_next(packet)) {
        if(packet)mbuf_freem(packet);
        return nullptr;
    }
    /* Allocation reserves storage but leaves m_len/pkthdr.len at zero.
     * Compare writable capacity before setting the populated lengths. */
    const size_t used=mbuf_len(packet);
    if(used<length && mbuf_trailingspace(packet)<length-used) {
        if(packet)mbuf_freem(packet);
        return nullptr;
    }
    mbuf_setlen(packet,length);
    mbuf_pkthdr_setlen(packet,length);
    mbuf_setnextpkt(packet,nullptr);
    return packet;
}

class OwlyNativeP2PInterface : public IO80211P2PInterface {
    OSDeclareDefaultStructors(OwlyNativeP2PInterface)
public:
#include "OwlyP2PInherited.inc"
    bool createPeerManager(ether_addr *mac,IO80211PeerManager **peer) override {
        bool ok=IO80211P2PInterface::createPeerManager(mac,peer);
        auto *front=OSDynamicCast(AirPortRTW89Front,owly_vif_controller(this));
        if(ok && peer && *peer && front)front->owlyNativeCapture(this,*peer);
        return ok;
    }
    UInt32 outputPacket(mbuf_t m,void *) override {
        auto *front=OSDynamicCast(AirPortRTW89Front,owly_vif_controller(this));
        if(front)return front->owlyNativeOutput(this,m);
        if(m)mbuf_freem(m);return kIOReturnOutputDropped;
    }
};
OSDefineMetaClassAndStructors(OwlyNativeP2PInterface,IO80211P2PInterface)
static_assert(sizeof(OwlyNativeP2PInterface)==sizeof(IO80211P2PInterface),
              "Native subclass adds no fields to the opaque Apple layout");

bool AirPortRTW89Front::owlyNativeStart()
{
    _owlyNativeCall=thread_call_allocate(owlyNativeTick,this);
    if(!_owlyNativeCall)return false;
    _owlyNativeClosed=false;
    setProperty("OwlyNativePeerDataRevision",7ULL,32);
    return true;
}
void AirPortRTW89Front::owlyNativeSchedule(uint64_t us)
{
    uint64_t interval;
    nanoseconds_to_absolutetime(us*1000u,&interval);
    IOLockLock(_owlyVifLock);
    if(!_owlyNativeClosed && !_owlyNativePending && _owlyNativeCall) {
        _owlyNativePending=true;retain();
        (void)thread_call_enter_delayed(_owlyNativeCall,mach_absolute_time()+interval);
    }
    IOLockUnlock(_owlyVifLock);
}
void AirPortRTW89Front::owlyNativeCapture(IO80211VirtualInterface *vif,IO80211PeerManager *raw)
{
    OSObject *peer=reinterpret_cast<OSObject *>(raw),*oldPeer=nullptr;
    IO80211VirtualInterface *oldVif=nullptr;
    if(!vif || !peer || !peer->metaCast("IO80211AWDLPeerManager"))return;
    vif->retain();peer->retain();
    IOLockLock(_owlyVifLock);
    if(!_owlyNativeClosed && !_owlyNativeUsers) {
        oldPeer=_owlyNativePeer;oldVif=_owlyNativePeerVif;
        _owlyNativePeer=peer;_owlyNativePeerVif=vif;_owlyNativeEnabled=false;
        _owlyNativeEnableIssued=false;_owlyNativeProgrammedChannel=0;
        _owlyNativeProgrammedGeneration=0;
        _owlyNativeHaveWindow=false;peer=nullptr;vif=nullptr;
    }
    IOLockUnlock(_owlyVifLock);
    OSSafeReleaseNULL(peer);OSSafeReleaseNULL(vif);
    OSSafeReleaseNULL(oldPeer);OSSafeReleaseNULL(oldVif);
    owlyNativeSchedule(1000);
}
bool AirPortRTW89Front::owlyNativeAcquire(IO80211VirtualInterface **vif,OSObject **peer)
{
    *vif=nullptr;*peer=nullptr;
    IOLockLock(_owlyVifLock);
    bool ok=!_owlyNativeClosed && !_owlyAWDLStopping && !_owlyVifMethodBusy &&
        !_owlyVifBusy && !_owlyAWDLRequestBusy && _owlyNativePeer &&
        _owlyAirlink.enabled && _owlyAirlink.cookie==_owlyNativePeerVif;
    if(ok) {
        *vif=_owlyNativePeerVif;*peer=_owlyNativePeer;
        (*vif)->retain();(*peer)->retain();retain();
        _owlyVifMethodBusy=true;++_owlyNativeUsers;
        _owlyNativeOwnerThread=current_thread();
    }
    IOLockUnlock(_owlyVifLock);return ok;
}
void AirPortRTW89Front::owlyNativeRelease(IO80211VirtualInterface *vif,OSObject *peer)
{
    IOLockLock(_owlyVifLock);
    _owlyVifMethodBusy=false;--_owlyNativeUsers;_owlyNativeOwnerThread=nullptr;
    IOLockWakeup(_owlyVifLock,&_owlyNativeUsers,false);
    IOLockUnlock(_owlyVifLock);
    peer->release();vif->release();
    owlyFinishDeferredStop();release();
}
void AirPortRTW89Front::owlyNativeStop()
{
    if(!_owlyVifLock)return;
    IOLockLock(_owlyVifLock);_owlyNativeClosed=true;IOLockUnlock(_owlyVifLock);
    bool canceled=_owlyNativeCall && thread_call_cancel(_owlyNativeCall);
    bool releasePending=false;OSObject *peer;IO80211VirtualInterface *vif;
    IOLockLock(_owlyVifLock);
    if(canceled && _owlyNativePending) {_owlyNativePending=false;releasePending=true;}
    /* stop() defers a call from the owner before reaching this method.
     * No timeout permits an Apple call to outlive VIF teardown. */
    while(_owlyNativeUsers && _owlyNativeOwnerThread!=current_thread())
        IOLockSleep(_owlyVifLock,&_owlyNativeUsers,THREAD_UNINT);
    peer=_owlyNativePeer;vif=_owlyNativePeerVif;
    _owlyNativePeer=nullptr;_owlyNativePeerVif=nullptr;_owlyNativeEnabled=false;
    _owlyNativeEnableIssued=false;_owlyNativeProgrammedChannel=0;
    _owlyNativeProgrammedGeneration=0;
    IOLockUnlock(_owlyVifLock);
    OSSafeReleaseNULL(peer);OSSafeReleaseNULL(vif);
    if(releasePending)release();
}
void AirPortRTW89Front::owlyNativeTick(thread_call_param_t context,thread_call_param_t)
{
    auto *self=static_cast<AirPortRTW89Front *>(context);
    IOLockLock(self->_owlyVifLock);
    self->_owlyNativePending=false;self->_owlyNativeCallbackThread=current_thread();
    IOLockUnlock(self->_owlyVifLock);
    IO80211VirtualInterface *vif;OSObject *peer;uint64_t next=100000;
    if(self->owlyNativeAcquire(&vif,&peer)) {
        struct owly_link_window window={};
        const bool there=self->backEnter();
        int ready=there && self->_back.native_window ? self->_back.native_window(self->_back.ctx,&window) : -1;
        self->backLeave();
        const bool abiReady=self->getProperty("OwlyNativeABIReady")==kOSBooleanTrue;
        if(!window.active)self->_owlyNativeHaveWindow=false;
        if(ready || !abiReady)self->_owlyNativeEnabled=false;
        if(!ready && abiReady && self->_workLoop && !self->_workLoop->inGate()) {
            struct GateRead {IO80211VirtualInterface *vif;OSObject *peer,*bound;
                owly_native_peer_gate value;bool valid,matches;}
                gate={vif,peer,nullptr,{},false,false};
            IOReturn gateStatus=self->_workLoop->runAction(
                [](OSObject *,void *opaque,void *,void *,void *) -> IOReturn {
                    auto *c=static_cast<GateRead *>(opaque);
                    c->bound=owlyNativeBoundPeer(c->vif);
                    c->matches=c->bound==c->peer;
                    c->valid=c->bound && owlyNativeReadPeerGate(c->bound,&c->value);
                    if(c->valid && !c->matches)c->bound->retain();
                    return kIOReturnSuccess;
                },self,&gate);
            self->setProperty("OwlyNativePeerBindingMatches",gate.matches);
            if(gateStatus==kIOReturnSuccess && gate.valid && !gate.matches) {
                /* createPeerManager can be re-entered while a retained old
                 * manager is in use. Rebind our own retained reference to
                 * the manager that GET203 and awdl0 actually use. Never write
                 * the private VIF pointer and never configure an orphan. */
                OSObject *stale=nullptr;
                IOLockLock(self->_owlyVifLock);
                if(!self->_owlyNativeClosed && self->_owlyNativePeer==peer && self->_owlyNativePeerVif==vif) {
                    stale=self->_owlyNativePeer;self->_owlyNativePeer=gate.bound;gate.bound=nullptr;
                    self->_owlyNativeEnabled=false;self->_owlyNativeEnableIssued=false;
                    self->_owlyNativeProgrammedChannel=0;self->_owlyNativeProgrammedGeneration=0;
                    self->_owlyNativeHaveWindow=false;self->_owlyNativeRepairAfterUS=0;
                    ++self->_owlyNativePeerRebindings;
                }
                IOLockUnlock(self->_owlyVifLock);
                OSSafeReleaseNULL(stale);OSSafeReleaseNULL(gate.bound);
                self->setProperty("OwlyNativePeerRebindings",self->_owlyNativePeerRebindings,64);
                self->owlyNativeRelease(vif,peer);self->owlyNativeSchedule(1000);
                IOLockLock(self->_owlyVifLock);self->_owlyNativeCallbackThread=nullptr;IOLockUnlock(self->_owlyVifLock);
                self->release();return;
            }
            const bool layoutReady=gateStatus==kIOReturnSuccess && gate.valid;
            const bool publishGate=self->_owlyNativeTicks<4 || !(self->_owlyNativeTicks%64) ||
                !layoutReady || !owly_native_peer_rx_open(&gate.value);
            if(publishGate)self->setProperty("OwlyNativePeerLayoutReady",layoutReady);
            if(!layoutReady) {
                self->_owlyNativeEnabled=false;
                self->owlyNativeRelease(vif,peer);
                self->owlyNativeSchedule(100000);
                IOLockLock(self->_owlyVifLock);self->_owlyNativeCallbackThread=nullptr;IOLockUnlock(self->_owlyVifLock);
                self->release();return;
            }
            if(publishGate) {
                self->setProperty("OwlyNativeAppleStateFlags",gate.value.flags,32);
                self->setProperty("OwlyNativeAppleSyncState",gate.value.sync_state,32);
                self->setProperty("OwlyNativeAppleRXGateOpen",owly_native_peer_rx_open(&gate.value));
                self->setProperty("OwlyNativeAppleRSSIFloor",static_cast<unsigned long long>(static_cast<uint32_t>(gate.value.rssi_floor)),32);
                self->setProperty("OwlyNativeAppleOwnMAC",owlyNativeMacValue(gate.value.own_mac),64);
            }
            const bool newEpoch=self->_owlyNativeProgrammedChannel!=window.channel ||
                self->_owlyNativeProgrammedGeneration!=window.generation;
            if(newEpoch)self->_owlyNativeRepairAfterUS=0;
            /* A successful enable call is not a durable state guarantee.
             * Native SET134/interface events can close SYNC_ACTIVE without
             * changing the frontend's cached bool. Restore via native APIs. */
            if(self->_owlyNativeEnabled && !(gate.value.flags&OWLY_NATIVE_PEER_SYNC_ACTIVE)) {
                self->_owlyNativeEnabled=false;
                self->_owlyNativeHaveWindow=false;
                ++self->_owlyNativeGateRecoveries;
                self->setProperty("OwlyNativeGateRecoveries",self->_owlyNativeGateRecoveries,64);
            }
            if(!(gate.value.flags&OWLY_NATIVE_PEER_CONFIGURED))self->_owlyNativeEnableIssued=false;
            /* AW-start is the real native state transition. Re-report the
             * current measured window if Apple lost its sync word, including
             * when our sequence counter has not advanced yet. */
            if(gate.value.sync_state==0)self->_owlyNativeHaveWindow=false;
            /* Apple enableAWDL supplies the first SET151 and SET117. A bound,
             * enabled VIF is enough to enter that transaction before an AW
             * exists. Window events still require a running schedule. */
            if((window.channel==6 || window.channel==44 || window.channel==149) &&
               (newEpoch || window.sampled_us>=self->_owlyNativeRepairAfterUS) &&
               (!self->_owlyNativeEnabled ||
                self->_owlyNativeProgrammedChannel!=window.channel ||
                self->_owlyNativeProgrammedGeneration!=window.generation)) {
                vif->IO80211VirtualInterface::setEnabledBySystem(true);
                vif->IO80211VirtualInterface::setLinkState(kIO80211NetworkLinkUp,1);
                int result=kIOReturnNotReady;
                if(owlyNativeDecompressionGuards()) {
                    if(!self->_owlyNativeEnableIssued ||
                       self->_owlyNativeProgrammedGeneration!=window.generation) {
                        owly_peer_enable(peer,"Owly native peer/data");
                        owly_peer_changed(peer,7);
                        self->_owlyNativeEnableIssued=true;
                        self->setProperty("OwlyNativePeerEnableIssued",true);
                    }
                    /* configure() starts with sparse channel6 defaults. This
                     * radio has an actual SCC binding, so program the real
                     * master's channel and the actual sixteen bound slots
                     * through exported native APIs. Their real ioctl results
                     * are checked; the backend's off-channel rejection stays. */
                    struct owly_cfg_sequence sequence;
                    owly_config_sequence(&sequence,window.channel);
                    const uint8_t masterChannel=window.remote && window.master_channel ?
                        window.master_channel : window.channel;
                    struct owly_cfg_u32 master={1,masterChannel};
                    struct ScheduleCall {OSObject *peer;owly_cfg_u32 *master;owly_cfg_sequence *sequence;int masterResult,sequenceResult;} call={peer,&master,&sequence,kIOReturnNotReady,kIOReturnNotReady};
                    /* Serialize native schedule bookkeeping on its owning
                     * workloop. No backend/glue lock is held across this call;
                     * enable/configure itself remains on the thread_call. */
                    result=static_cast<int>(self->_workLoop->runAction(
                        [](OSObject *,void *opaque,void *,void *,void *) -> IOReturn {
                            auto *c=static_cast<ScheduleCall *>(opaque);
                            c->masterResult=owly_peer_master_channel(c->peer,c->master);
                            if(c->masterResult)return static_cast<IOReturn>(c->masterResult);
                            c->sequenceResult=owly_peer_channel_sequence(c->peer,c->sequence);
                            return static_cast<IOReturn>(c->sequenceResult);
                        },self,&call));
                    self->setProperty("OwlyNativeMasterProgramResult",static_cast<unsigned long long>(static_cast<uint32_t>(call.masterResult)),32);
                    self->setProperty("OwlyNativeSequenceProgramResult",static_cast<unsigned long long>(static_cast<uint32_t>(call.sequenceResult)),32);
                    if(!result)result=owly_peer_awdl_enable(peer);
                }
                if(!result) {
                    /* Native enable/configure may reset SET117 and advance
                     * the backend epoch. Commit the post-callback snapshot,
                     * otherwise every timer tick can restart this session. */
                    struct owly_link_window confirmed={};
                    const bool present=self->backEnter();
                    const int after=present && self->_back.native_window ?
                        self->_back.native_window(self->_back.ctx,&confirmed) : -1;
                    self->backLeave();
                    if(after || confirmed.channel!=window.channel ||
                       memcmp(confirmed.local,window.local,6)) result=kIOReturnNotReady;
                    else {
                        window=confirmed;
                        self->_owlyNativeProgrammedChannel=window.channel;
                        self->_owlyNativeProgrammedGeneration=window.generation;
                        self->_owlyNativeHaveWindow=false;
                    }
                }
                self->_owlyNativeEnabled=result==0;
                if(!newEpoch && !(gate.value.flags&OWLY_NATIVE_PEER_SYNC_ACTIVE))
                    self->_owlyNativeRepairAfterUS=window.sampled_us+500000u;
                self->setProperty("OwlyNativeEnableResult",static_cast<unsigned long long>(static_cast<uint32_t>(result)),32);
                self->setProperty("OwlyNativeProgrammedChannel",static_cast<unsigned long long>(self->_owlyNativeProgrammedChannel),32);
                self->setProperty("OwlyNativeProgrammedGeneration",self->_owlyNativeProgrammedGeneration,64);
            }
            if(self->_owlyNativeEnabled && window.active &&
               window.until_next_tu && window.until_next_tu<=OWLY_LINK_AW_US/1024u &&
               (!self->_owlyNativeHaveWindow || self->_owlyNativeLastWindow!=window.sequence)) {
                struct LegacyWindowStart {
                    uint32_t counter, sync_state;
                    uint8_t sync_master[6], top_master[6];
                    uint32_t start_us_be;
                    apple80211_channel channel;
                } payload={};
                static_assert(sizeof(LegacyWindowStart)==36 &&
                              offsetof(LegacyWindowStart,start_us_be)==20 &&
                              offsetof(LegacyWindowStart,channel)==24,
                              "Legacy availability-window start ABI");
                const uint64_t phase_us=OWLY_LINK_AW_US-window.until_next_tu*1024u;
                // The backend reports time to the next window rounded up to a TU.
                const uint64_t start_us=window.sampled_us>=phase_us ? window.sampled_us-phase_us : 0;
                payload.counter=window.sequence;
                payload.sync_state=1;
                memcpy(payload.sync_master,window.master,6);
                memcpy(payload.top_master,window.master,6);
                payload.start_us_be=OSSwapHostToBigInt32(static_cast<uint32_t>(start_us));
                payload.channel={APPLE80211_VERSION,window.channel,
                    static_cast<uint32_t>(APPLE80211_C_FLAG_20MHZ |
                        (window.channel<=14 ? APPLE80211_C_FLAG_2GHZ : APPLE80211_C_FLAG_5GHZ))};
                struct WindowCall {OSObject *peer;LegacyWindowStart *payload;owly_native_peer_gate after;bool valid;} call={peer,&payload,{},false};
                IOReturn status=self->_workLoop->runAction(
                    [](OSObject *,void *opaque,void *,void *,void *) -> IOReturn {
                        auto *c=static_cast<WindowCall *>(opaque);
                        owly_peer_window(c->peer,41,c->payload,sizeof(*c->payload));
                        c->valid=owlyNativeReadPeerGate(c->peer,&c->after);
                        return kIOReturnSuccess;
                    },self,&call);
                self->setProperty("OwlyNativeWindowCallStatus",static_cast<unsigned long long>(static_cast<uint32_t>(status)),32);
                ++self->_owlyNativeWindowCalls;self->_owlyNativeLastWindow=window.sequence;self->_owlyNativeHaveWindow=true;
                if(call.valid && (call.after.flags!=gate.value.flags || call.after.sync_state!=gate.value.sync_state)) {
                    self->setProperty("OwlyNativeAppleStateFlags",call.after.flags,32);
                    self->setProperty("OwlyNativeAppleSyncState",call.after.sync_state,32);
                    self->setProperty("OwlyNativeAppleRXGateOpen",owly_native_peer_rx_open(&call.after));
                }
            }
            if(window.active)next=window.until_next_tu ? (uint64_t)window.until_next_tu*1024u : 1024u;
        }
        if(++self->_owlyNativeTicks<=4 || !(self->_owlyNativeTicks%64)) {
            self->setProperty("OwlyNativeActionsObserved",window.actions,64);
            self->setProperty("OwlyNativePeerCount",static_cast<unsigned long long>(window.peers),32);
            self->setProperty("OwlyNativeWindowActive",window.active);
            self->setProperty("OwlyNativeBoundChannel",static_cast<unsigned long long>(window.channel),32);
            self->setProperty("OwlyNativeRemoteClock",window.remote);
            self->setProperty("OwlyNativeDataAdmitted",window.data_rx_admitted,64);
            self->setProperty("OwlyNativeTXQueued",window.tx_enqueued,64);
            self->setProperty("OwlyNativeTXHandoffs",window.tx_handoffs,64);
            self->setProperty("OwlyNativeTXRefused",window.tx_refused,64);
            self->setProperty("OwlyNativeTXExpired",window.tx_expired,64);
            self->setProperty("OwlyNativeTXRadioACK",window.tx_radio_acked,64);
            self->setProperty("OwlyNativeActionCalls",self->_owlyNativeActionCalls,64);
            self->setProperty("OwlyNativeActionAllocFailures",self->_owlyNativeActionAllocFailures,64);
            self->setProperty("OwlyNativeDataCalls",self->_owlyNativeDataCalls,64);
            self->setProperty("OwlyNativeWindowCalls",self->_owlyNativeWindowCalls,64);
            self->setProperty("OwlyNativeLocalMAC",owlyNativeMacValue(window.local),64);
        }
        self->owlyNativeRelease(vif,peer);
    }
    self->owlyNativeSchedule(next);
    IOLockLock(self->_owlyVifLock);self->_owlyNativeCallbackThread=nullptr;IOLockUnlock(self->_owlyVifLock);
    self->release(); /* reference owned by this scheduled invocation */
}
bool AirPortRTW89Front::owlyNativeReceive(const struct owly_abi6_packet *pkt)
{
    if(!pkt || !pkt->channel || !pkt->received_us ||
       (pkt->kind==OWLY_ABI6_PACKET_ACTION && pkt->rssi>=0) ||
       (pkt->kind!=OWLY_ABI6_PACKET_ACTION && pkt->kind!=OWLY_ABI6_PACKET_IPV6))return false;
    IO80211VirtualInterface *vif;OSObject *peer;
    if(!owlyNativeAcquire(&vif,&peer))return false;
    bool submitted=false;
    if(_owlyNativeEnabled && pkt->kind==OWLY_ABI6_PACKET_ACTION && pkt->length>=40 && pkt->length<=OWLY_ABI6_PACKET_MAX_ACTION) {
        struct owly_action_info decoded={};
        if(owly_decode_action(pkt->bytes,pkt->length,&decoded)==OWLY_ACTION_DECODED && decoded.complete &&
           !memcmp(pkt->bytes+10,pkt->src,6)) {
            size_t length=pkt->length-24;mbuf_t m=owlyNativeAllocAction(length);
            if(m && mbuf_len(m)>=length) {
                alignas(8) uint8_t metadata[72]={};
                apple80211_channel channel={APPLE80211_VERSION,pkt->channel,
                    static_cast<uint32_t>(APPLE80211_C_FLAG_20MHZ | (pkt->channel<=14 ? APPLE80211_C_FLAG_2GHZ : APPLE80211_C_FLAG_5GHZ))};
                int32_t rssi=pkt->rssi;uint32_t time=OSSwapHostToBigInt32(static_cast<uint32_t>(pkt->received_us));
                memcpy(mbuf_data(m),pkt->bytes+24,length);memcpy(metadata,pkt->src,6);
                memcpy(metadata+12,&channel,sizeof(channel));memcpy(metadata+44,&rssi,4);memcpy(metadata+48,&time,4);
                struct ActionCall {IO80211VirtualInterface *vif;OSObject *peer;mbuf_t packet;uint8_t *metadata;
                    owly_native_peer_gate gate,after;uint64_t received;
                    bool valid,called,matches,afterValid,disposition,present,addCalled,addVerified,resubmitted,conflict,looked;}
                    call={vif,peer,m,metadata,{},{},pkt->received_us,
                          false,false,false,false,false,false,false,false,false,false,false};
                IOReturn status=_workLoop->runAction(
                    [](OSObject *owner,void *opaque,void *,void *,void *) -> IOReturn {
                        auto *self=static_cast<AirPortRTW89Front *>(owner);
                        auto *c=static_cast<ActionCall *>(opaque);
                        c->matches=owlyNativeBoundPeer(c->vif)==c->peer;
                        if(!c->matches)return kIOReturnNotReady;
                        c->valid=owlyNativeReadPeerGate(c->peer,&c->gate);
                        if(!c->valid || !owly_native_peer_rx_open(&c->gate))return kIOReturnNotReady;
                        c->called=true;
                        c->disposition=owly_peer_process_action(c->peer,c->packet,12,c->metadata,72);
                        c->afterValid=owlyNativeReadPeerGate(c->peer,&c->after);
                        const bool processed=c->afterValid &&
                            static_cast<uint32_t>(owly_native_peer_rx_af_total(&c->after)-
                                                  owly_native_peer_rx_af_total(&c->gate))!=0;
                        IOLockLock(self->_owlyVifLock);
                        const bool live=!self->_owlyNativeClosed && !self->_owlyAWDLStopping;
                        IOLockUnlock(self->_owlyVifLock);
                        if(!live || !processed || !owly_native_peer_rx_open(&c->after))return kIOReturnSuccess;
                        /* Same recursive lock as Apple's parser and GET203.
                         * Pointer return alone is not peer-admission evidence. */
                        owly_peer_lock(c->peer);
                        c->looked=true;
                        OSObject *found=owly_peer_find(c->peer,c->metadata);
                        c->present=found && owly_peer_mac_equal(c->peer,found,c->metadata)==1;
                        c->conflict=(found && !c->present) ||
                            (!found && owly_peer_find_base(c->peer,c->metadata));
                        int32_t signal;memcpy(&signal,c->metadata+44,4);
                        if(!c->present && !c->conflict && signal<0 && signal>=c->after.rssi_floor &&
                           !(c->metadata[0]&1) && owlyNativeMacValue(c->metadata) &&
                           !(c->after.own_mac[0]&1) && owlyNativeMacValue(c->after.own_mac) &&
                           memcmp(c->metadata,c->after.own_mac,6) &&
                           c->received>=self->_owlyNativeNextPeerAdmissionUS) {
                            self->_owlyNativeNextPeerAdmissionUS=c->received>UINT64_MAX-500000u ?
                                UINT64_MAX:c->received+500000u;
                            c->addCalled=true;
                            OSObject *added=owly_peer_add(c->peer,c->metadata,c->packet);
                            found=owly_peer_find(c->peer,c->metadata);
                            c->addVerified=added && found==added &&
                                owly_peer_mac_equal(c->peer,found,c->metadata)==1;
                            if(c->addVerified) {
                                /* Parse timing/TLVs into the native object;
                                 * this does not retransmit the radio frame. */
                                c->resubmitted=true;
                                (void)owly_peer_process_action(c->peer,c->packet,12,c->metadata,72);
                                c->afterValid=owlyNativeReadPeerGate(c->peer,&c->after);
                                found=owly_peer_find(c->peer,c->metadata);
                            }
                            c->present=found && owly_peer_mac_equal(c->peer,found,c->metadata)==1;
                        }
                        owly_peer_unlock(c->peer);
                        return kIOReturnSuccess;
                    },this,&call);
                /* The exact synchronous processor frees only its own
                 * coalesced copy, never the caller's original packet. */
                mbuf_freem(m);
                const bool processed=call.afterValid &&
                    static_cast<uint32_t>(owly_native_peer_rx_af_total(&call.after)-
                                          owly_native_peer_rx_af_total(&call.gate))!=0;
                const uint64_t sample=_owlyNativeActionCalls+_owlyNativeGateBlocked;
                if(sample<4 || !(sample%64)) {
                    setProperty("OwlyNativeLastActionRSSI",static_cast<unsigned long long>(static_cast<uint32_t>(rssi)),32);
                    setProperty("OwlyNativeLastActionHeaderVersion",decoded.header_version,32);
                    setProperty("OwlyNativeLastActionSubtype",decoded.subtype,32);
                    setProperty("OwlyNativeLastActionSourceMAC",owlyNativeMacValue(pkt->src),64);
                    setProperty("OwlyNativeActionMbufLength",static_cast<unsigned long long>(length),32);
                    setProperty("OwlyNativePeerBindingMatches",call.matches);
                    if(call.afterValid)setProperty("OwlyNativeAppleActionRxTotal",owly_native_peer_rx_af_total(&call.after),32);
                }
                if(call.valid && (sample<4 || !(sample%64) || !owly_native_peer_rx_open(&call.gate))) {
                    setProperty("OwlyNativeAppleStateFlags",call.gate.flags,32);
                    setProperty("OwlyNativeAppleSyncState",call.gate.sync_state,32);
                    setProperty("OwlyNativeAppleRXGateOpen",owly_native_peer_rx_open(&call.gate));
                }
                if(status==kIOReturnSuccess && call.called) {
                    _owlyNativeActionCalls+=call.resubmitted ? 2u:1u;
                    if(call.addCalled) {
                        ++_owlyNativePeerAddAttempts;
                        if(call.addVerified && call.present)++_owlyNativePeerAddVerified;
                        else ++_owlyNativePeerAddFailed;
                    }
                    if(call.resubmitted)++_owlyNativePeerResubmissions;
                    if(sample<4 || !(sample%64) || call.addCalled || call.conflict) {
                        if(call.looked) {
                            setProperty("OwlyNativeApplePeerPresent",call.present);
                            setProperty("OwlyNativeApplePeerLookupConflict",call.conflict);
                        }
                        setProperty("OwlyNativePeerAddAttempts",_owlyNativePeerAddAttempts,64);
                        setProperty("OwlyNativePeerAddVerified",_owlyNativePeerAddVerified,64);
                        setProperty("OwlyNativePeerAddFailed",_owlyNativePeerAddFailed,64);
                        setProperty("OwlyNativePeerResubmissions",_owlyNativePeerResubmissions,64);
                    }
                    if(processed)++_owlyNativeActionsProcessed;
                    else ++_owlyNativeActionsUnprocessed;
                    if(sample<4 || !(sample%64) || !processed) {
                        setProperty("OwlyNativeActionsProcessed",_owlyNativeActionsProcessed,64);
                        setProperty("OwlyNativeActionsUnprocessed",_owlyNativeActionsUnprocessed,64);
                    }
                    submitted=processed;
                }
                else {++_owlyNativeGateBlocked;setProperty("OwlyNativeGateBlocked",_owlyNativeGateBlocked,64);}
            } else {
                if(m)mbuf_freem(m);
                ++_owlyNativeActionAllocFailures;
                setProperty("OwlyNativeActionAllocFailures",_owlyNativeActionAllocFailures,64);
            }
        }
    } else if(_owlyNativeEnabled && pkt->kind==OWLY_ABI6_PACKET_IPV6 && pkt->length>=40 && pkt->length<=OWLY_ABI6_PACKET_MAX_IPV6) {
        size_t length=14u+pkt->length;mbuf_t m=allocatePacket(static_cast<UInt32>(length));
        if(m && mbuf_len(m)>=length) {
            auto *bytes=static_cast<uint8_t *>(mbuf_data(m));
            memcpy(bytes,pkt->dst,6);memcpy(bytes+6,pkt->src,6);bytes[12]=0x86;bytes[13]=0xdd;
            memcpy(bytes+14,pkt->bytes,pkt->length);
            /* Same data route as the reference RTL software stack. The glue
             * already admitted the real recent peer/channel/destination and
             * decoded IPv6. pushPacket owns m and feeds the real awdl ifnet;
             * no opaque packet_info_tag layout or fabricated native peer. */
            owly_vif_push(vif,m);
            ++_owlyNativeDataCalls;submitted=true;
        } else if(m)freePacket(m);
    }
    owlyNativeRelease(vif,peer);return submitted;
}
UInt32 AirPortRTW89Front::owlyNativeOutput(IO80211VirtualInterface *vif,mbuf_t m)
{
    if(!m)return kIOReturnOutputDropped;
    retain();IOLockLock(_owlyVifLock);
    bool allowed=!_owlyNativeClosed && !_owlyAWDLStopping && _owlyAirlink.enabled && _owlyAirlink.cookie==vif;
    IOLockUnlock(_owlyVifLock);
    /* Bounded framing evidence, before ownership transfers to the backend.
     * Only the L2/SNAP/AWDL header is sampled, no IP or application payload. */
    const uint64_t sample=__atomic_add_fetch(&_owlyNativeTXSamples,1u,__ATOMIC_RELAXED);
    if(sample<=4 || !(sample%64)) {
        uint8_t header[30]={};const size_t length=mbuf_pkthdr_len(m);
        const size_t copied=length<sizeof(header) ? length : sizeof(header);
        setProperty("OwlyNativeTXInputLength",static_cast<unsigned long long>(length),64);
        if(copied>=14 && !mbuf_copydata(m,0,copied,header)) {
            setProperty("OwlyNativeTXInputSourceMAC",owlyNativeMacValue(header+6),64);
            setProperty("OwlyNativeTXInputType",static_cast<unsigned long long>((header[12]<<8)|header[13]),32);
            static const uint8_t snap[8]={0xaa,0xaa,3,0,0x17,0xf2,8,0};
            const bool wrapped=copied==30 && !memcmp(header+14,snap,8);
            setProperty("OwlyNativeTXInputHasSNAP",wrapped);
            setProperty("OwlyNativeTXInputHeaderVersion",wrapped ? static_cast<unsigned long long>((header[22]<<8)|header[23]) : 0ULL,32);
            setProperty("OwlyNativeTXInputHeaderReserved",wrapped ? static_cast<unsigned long long>((header[26]<<8)|header[27]) : 0ULL,32);
        }
    }
    UInt32 result=kIOReturnOutputDropped;
    bool there=allowed && backEnter();
    if(there && _back.native_output)result=_back.native_output(_back.ctx,m);
    else mbuf_freem(m);
    if(allowed)backLeave();
    release();return result;
}
