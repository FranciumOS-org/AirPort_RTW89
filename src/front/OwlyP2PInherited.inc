/* SPDX-License-Identifier: GPL-2.0 */
/* MacKernelSDK declares these as P2P overrides, whereas pinned Legacy4C
 * actually inherits the Virtual implementation. Every corresponding live
 * image vtable entry was compared: identical target addresses in both tables.
 * Local forwarding overrides express that inheritance without importing
 * nonexistent P2P methods or changing the vendored SDK. */
    void free() override {IO80211VirtualInterface::free();}
    bool willTerminate(IOService *p,uint o) override {return IO80211VirtualInterface::willTerminate(p,o);}
    IOReturn configureReport(IOReportChannelList *c,IOReportConfigureAction a,void *r,void *d) override {return IO80211VirtualInterface::configureReport(c,a,r,d);}
    IOReturn updateReport(IOReportChannelList *c,IOReportUpdateAction a,void *r,void *d) override {return IO80211VirtualInterface::updateReport(c,a,r,d);}
    bool terminate(IOOptionBits o=0) override {return IO80211VirtualInterface::terminate(o);}
    bool attach(IOService *p) override {return IO80211VirtualInterface::attach(p);}
    void detach(IOService *p) override {IO80211VirtualInterface::detach(p);}
    IOReturn newUserClient(task_t t,void *s,UInt k,OSDictionary *d,IOUserClient **c) override {return IO80211VirtualInterface::newUserClient(t,s,k,d,c);}
    const char *stringFromReturn(IOReturn r) override {return IO80211VirtualInterface::stringFromReturn(r);}
    int errnoFromReturn(IOReturn r) override {return IO80211VirtualInterface::errnoFromReturn(r);}
    IOReturn powerStateWillChangeTo(IOPMPowerFlags p,unsigned long n,IOService *s) override {return IO80211VirtualInterface::powerStateWillChangeTo(p,n,s);}
    IOReturn powerStateDidChangeTo(IOPMPowerFlags p,unsigned long n,IOService *s) override {return IO80211VirtualInterface::powerStateDidChangeTo(p,n,s);}
    bool init(IO80211Controller *c,ether_addr *m,uint r,const char *n) override {return IO80211VirtualInterface::init(c,m,r,n);}
    UInt getMediumType() override {return IO80211VirtualInterface::getMediumType();}
    void setLinkState(IO80211LinkState s,uint r) override {IO80211VirtualInterface::setLinkState(s,r);}
    bool dequeueOutputPacketsWithServiceClass(uint q,IOMbufServiceClass s,mbuf_t *h,mbuf_t *t,UInt *n,unsigned long long *b) override {return IO80211VirtualInterface::dequeueOutputPacketsWithServiceClass(q,s,h,t,n,b);}
    void setEnabledBySystem(bool on) override {IO80211VirtualInterface::setEnabledBySystem(on);}
    void handleIoctl(unsigned long c,void *d) override {IO80211VirtualInterface::handleIoctl(c,d);}
    /* SDK spells this UInt32; the pinned implementation has no return value.
     * Native Apple callers ignore it. Always transfer ownership via the real
     * method and do not interpret a residual register as delivery status. */
    UInt32 inputPacket(mbuf_t m,packet_info_tag *p) override {owly_vif_input(this,m,p);return 0;}
    IOReturn controllerWillChangePowerState(IO80211Controller *c,unsigned long f,UInt s,IOService *p) override {return IO80211VirtualInterface::controllerWillChangePowerState(c,f,s,p);}
    IOReturn controllerDidChangePowerState(IO80211Controller *c,unsigned long f,UInt s,IOService *p) override {return IO80211VirtualInterface::controllerDidChangePowerState(c,f,s,p);}
    bool handleDebugCmd(apple80211_debug_command *d) override {return IO80211VirtualInterface::handleDebugCmd(d);}
    void signalOutputThread() override {IO80211VirtualInterface::signalOutputThread();}
    bool isOutputFlowControlled() override {return IO80211VirtualInterface::isOutputFlowControlled();}
    void setOutputFlowControlled() override {IO80211VirtualInterface::setOutputFlowControlled();}
    void clearOutputFlowControlled() override {IO80211VirtualInterface::clearOutputFlowControlled();}
    void outputStart(uint q) override {IO80211VirtualInterface::outputStart(q);}
    UInt32 configureAQMOutput() override {return IO80211VirtualInterface::configureAQMOutput();}
