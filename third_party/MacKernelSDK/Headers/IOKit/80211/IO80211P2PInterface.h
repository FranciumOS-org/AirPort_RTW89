#ifndef IO80211P2PInterface_h
#define IO80211P2PInterface_h

#include "IO80211VirtualInterface.h"

class IO80211P2PInterface : public IO80211VirtualInterface {
    OSDeclareDefaultStructors(IO80211P2PInterface)

public:
    /*
     * Only the five methods IO80211FamilyLegacy's own IO80211P2PInterface
     * vtable actually overrides. This header used to redeclare about
     * twenty-five of them; every one that the family does not define is a
     * vtable slot naming a symbol that does not exist, and a subclass built
     * here inherits all of them. The front then does not load at boot -- no
     * panic, no message, no Wi-Fi -- which is how it was found. The rest are
     * inherited from IO80211VirtualInterface and keep their slots either way,
     * so nothing is lost by leaving them out. Checked against the vtable at
     * __ZTV19IO80211P2PInterface in v1.0.0; tools/check_imports.py now holds
     * the build to it.
     */
    virtual bool createPeerManager(ether_addr *,IO80211PeerManager **) APPLE_KEXT_OVERRIDE;
    virtual void setUnitNumber(char const*) APPLE_KEXT_OVERRIDE;
    virtual bool initIfnetEparams(ifnet_init_eparams *) APPLE_KEXT_OVERRIDE;
    virtual bool attachToBpf() APPLE_KEXT_OVERRIDE;
    virtual bool configureIfnet() APPLE_KEXT_OVERRIDE;
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  0);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  1);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  2);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  3);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  4);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  5);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  6);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  7);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  8);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  9);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface, 10);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface, 11);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface, 12);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface, 13);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface, 14);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface, 15);
public:
    char buf[0x300];
};

#endif /* IO80211P2PInterface_h */
