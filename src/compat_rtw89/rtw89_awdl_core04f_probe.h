// SPDX-License-Identifier: MIT
// OWLY Core-04F: ONE synthetic, deliberately incomplete AWDL-like vendor
// action frame for RF management-TX diagnostics. THIS IS NOT A VALID PSF.
#ifndef RTW89_AWDL_CORE04F_PROBE_H
#define RTW89_AWDL_CORE04F_PROBE_H
#include <stddef.h>
#define OWLY_CORE04F_PROBE_LEN 40u
static inline int owly_core04f_build_probe(unsigned char *f, size_t cap,
                                            const unsigned char *src)
{
    static const unsigned char bssid[6] = {0x00,0x25,0x00,0xff,0x94,0x73};
    static const unsigned char mark[8] = {'O','W','L','Y','0','4','F','1'};
    unsigned int i, nonzero=0;
    if (!f || !src || cap < OWLY_CORE04F_PROBE_LEN || (src[0] & 1u))
        return 0;
    for (i=0;i<6;++i) nonzero |= src[i];
    if (!nonzero) return 0;
    for (i=0;i<OWLY_CORE04F_PROBE_LEN;++i) f[i]=0;
    f[0]=0xd0; // unprotected 802.11 management Action, To/FromDS=0
    for (i=4;i<10;++i) f[i]=0xff; // broadcast, NO_ACK
    for (i=0;i<6;++i) { f[10+i]=src[i]; f[16+i]=bssid[i]; }
    f[22]=0x10; // sequence 1 (hardware may override)
    f[24]=127; // vendor action
    f[25]=0x00; f[26]=0x17; f[27]=0xf2; f[28]=0x08; // Apple AWDL OUI/type
    f[29]=0x10; // AWDL header version 0x10
    f[30]=0;    // PSF subtype: intentionally NO TLVs, not protocol-valid
    f[31]=0;
    for (i=0;i<8;++i) f[32+i]=mark[i]; // known marker, NOT AWDL clock fields
    return 1;
}
static inline int owly_core04f_is_probe(const unsigned char *p,size_t n)
{
    static const unsigned char mark[8]={'O','W','L','Y','0','4','F','1'};
    unsigned int i;
    if (!p || n!=OWLY_CORE04F_PROBE_LEN || p[0]!=0xd0 || p[24]!=127 ||
        p[25]!=0 || p[26]!=0x17 || p[27]!=0xf2 || p[28]!=8 || p[30]!=0)
        return 0;
    for (i=0;i<8;++i) if(p[32+i]!=mark[i]) return 0;
    return 1;
}
#endif
