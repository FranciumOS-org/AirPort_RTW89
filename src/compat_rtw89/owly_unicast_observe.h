/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_UNICAST_OBSERVE_H
#define OWLY_UNICAST_OBSERVE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Observation only: these helpers never admit, manufacture or modify packets. */
struct owly_tcp_observation {bool ipv6,tcp;uint8_t flags;uint16_t source,destination;uint32_t sequence,acknowledgment;};
static inline uint16_t owly_obs_be16(const uint8_t *p){return (uint16_t)((uint16_t)p[0]<<8|p[1]);}
static inline uint32_t owly_obs_be32(const uint8_t *p){return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static inline struct owly_tcp_observation owly_observe_ip(const uint8_t *ip,size_t n)
{
    struct owly_tcp_observation o={0};
    if(!ip || n<40 || ip[0]>>4!=6 || !owly_obs_be16(ip+4) || n!=40u+owly_obs_be16(ip+4))return o;
    o.ipv6=true;
    if(ip[6]!=6 || n<60)return o;
    const size_t h=(ip[52]>>4)*4u;
    if(h<20 || h>n-40)return o;
    o.tcp=true;o.flags=ip[53];o.source=owly_obs_be16(ip+40);o.destination=owly_obs_be16(ip+42);
    o.sequence=owly_obs_be32(ip+44);o.acknowledgment=owly_obs_be32(ip+48);return o;
}
static inline bool owly_observe_unicast_frame(const uint8_t *p,size_t n)
{
    static const uint8_t b[6]={0,0x25,0,0xff,0x94,0x73};
    if(!p || n<24 || (p[0]!=8 && p[0]!=0x88) || (p[4]&1))return false;
    for(unsigned i=0;i<6;i++)if(p[16+i]!=b[i])return false;
    return true;
}
static inline const uint8_t *owly_observe_frame_ip(const uint8_t *p,size_t n,size_t *size)
{
    static const uint8_t snap[8]={0xaa,0xaa,3,0,0x17,0xf2,8,0};
    *size=0;
    if(!owly_observe_unicast_frame(p,n) || (p[1]&0x43))return NULL;
    size_t at=p[0]==0x88 ? 26u : 24u;
    if(p[0]==0x88) {
        if(n<26 || (p[24]&0x80))return NULL; /* decode A-MSDU at its normal sink */
        if(p[1]&0x80)at+=4;
    }
    if(at>n || n-at<16)return NULL;
    for(unsigned i=0;i<8;i++)if(p[at+i]!=snap[i])return NULL;
    if(p[at+8]!=3 || (p[at+9]!=0 && p[at+9]!=4) || p[at+12] || p[at+13] ||
       p[at+14]!=0x86 || p[at+15]!=0xdd)return NULL;
    const uint8_t *ip=p+at+16;*size=n-at-16;
    if(!owly_observe_ip(ip,*size).ipv6){*size=0;return NULL;}
    return ip;
}
#endif
