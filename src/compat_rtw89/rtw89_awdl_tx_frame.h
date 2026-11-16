// SPDX-License-Identifier: MIT
// Owly Core-04: zero-allocation, bounded AWDL Action/PSF/MIF frame serializer.
// IMPORTANT: a syntactically correct 802.11 frame is NOT an on-air-valid AWDL
// participant. Source identity, election, firmware rates, TX clock, TSF,
// channel selection, regulatory and ACK handling are NOT implemented here.
// Never enqueue these frames without an audited management TX implementation.
#ifndef RTW89_AWDL_TX_FRAME_H
#define RTW89_AWDL_TX_FRAME_H

#include <stddef.h>
#define OWLY_TX_MAX_LEN 4096u
#define OWLY_TX_HDR_LEN 40u
#define OWLY_TX_PSF 0u
#define OWLY_TX_MIF 3u

/* Explicit TLV sequence, from the Owly AWDL link-layer specification. */
static const unsigned char owly_tx_psf_types[] = {4,5,18,24,6,7,12,21};
static const unsigned char owly_tx_mif_types[] = {4,5,18,24,6,7,16,12,21};

struct owly_tx_frame {
    unsigned char *bytes;
    size_t capacity;
    size_t length;
    unsigned int next_tlv;
    unsigned int subtype;
    unsigned int active;
    unsigned int complete;
};

static inline void owly_tx_put16(unsigned char *p, unsigned short x)
{
    p[0]=(unsigned char)x; p[1]=(unsigned char)(x>>8);
}
static inline void owly_tx_put32(unsigned char *p, unsigned int x)
{
    p[0]=(unsigned char)x; p[1]=(unsigned char)(x>>8);
    p[2]=(unsigned char)(x>>16); p[3]=(unsigned char)(x>>24);
}
static inline unsigned short owly_tx_le16(const unsigned char *p)
{
    return (unsigned short)(p[0] | ((unsigned short)p[1]<<8));
}
static inline int owly_tx_addr_ok(const unsigned char *mac)
{
    unsigned int i, nz=0;
    if (!mac || (mac[0] & 1u)) return 0; /* unicast source */
    for (i=0; i<6; ++i) nz |= mac[i];
    return nz != 0;
}

/* Non-transmitting constructor. No FCS/radiotap or encrypted management flag. */
static inline int owly_tx_begin(struct owly_tx_frame *b, unsigned char *dst,
                                size_t cap, const unsigned char src[6],
                                unsigned int subtype, unsigned short seq12,
                                unsigned char header_version,
                                unsigned int phy_tx_us,
                                unsigned int target_tx_us)
{
    static const unsigned char bssid[6] = {0,0x25,0,0xff,0x94,0x73};
    unsigned int i;
    if (!b) return 0;
    *b=(struct owly_tx_frame){0};
    if (!dst || cap < OWLY_TX_HDR_LEN || cap>OWLY_TX_MAX_LEN ||
        !owly_tx_addr_ok(src) || (subtype!=OWLY_TX_PSF && subtype!=OWLY_TX_MIF) ||
        seq12>4095u || header_version==0u) return 0;
    for (i=0; i<OWLY_TX_HDR_LEN; ++i) dst[i]=0;
    dst[0]=0xd0; dst[1]=0; /* unprotected management Action */
    for (i=4;i<10;i++) dst[i]=0xff; /* broadcast destination */
    for (i=0;i<6;i++) { dst[10+i]=src[i]; dst[16+i]=bssid[i]; }
    owly_tx_put16(dst+22,(unsigned short)(seq12<<4));
    dst[24]=127; dst[25]=0; dst[26]=0x17; dst[27]=0xf2; dst[28]=8;
    dst[29]=header_version; dst[30]=(unsigned char)subtype; dst[31]=0;
    owly_tx_put32(dst+32,phy_tx_us); owly_tx_put32(dst+36,target_tx_us);
    b->bytes=dst; b->capacity=cap; b->length=OWLY_TX_HDR_LEN;
    b->subtype=subtype; b->active=1;
    return 1;
}

static inline int owly_tx_tlv_valid(unsigned int type,
                                    const unsigned char *v,size_t n)
{
    unsigned int stride;
    if (!v || n>65535u) return 0;
    switch(type) {
    case 4: /* Sync: next AW seq at value+29 */
        return n>=31u && owly_tx_le16(v+5)==16u && v[27]==4u;
    case 5: return n>=21u;
    case 18: /* 16 slots, no duplicates, 4 AW/slot */
        if (n<6 || v[0]!=15 || v[2]!=0 || v[3]!=3 ||
            v[4]!=255 || v[5]!=255) return 0;
        stride=v[1]==0 ? 1u : (v[1]==1 || v[1]==3 ? 2u : 0u);
        return stride && n>=6u+16u*stride;
    case 24: return n>=40u;
    case 6: return n>=9u;
    case 7: return n>=8u;
    case 16: /* ARPA name and DNS .local pointer */
        return n>=4u && v[0]==3 && v[1]>0 &&
               n==(size_t)v[1]+4u && v[n-2]==0xc0 && v[n-1]==0x0c;
    case 12: return n>=2u;
    case 21: return n>=2u && v[0]!=0 && v[1]!=0;
    default: return 0;
    }
}

/* Fail closed, do not change state on rejection. */
static inline int owly_tx_add(struct owly_tx_frame *b,unsigned int type,
                              const unsigned char *v,size_t n)
{
    const unsigned char *order;
    size_t order_len, i;
    if (!b || !b->active || b->complete || !b->bytes) return 0;
    if (b->subtype==OWLY_TX_MIF) {
        order=owly_tx_mif_types; order_len=sizeof(owly_tx_mif_types);
    } else {
        order=owly_tx_psf_types; order_len=sizeof(owly_tx_psf_types);
    }
    if (b->next_tlv>=order_len || type!=order[b->next_tlv] ||
        !owly_tx_tlv_valid(type,v,n) ||
        b->length>b->capacity || n>b->capacity-b->length ||
        b->capacity-b->length-n<3u) return 0;
    b->bytes[b->length]=(unsigned char)type;
    owly_tx_put16(b->bytes+b->length+1,(unsigned short)n);
    for(i=0;i<n;++i) b->bytes[b->length+3+i]=v[i];
    b->length+=n+3;
    ++b->next_tlv;
    return 1;
}

/* Software-only handoff contract for a FUTURE audited TX backend.
 * The callback MUST copy bytes if it keeps them after returning.
 * This library never supplies a callback or calls hardware itself.
 * Return convention: sink returns 0 for accepted enqueue, nonzero for refusal.
 */
typedef int (*owly_tx_sink_fn)(void *ctx,const unsigned char *frame,size_t len);
static inline int owly_tx_handoff(const struct owly_tx_frame *b,
                                  owly_tx_sink_fn sink,void *ctx)
{
    if (!b || !b->complete || !b->bytes || !sink) return 0;
    return sink(ctx,b->bytes,b->length)==0;
}

static inline int owly_tx_finish(struct owly_tx_frame *b,size_t *out_len)
{
    size_t n;
    if (!b || !b->active || b->complete || !out_len) return 0;
    n=b->subtype==OWLY_TX_MIF ? sizeof(owly_tx_mif_types):sizeof(owly_tx_psf_types);
    if (b->next_tlv!=n) return 0;
    *out_len=b->length;
    b->complete=1;
    return 1;
}
#endif
