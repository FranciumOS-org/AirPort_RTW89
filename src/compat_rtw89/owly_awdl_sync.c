/* SPDX-License-Identifier: GPL-2.0 */
#include "owly_awdl_sync.h"
#include "owly_radio_timing.h"
#if defined(RTW89_MACOS)
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#include <string.h>

static const uint8_t bssid[6] = {0, 0x25, 0, 0xff, 0x94, 0x73};
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
static const uint8_t broadcast[6] = {255, 255, 255, 255, 255, 255};
#endif
enum { SYNC_PARAMS_WIRE_LEN = 73, CHANNEL_SEQUENCE_WIRE_LEN = 41 };
_Static_assert(40u+3u+SYNC_PARAMS_WIRE_LEN+3u+CHANNEL_SEQUENCE_WIRE_LEN==OWLY_SYNC_WIRE_OVERHEAD,
               "Fixed AWDL action frame overhead");
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (uint16_t)p[1] << 8); }
static uint16_t be16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0]<<8 | p[1]); }
static void put16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void put32(uint8_t *p, uint32_t v)
{ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static bool valid_mac(const uint8_t *p)
{ return p && !(p[0]&1u) && (p[0]|p[1]|p[2]|p[3]|p[4]|p[5]); }
static bool social(uint8_t ch) { return ch==6 || ch==44 || ch==149; }

void owly_sync_reset(struct owly_sync *s) { if (s) memset(s,0,sizeof(*s)); }

/* A bounded DNS name reader. Compression pointers must point backwards;
 * the hop and expanded-size limits also reject cycles and oversized names. */
static bool dns_name(const uint8_t *p,size_t n,size_t at,uint8_t out[256],size_t *after)
{
    if(out)memset(out,0,256);
    size_t used=0,next=0;unsigned hops=0;
    for(unsigned labels=0;labels<128;labels++) {
        if(at>=n)return false;
        uint8_t len=p[at];
        if((len&0xc0u)==0xc0u) {
            if(at+1>=n || ++hops>16)return false;
            size_t target=((size_t)(len&0x3fu)<<8)|p[at+1];
            if(target<12 || target>=at)return false;
            if(!next)next=at+2;
            at=target;continue;
        }
        if(len>63 || at+1u+len>n || used+1u+len>255)return false;
        if(out)out[used]=len;
        ++used;++at;
        for(unsigned i=0;i<len;i++) {
            uint8_t c=p[at+i];
            if(out)out[used+i]=(c>='A' && c<='Z') ? (uint8_t)(c+32) : c;
        }
        used+=len;at+=len;
        if(!len) {if(after)*after=next ? next : at;return true;}
    }
    return false;
}
static bool uuid_local(const uint8_t name[256])
{
    if(name[0]!=36 || name[37]!=5 || memcmp(name+38,"local",5) || name[43])return false;
    for(unsigned i=0;i<36;i++) {
        uint8_t c=name[i+1];
        bool dash=i==8 || i==13 || i==18 || i==23;
        if(dash ? c!='-' : !((c>='0' && c<='9') || (c>='a' && c<='f')))return false;
    }
    return true;
}
static bool mdns_local_host(const uint8_t *dns,size_t n,const uint8_t ip[16],uint8_t host[36])
{
    if(n<12 || n>1800 || !(dns[2]&0x80u) || (dns[2]&0x78u) || (dns[3]&15u))return false;
    const unsigned questions=be16(dns+4);
    const unsigned records=(unsigned)be16(dns+6)+be16(dns+8)+be16(dns+10);
    if(questions>16 || !records || records>64)return false;
    uint8_t name[256],candidate[36];bool found=false;
    for(unsigned pass=0;pass<2;pass++) {
        size_t at=12;
        for(unsigned i=0;i<questions;i++) {
            if(!dns_name(dns,n,at,NULL,&at) || n-at<4)return false;
            at+=4;
        }
        bool matched=false;
        for(unsigned i=0;i<records;i++) {
            if(!dns_name(dns,n,at,name,&at) || n-at<10)return false;
            const unsigned type=be16(dns+at),klass=be16(dns+at+2)&0x7fffu;
            const bool live=(dns[at+4]|dns[at+5]|dns[at+6]|dns[at+7])!=0;
            const size_t size=be16(dns+at+8);at+=10;
            if(size>n-at)return false;
            if(pass==0 && !found && live && klass==1 && type==28 && size==16 &&
               uuid_local(name) && !memcmp(dns+at,ip,16)) {
                memcpy(candidate,name+1,36);found=true;
            }
            if(pass==1 && live && klass==1 && type==33 && size>=7) {
                size_t end;
                if(!dns_name(dns,n,at+6,name,&end) || end!=at+size)return false;
                if(uuid_local(name) && !memcmp(name+1,candidate,36))matched=true;
            }
            at+=size;
        }
        if(at!=n || !found)return false;
        if(pass==1 && !matched)return false;
    }
    memcpy(host,candidate,36);return true;
}
bool owly_sync_note_tx(struct owly_sync *s,const uint8_t *eth,size_t n)
{
    if(!s || !eth || n<14 || !valid_mac(s->mac) || memcmp(eth+6,s->mac,6))return false;
    size_t off;
    const unsigned type=be16(eth+12);
    if(type==0x86ddu)off=14;
    else {
        static const uint8_t snap[8]={0xaa,0xaa,3,0,0x17,0xf2,8,0};
        if(type>1500 || type!=n-14 || n<30 || memcmp(eth+14,snap,8) ||
           eth[22]!=3 || (eth[23]!=0 && eth[23]!=4) || eth[28]!=0x86 || eth[29]!=0xdd)return false;
        off=30;
    }
    if(n-off<60)return false;
    const uint8_t *ip=eth+off;
    const size_t length=n-off;
    static const uint8_t group[16]={0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0xfb};
    uint8_t local[16]={0xfe,0x80,0,0,0,0,0,0,0,0,0,0xff,0xfe,0,0,0};
    local[8]=s->mac[0]^2u;local[9]=s->mac[1];local[10]=s->mac[2];
    memcpy(local+13,s->mac+3,3);
    if(ip[0]>>4!=6 || be16(ip+4)!=length-40 || ip[6]!=17 || ip[7]!=255 ||
       memcmp(ip+8,local,16) || memcmp(ip+24,group,16) ||
       be16(ip+40)!=5353 || be16(ip+42)!=5353 || be16(ip+44)!=length-40)return false;
    uint8_t host[36];
    if(!mdns_local_host(ip+48,length-48,local,host))return false;
    bool changed=!s->have_host || memcmp(s->host,host,36);
    memcpy(s->host,host,36);s->have_host=true;
    return changed;
}

#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
static void clear_mi(struct owly_sync *s)
{
    memset(&s->auto_mi,0,sizeof(s->auto_mi));
    memset(&s->pending_mi,0,sizeof(s->pending_mi));
    s->broadcast_mif_submitted=false;
    s->last_broadcast_mif=false;
}
#endif

int owly_sync_template(struct owly_sync *s,const uint8_t *p,size_t n,const uint8_t mac[6])
{
    size_t pos=0, kept=0;
    unsigned seen_version=0, seen_service=0, count=0, kept_count=0;bool native_arpa=false;
    if (!s) return -1;
    if (!p && !n) {
        s->active=false; s->template_len=0; s->due_us=0;
        s->native_arpa=s->have_host=false;memset(s->host,0,sizeof(s->host));
        memset(s->template_bytes,0,sizeof(s->template_bytes));
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        clear_mi(s);
#endif
        return 0;
    }
    if (!p || !n || n>OWLY_SYNC_TEMPLATE_MAX || !valid_mac(mac)) return -1;
    /* Validate before committing. This API borrows a separate kernel buffer;
     * overlap with state is not a supported way to update a live template. */
    if ((uintptr_t)p < (uintptr_t)s+sizeof(*s) &&
        (uintptr_t)s < (uintptr_t)p+n) return -1;
    while (pos<n) {
        unsigned type;
        size_t m;
        if (n-pos<3 || ++count>64) return -1;
        type=p[pos]; m=le16(p+pos+1);
        if (m>n-pos-3) return -1;
        if (type==21) {
            if (++seen_version!=1 || m<2 || !p[pos+3] || !p[pos+4]) return -1;
        }
        if (type==6) {
            /* Apple's native service template need not repeat Version TLV. */
            if (m<9) return -1;
            ++seen_service;
        }
        if(type==16)native_arpa=true;
        if (type!=4 && type!=18) {
            if (++kept_count>62) return -1;
            kept+=3+m;
        }
        pos+=3+m;
    }
    if ((!seen_version && !seen_service) || !kept) return -1;
    pos=kept=0;
    while (pos<n) {
        size_t m=3u+le16(p+pos+1);
        if (p[pos]!=4 && p[pos]!=18) {
            memcpy(s->template_bytes+kept,p+pos,m); kept+=m;
        }
        pos+=m;
    }
    memset(s->template_bytes+kept,0,sizeof(s->template_bytes)-kept);
    if(memcmp(s->mac,mac,6)) {
        s->have_host=false;
        memset(s->host,0,sizeof(s->host));
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        clear_mi(s);
#endif
    }
    memcpy(s->mac,mac,6); s->template_len=kept;s->native_arpa=native_arpa;
    return 0;
}

#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
int owly_sync_mi(struct owly_sync *s, bool automatic, const uint8_t destination[6],
                 const uint8_t *p, size_t n, const uint8_t mac[6],
                 uint8_t channel, uint64_t now)
{
    if (!s || !destination || !valid_mac(mac) ||
        (!social(channel) && !(automatic && channel==0)) ||
        (valid_mac(s->mac) && memcmp(s->mac,mac,6))) return OWLY_MI_INVALID;
    const bool group=!memcmp(destination,broadcast,6);
    if (!group && (automatic || !valid_mac(destination) || !memcmp(destination,mac,6)))
        return OWLY_MI_INVALID;
    struct owly_mi_template *mi=automatic ? &s->auto_mi : &s->pending_mi;
    if (automatic && !p && !n) {
        memset(mi,0,sizeof(*mi));
        return 0;
    }
    if (!p || !n || n>OWLY_MI_TEMPLATE_MAX ||
        ((uintptr_t)p < (uintptr_t)s+sizeof(*s) && (uintptr_t)s < (uintptr_t)p+n))
        return OWLY_MI_INVALID;

    /* Validate the whole Legacy MI before touching the live scheduler.
     * The native V2 election record leads every MI from this family. */
    if (n<43 || p[0]!=24 || le16(p+1)!=40) return OWLY_MI_INVALID;
    bool has_arpa=false, changed=false;
    size_t kept=0;
    for (size_t at=0;at<n;) {
        if (n-at<3) return OWLY_MI_INVALID;
        const uint8_t type=p[at];
        const size_t size=3u+le16(p+at+1);
        if (size>n-at || (type==24 && at)) return OWLY_MI_INVALID;
        if (type!=4 && type!=18) {
            if (kept+size>mi->length || memcmp(mi->bytes+kept,p+at,size))
                changed=true;
            kept+=size;
            has_arpa|=type==16;
        }
        at+=size;
    }
    changed|=kept!=mi->length;
    if (!automatic && mi->length && channel==s->pending_mi_channel &&
        now>=s->pending_mi_us && now-s->pending_mi_us<OWLY_MI_PENDING_US) {
        if (!changed && !memcmp(destination,s->pending_mi_destination,6)) return 0;
        return OWLY_MI_BUSY;
    }
    if (changed) {
        size_t out=0;
        for (size_t at=0;at<n;) {
            const size_t size=3u+le16(p+at+1);
            if (p[at]!=4 && p[at]!=18) {
                memcpy(mi->bytes+out,p+at,size);
                out+=size;
            }
            at+=size;
        }
        mi->length=kept;
        mi->has_arpa=has_arpa;
    }
    if (automatic) {
        /* The broadcast template belongs to this VIF, even when Apple
         * sets it before association. Only the worker puts it on air
         * with the current bound channel's synchronization fields. */
        if (changed && s->mif_due_us>now) s->mif_due_us=now;
    } else {
        s->pending_mi_us=now;
        s->pending_mi_channel=channel;
        memcpy(s->pending_mi_destination,destination,6);
    }
    if (!s->template_len) memcpy(s->mac,mac,6);
    return 0;
}
#endif

void owly_sync_request(struct owly_sync *s,bool on)
{
    if (!s) return;
    s->requested=on;
    s->explicitly_disabled=!on;
    if (!on) {
        s->active=false; s->due_us=0; s->blocked=false;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        s->mif_due_us=0;
        /* Legacy supplies SET225 and SET151 before the SET117 off/on
         * pair that resets its election. Keep the registered broadcast
         * for that VIF. Pending directed responses belong to the old clock. */
        memset(&s->pending_mi,0,sizeof(s->pending_mi));
        s->pending_mi_ready=false;
        s->broadcast_mif_submitted=false;
        s->last_broadcast_mif=false;
#endif
    }
}

bool owly_sync_configured(const struct owly_sync *s)
{
    return s && s->requested && s->template_len && !s->blocked;
}

void owly_sync_reconcile(struct owly_sync *s,bool ready,uint8_t ch,uint64_t now)
{
    bool can;
    if (!s) return;
    can=ready && social(ch) && owly_sync_configured(s);
    if (!can) { s->active=false; s->due_us=0; return; }
    if (!s->active || s->channel!=ch) {
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        if (s->channel!=ch) s->broadcast_mif_submitted=false;
#endif
        s->channel=ch;
        s->due_us=now;
        s->last_us=now;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        s->mif_due_us=now;
#endif
    }
    s->active=true;
}

int owly_sync_frame(struct owly_sync *s,uint64_t now,uint8_t *f,size_t cap,size_t *length)
{
    uint64_t due, elapsed, missed, period;
    size_t n, pos;
    uint8_t *v;
    unsigned i;
    bool follow=false;
    if (!s || !f || !length) return -1;
    *length=0;
    if (!s->active) return 0;
    if (now<s->last_us) { s->active=false; s->blocked=true; return 0; }
    const uint8_t *template_bytes=s->template_bytes;
    size_t template_len=s->template_len;
    bool native_arpa=s->native_arpa;
    bool mif, advance_psf;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    if (s->pending_mi.length && (s->pending_mi_channel!=s->channel ||
        now<s->pending_mi_us || now-s->pending_mi_us>=OWLY_MI_PENDING_US))
        s->pending_mi.length=0;
    const bool mif_due=now>=s->mif_due_us;
    const bool psf_due=now>=s->due_us;
    const bool psf_ready=psf_due && (!s->hold_for_peer || now-s->due_us>=OWLY_MI_PENDING_US);
    const bool one_shot=s->pending_mi.length && s->pending_mi_ready &&
                        (!psf_ready || s->pending_mi_us<s->due_us);
    /* A broadcast PSF may be held for a different peer than the one-shot
     * MI. Among eligible broadcasts, choose the oldest deadline, with PSF
     * first at startup when both deadlines are equal. */
    mif=one_shot || (mif_due && (!psf_ready || s->mif_due_us<s->due_us));
    due=one_shot ? s->pending_mi_us : mif ? s->mif_due_us : s->due_us;
    advance_psf=!mif;
    const struct owly_mi_template *mi=one_shot ? &s->pending_mi :
        mif && s->auto_mi.length ? &s->auto_mi : NULL;
    if (mi) {
        template_bytes=mi->bytes;
        template_len=mi->length;
        native_arpa=mi->has_arpa;
    }
#else
    mif=(s->staged&1u) != 0;
    due=s->due_us;
    advance_psf=true;
#endif
    n=OWLY_SYNC_WIRE_OVERHEAD+template_len;
    if (cap<n || cap>OWLY_SYNC_FRAME_MAX) return -1;
    const bool add_arpa=mif && s->have_host && !native_arpa && cap-n>=43u;
    const size_t template_end=n;
    if(add_arpa)n+=43u;
    s->last_us=now;
    if (now<due) return 0;
    period=s->native.psf_period_ms ? (uint64_t)s->native.psf_period_ms*1000u : OWLY_SYNC_AF_US;
    elapsed=now-due;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    /* A known peer can leave this channel for most of the 16-slot cycle. */
    if (!one_shot && s->hold_for_peer && elapsed<OWLY_MI_PENDING_US) return 0;
#else
    if (s->hold_for_peer && elapsed<period) return 0;
#endif
    if (UINT64_MAX-now<period+6u*OWLY_SYNC_AW_US) {
        s->active=false; s->blocked=true; return 0;
    }
    if (advance_psf) {
        missed=elapsed/period;
        s->skipped+=missed;
        s->due_us=due+(missed+1u)*period;
    }
    memset(f,0,n);
    f[0]=0xd0;
    memset(f+4,255,6);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    if (one_shot) memcpy(f+4,s->pending_mi_destination,6);
#endif
    memcpy(f+10,s->mac,6); memcpy(f+16,bssid,6);
    put16(f+22,(uint16_t)((s->sequence++ & 4095u)<<4));
    f[24]=127; f[26]=0x17; f[27]=0xf2; f[28]=8; f[29]=0x10;
    f[30]=mif ? 3u : 0u;
    /* The countdown below describes this opportunity. A deferred due time
     * is not a measured RF timestamp and must not appear as airtime jitter. */
    put32(f+32,(uint32_t)now); put32(f+36,(uint32_t)now);
    f[40]=4; put16(f+41,SYNC_PARAMS_WIRE_LEN);
    v=f+43;
    uint16_t sequence=(uint16_t)(now/OWLY_SYNC_AW_US);
    uint16_t until_aw=(uint16_t)((OWLY_SYNC_AW_US-now%OWLY_SYNC_AW_US+1023u)/1024u);
    uint16_t advertised_slots = UINT16_MAX;
    v[0]=s->channel;
    v[3]=s->channel;
    put16(v+5,16); put16(v+7,(uint16_t)(period/1000u)); put16(v+9,0x1800);
    put16(v+11,16); put16(v+13,16);
    v[17]=v[18]=v[19]=v[20]=3;
    memcpy(v+21,s->mac,6); v[27]=4;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    follow=s->peer_clock.active && s->peer_clock.remote &&
       s->peer_clock.channel==s->channel && s->have_master_election &&
       !memcmp(s->master_election,s->peer_clock.master,6) &&
       now>=s->peer_clock.sampled_us && now-s->peer_clock.sampled_us<OWLY_SYNC_AW_US;
    if(follow) {
        memcpy(v+21,s->peer_clock.master,6);
        if(s->peer_clock.master_channel)
            v[3]=s->peer_clock.master_channel;
        if(!owly_radio_project_window(s->peer_clock.sampled_us,s->peer_clock.sequence,
               s->peer_clock.until_next_tu,now,&sequence,&until_aw))return 0;
        if (s->shared_slots)
            advertised_slots = s->shared_slots;
    }
    /* Multichannel: advertise only the slots we really spend here. */
    if (s->presence_slots) {
        advertised_slots &= s->presence_slots;
        if (!advertised_slots)
            advertised_slots = s->presence_slots;
    }
#endif
    /* Peers use the slot countdown even when every slot uses one channel.
     * The short remaining field describes the first AW in that slot. */
    const uint16_t until_slot=(uint16_t)(until_aw+(3u-(sequence&3u))*16u);
    put16(v+1,until_slot);
    put16(v+15,until_slot>48u ? (uint16_t)(until_slot-48u) : 0u);
    put16(v+29,sequence);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    if (mif && !one_shot) {
        /* When tracking a peer, keep the MIF due at the next slot edge.
         * The link gate will move it to the first open AW on this channel.
         * Waiting for the middle can miss the only listening AW. */
        s->mif_due_us=now+((uint64_t)until_slot+(follow ? 0u : 32u))*1024u;
    }
#endif
    /* The embedded sequence uses the legacy flag/channel pairs from Apple
     * captures. The standalone sequence uses primary and operating class. */
    v[33]=15; v[34]=1; v[35]=0; v[36]=3; v[37]=v[38]=255;
    const uint8_t legacy_center = s->channel == 6 ? 6 : s->channel + 2;
    for (i=0;i<16;i++) {
        if (!(advertised_slots & (1u << i))) continue;
        v[39+2*i]=s->channel==6 ? 0x2b : 0x1d;
        v[40+2*i]=legacy_center;
    }
    pos=40u+3u+SYNC_PARAMS_WIRE_LEN;
    f[pos]=18; put16(f+pos+1,CHANNEL_SEQUENCE_WIRE_LEN); v=f+pos+3;
    v[0]=15; v[1]=3; v[2]=0; v[3]=3; v[4]=v[5]=255;
    for (i=0;i<16;i++) {
        if (!(advertised_slots & (1u << i))) continue;
        v[6+2*i]=s->channel;
        v[7+2*i]=s->channel==6 ? 0x51 : 0x80;
    }
    pos+=3u+CHANNEL_SEQUENCE_WIRE_LEN;
    memcpy(f+pos,template_bytes,template_len);
    if(add_arpa) {
        uint8_t *host=f+template_end;
        host[0]=16;put16(host+1,40);host[3]=3;host[4]=36;
        memcpy(host+5,s->host,36);host[41]=0xc0;host[42]=0x0c;
    }
    /* Render one consistent election across Sync, v1 and v2. Copying only
     * 20 bytes left the local metric as the root metric, and incorrectly
     * repeated the root's zero distance. Never alter native own metric or
     * own counter. The original Apple template remains immutable. */
    uint8_t root[24]={};bool election=false;
    for(size_t at=pos;at+3<=template_end;) {
        const size_t size=le16(f+at+1);if(size>template_end-at-3)break;
        if(f[at]==24 && size>=40) {
            v=f+at+3;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
            if(follow) {
                memcpy(v,s->master_election,24);put32(v+16,1);
            } else
#endif
            {
                memcpy(v,s->mac,6);memcpy(v+6,s->mac,6);
                memcpy(v+12,v+36,4);put32(v+16,0);memcpy(v+20,v+24,4);
            }
            memcpy(root,v,24);election=true;
        }
        at+=3+size;
    }
    for(size_t at=pos;at+3<=template_end;) {
        const size_t size=le16(f+at+1);if(size>template_end-at-3)break;
        v=f+at+3;
        if(f[at]==5 && size>=21) {
            if(election) {v[3]=root[16];memcpy(v+5,root,6);memcpy(v+11,root+20,4);}
            else {v[3]=0;memcpy(v+5,s->mac,6);memcpy(v+11,v+15,4);}
        } else if(f[at]==12 && size>=2) {
            /* Country and all local identities stay native. Only correct
             * the advertised social-channel map to the radio we serve.
             * Optional fields precede this map according to the flags. */
            const uint16_t flags=le16(v);
            const size_t map=2u+((flags&0x100u) ? 3u : 0u);
            if((flags&0x200u) && map+2u<=size)
                put16(v+map,s->channel==6 ? 1u : s->channel==44 ? 2u : 4u);
        }
        at+=3+size;
    }
    (void)follow;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    s->last_pending_mi=one_shot;
    s->last_native_mi=mi!=NULL;
    s->last_broadcast_mif=mif && !one_shot;
#endif
    ++s->staged; *length=n;
    return 1;
}

void owly_sync_result(struct owly_sync *s,int rc)
{
    if (!s) return;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    const bool retry=rc==-ENOMEM || rc==-ENOSPC || rc==-EBUSY;
    if (s->last_broadcast_mif) {
        if (!rc) s->broadcast_mif_submitted=true;
        else if (retry && !s->broadcast_mif_submitted) s->mif_due_us=s->last_us;
        s->last_broadcast_mif=false;
    }
    if (s->last_pending_mi && !retry) s->pending_mi.length=0;
    s->last_pending_mi=false;
    if (rc && (s->last_native_mi || retry)) {
        ++s->failed;
        return;
    }
    if (s->last_native_mi) ++s->native_mi_handed_off;
#endif
    if (!rc) ++s->handed_off;
    else { ++s->failed; s->active=false; s->blocked=true; }
}
