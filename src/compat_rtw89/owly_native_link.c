/* SPDX-License-Identifier: GPL-2.0 */ /* Modified 2026-11-15: BlockAck reply/dynamic-CAM fixes; see MODIFICATIONS.md. */
#include "owly_native_link.h"
#include "owly_native_scan_policy.h"
#include "rtw89_awdl_action_decode.h"
#if defined(RTW89_MACOS)
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#include <string.h>
static const uint8_t bssid[6]={0,0x25,0,0xff,0x94,0x73};
static const uint8_t snap[8]={0xaa,0xaa,3,0,0x17,0xf2,8,0};
/* Both mDNS and unicast may have to wait for one visit per channel sequence. */
#define OWLY_LINK_CYCLE_US (16u * 4u * OWLY_LINK_AW_US)
#define OWLY_LINK_TX_TTL_US (OWLY_LINK_CYCLE_US + OWLY_LINK_AW_US)
#define OWLY_LINK_SCAN_CREDIT_US 2000000ull
#define OWLY_LINK_RECENT_ACTION_US 4096u
#define OWLY_LINK_IDLE_MAX_SLOTS 5u
#define OWLY_LINK_PEER_AWAKE_US 100000u
#define OWLY_LINK_IDLE_AW_US 4000u
#define OWLY_LINK_IDLE_RETURN_GUARD_US 1024u
_Static_assert(OWLY_LINK_QUEUE<=32u,"TX occupancy mask must cover the entire queue");
static bool mac_ok(const uint8_t *a) {return a && !(a[0]&1u) && (a[0]|a[1]|a[2]|a[3]|a[4]|a[5]);}
static bool channel_ok(uint8_t c) {return c==6 || c==44 || c==149;}
static uint16_t be16(const uint8_t *p) {return (uint16_t)((uint16_t)p[0]<<8|p[1]);}
static void put16(uint8_t *p,uint16_t v) {p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static bool ip_ok(const uint8_t *ip,size_t n) {return ip && n>=41 && ip[0]>>4==6 && be16(ip+4) && n==40u+be16(ip+4);}
static bool overlap(const void *a,size_t an,const void *b,size_t bn) {
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return an && bn && (x<=y ? y-x<an : x-y<bn);
}
static bool fresh(const struct owly_link_peer *p,uint64_t now) {
    return owly_link_peer_alive(p,now);
}
static void expire(struct owly_native_link *s,uint64_t now) {
    unsigned i;
    if(now<s->last_now_us) {
        memset(s->peers,0,sizeof(s->peers));s->tx_expired+=s->count;s->head=s->count=0;
        s->queue_used=0;
        s->last_unicast_activity_us=0;
        s->preferred_us=now;
        s->pause_started_us=s->tx_paused ? now : 0;
        ++s->generation;
    }
    s->last_now_us=now;
    for(i=0;i<OWLY_LINK_PEERS;i++) if(s->peers[i].used && !fresh(&s->peers[i],now))
        memset(&s->peers[i],0,sizeof(s->peers[i]));
}

/* RX samples are taken before the link lock. A timer or output callback
 * can advance last_now_us before this sample is processed. Keep that sample
 * for phase calculation while aging state with monotonic housekeeping time. */
static uint64_t rx_housekeeping_time(const struct owly_native_link *s,uint64_t sample_us)
{
    return sample_us < s->last_now_us ? s->last_now_us : sample_us;
}
void owly_link_reset(struct owly_native_link *s) {if(s) memset(s,0,sizeof(*s));}
void owly_link_reconcile(struct owly_native_link *s,bool active,const uint8_t local[6],uint8_t ch,uint64_t now) {
    if(!s)return;
    active=active && mac_ok(local) && channel_ok(ch);
    if(active!=s->active || (active && (s->channel!=ch || memcmp(s->local,local,6)))) {
        memset(s->peers,0,sizeof(s->peers));s->tx_expired+=s->count;s->head=s->count=0;
        s->queue_used=0;
        s->last_unicast_activity_us=0;
        memset(s->preferred,0,6);s->preferred_us=0;++s->generation;
        s->tx_paused=false;s->pause_started_us=0;
    }
    s->active=active;
    if(active) {memcpy(s->local,local,6);s->channel=ch;}
    else {memset(s->local,0,6);s->channel=0;s->sync_enabled=false;}
    expire(s,now);
}

void owly_link_set_tx_paused(struct owly_native_link *s,bool paused,uint64_t now)
{
    if(s->tx_paused==paused)return;
    if(paused) {
        s->tx_paused=true;
        s->pause_started_us=now;
        return;
    }
    /* Count only the scan time each packet actually spent waiting. Bound
     * the extra lifetime even if several scans interrupt one packet. */
    for(unsigned i=0;i<s->count;i++) {
        struct owly_link_frame *f=&s->queue[s->queue_order[(s->head+i)%OWLY_LINK_QUEUE]];
        const uint64_t start=f->queued_us>s->pause_started_us ? f->queued_us : s->pause_started_us;
        const uint64_t held=now>start ? now-start : 0;
        const uint64_t budget=OWLY_LINK_SCAN_CREDIT_US-f->pause_credit_us;
        f->pause_credit_us+=held<budget ? held : budget;
    }
    s->tx_paused=false;
    s->pause_started_us=0;
}
static struct owly_link_peer *find(struct owly_native_link *s,const uint8_t mac[6]) {
    unsigned i;for(i=0;i<OWLY_LINK_PEERS;i++)if(s->peers[i].used&&!memcmp(s->peers[i].mac,mac,6))return &s->peers[i];
    return NULL;
}
static bool sync_master(const uint8_t *raw,size_t n,uint8_t master[6],
                        uint16_t *remaining,uint8_t *presence) {
    size_t at=40;
    while(at+3<=n) {size_t z=owly_le16(raw+at+1);if(z>n-at-3)return false;
        if(raw[at]==4) {
            if(z<31 || !mac_ok(raw+at+3+21))return false;
            memcpy(master,raw+at+3+21,6);
            *remaining=owly_le16(raw+at+3+15);
            *presence=raw[at+3+27];
            return true;
        }
        at+=3+z;
    }return false;
}
static uint16_t aw_countdown(const struct owly_action_info *d,uint16_t remaining,uint8_t presence)
{
    if(presence!=4u)return 0;
    const uint16_t slot=d->tx_down_tu;
    const unsigned aw=d->next_aw_seq&3u;
    /* iOS publishes the time left in the four-AW slot at offset 1.
     * Offset 15 can be zero after the first AW. Require the countdown
     * and advertised AW index to agree before treating it as a clock. */
    if(slot && slot<=64u && (64u-slot)/16u==aw)
        return (uint16_t)(slot-(3u-aw)*16u);
    return remaining; /* Older single-channel peers may only fill offset 15. */
}

/* One late sample (host or ring delay) must not throw away a clock that
 * several windows agreed on; three in a row mean the clock really moved. */
#define OWLY_LINK_CLOCK_ERROR_US 4000u
#define OWLY_LINK_CLOCK_OUTLIERS 3u
static void sample_peer_clock(struct owly_native_link *s,struct owly_link_peer *p,
                              const struct owly_action_info *d,
                              const uint8_t master[6],uint16_t countdown,uint64_t now)
{
    const bool is_root=!memcmp(p->mac,master,6);
    if(!is_root || memcmp(p->master,master,6) ||
       (p->clock_rx_us && now-p->clock_rx_us>OWLY_LINK_PEER_TTL_US)) {
        p->clock_rx_us=0;
        p->consistent=0;
        p->outliers=0;
        p->clock_valid=false;
    }
    if(!is_root) {++s->clock_not_root;return;}
    if(!countdown) {++s->clock_no_countdown;return;}

    uint64_t anchor=now+(uint64_t)countdown*1024u;
    /* The sequence names the current AW. The boundary ahead starts AW+1. */
    const uint16_t next=(uint16_t)(d->next_aw_seq+1u);
    if(p->clock_rx_us) {
        const uint16_t delta=(uint16_t)(next-p->next_seq);
        const uint64_t predicted=p->anchor_us+(uint64_t)delta*OWLY_LINK_AW_US;
        const uint64_t error=predicted>anchor ? predicted-anchor : anchor-predicted;
        if(delta && delta<32768u && error<=OWLY_LINK_CLOCK_ERROR_US) {
            if(p->consistent<65535u)++p->consistent;
            p->clock_valid=p->consistent>=2u;
            p->outliers=0;
            ++s->clock_ok;
            /* Smooth bounded host-RX jitter across consecutive windows. */
            anchor=predicted>anchor ? predicted-(predicted-anchor)/4u : predicted+(anchor-predicted)/4u;
        } else if(!delta && now-p->clock_rx_us<OWLY_LINK_AW_US) {
            anchor=p->anchor_us;
        } else if(p->clock_valid && delta && delta<32768u &&
                  ++p->outliers<OWLY_LINK_CLOCK_OUTLIERS) {
            /* Keep the agreed clock; this sample alone disagrees. */
            ++s->clock_outlier;
            return;
        } else {
            ++s->clock_reset;
            p->consistent=0;
            p->outliers=0;
            p->clock_valid=false;
        }
    }
    p->anchor_us=anchor;
    p->next_seq=next;
    p->clock_rx_us=now;
}

bool owly_link_observe(struct owly_native_link *s,const uint8_t *raw,size_t n,uint8_t ch,int8_t rssi,uint64_t now) {
    struct owly_action_info d;struct owly_link_peer *p;uint8_t master[6],presence;
    unsigned i,slot=OWLY_LINK_PEERS;uint64_t oldest=UINT64_MAX;uint16_t remaining;
    if(!s || !s->active || ch!=s->channel || rssi>=0 || rssi<-127 || !now ||
       owly_decode_action(raw,n,&d)!=OWLY_ACTION_DECODED || !d.complete ||
       (raw[1]&4u) || (raw[22]&15u) ||
       !mac_ok(raw+10) || !memcmp(raw+10,s->local,6) || d.aw_period_tu!=16 ||
       !sync_master(raw,n,master,&remaining,&presence) || remaining>d.aw_period_tu) {
        if(s)++s->rejected_actions;
        return false;
    }
    const uint64_t current=rx_housekeeping_time(s,now);
    if(current-now>OWLY_LINK_PEER_TTL_US) {++s->rejected_actions;return false;}
    expire(s,current);p=find(s,raw+10);
    if(!p) {
        for(i=0;i<OWLY_LINK_PEERS;i++) {
            if(!s->peers[i].used) {slot=i;break;}
            if(s->peers[i].last_rx_us<oldest) {oldest=s->peers[i].last_rx_us;slot=i;}
        }
        p=&s->peers[slot];memset(p,0,sizeof(*p));p->used=true;memcpy(p->mac,raw+10,6);
    }
    if(p->last_rx_us && now<=p->last_rx_us) {++s->rejected_actions;return false;}
    if(memcmp(p->master,master,6)) {
        p->has_election=false;memset(p->election,0,sizeof(p->election));
        p->last_mif_rx_us=0;
        p->master_channel=0;
    }
    sample_peer_clock(s,p,&d,master,aw_countdown(&d,remaining,presence),now);
    p->last_rx_us=now;
    p->rssi=rssi;p->channel=ch;
    /* iOS sends MIFs with this field zero while keeping the same master.
     * A frame heard on the AP channel does not locate the master's channel. */
    if(channel_ok(d.master_channel))p->master_channel=d.master_channel;
    memcpy(p->master,master,6);
    /* A peer may advertise its infrastructure channel in other slots.
     * Retain its identity from this real SCC action; mark those slots unavailable. */
    p->local_slots=0;
    for(i=0;i<16;i++) {
        p->channels[i]=channel_ok(d.channels[i]) ? d.channels[i] : 0;
        p->local_slots+=p->channels[i]==ch;
    }
    /* PSFs are also heard on social-channel visits outside the peer's
     * data schedule. An on-schedule MIF is stronger evidence of presence. */
    if(d.subtype==3 && p->channels[(d.next_aw_seq/4u)&15u]==ch)
        p->last_mif_rx_us=now;
    for(size_t at=40;at+3<=n;) {
        size_t size=owly_le16(raw+at+1);if(size>n-at-3)break;
        if(raw[at]==24 && size>=40) {
            const uint8_t *v=raw+at+3;
            /* This software clock follows only a root heard directly. A
             * relay or contradictory root prefix cannot authorize a root
             * metric. In particular distance 0 belongs to that root only. */
            p->has_election=!memcmp(v,master,6) && !memcmp(master,p->mac,6) &&
                !memcmp(v+6,p->mac,6) && !v[16] && !v[17] && !v[18] && !v[19];
            if(p->has_election)memcpy(p->election,v,sizeof(p->election));
            else memset(p->election,0,sizeof(p->election));
        }
        at+=3+size;
    }
    ++s->actions;return true;
}
static bool clock_fresh(const struct owly_link_peer *p,uint64_t now)
{
    return p->clock_valid && now>=p->clock_rx_us && now-p->clock_rx_us<=OWLY_LINK_PEER_TTL_US;
}
static bool waiting_for_master(const struct owly_native_link *s,uint64_t now)
{
    return mac_ok(s->preferred) && now>=s->preferred_us &&
        now-s->preferred_us<=OWLY_LINK_PEER_TTL_US;
}
static struct owly_link_peer *master_peer(struct owly_native_link *s,uint64_t now) {
    struct owly_link_peer *best=NULL,*preferred=NULL;unsigned i;
    for(i=0;i<OWLY_LINK_PEERS;i++) {
        struct owly_link_peer *p=&s->peers[i];
        if(!fresh(p,now) || !clock_fresh(p,now))continue;
        if(!best || p->rssi>best->rssi || (p->rssi==best->rssi && memcmp(p->mac,best->mac,6)<0))best=p;
        if(!memcmp(s->preferred,p->mac,6))preferred=p;
    }
    if(preferred) {
        if(s->preferred_us<preferred->clock_rx_us)s->preferred_us=preferred->clock_rx_us;
        return preferred;
    }
    /* An old Apple election choice cannot keep every later session waiting
     * for a peer that left the channel or changed its address. */
    return waiting_for_master(s,now) ? NULL : best;
}
uint8_t owly_link_follow_channel(struct owly_native_link *s,uint64_t now)
{
    if (!s || !s->active) return 6;
    expire(s,now);
    struct owly_link_peer *p=master_peer(s,now);
    if (!p) return 6;
    const uint8_t channels[3]={6,44,149};
    uint8_t want=6; unsigned most=0;
    for(unsigned i=0;i<3;i++) {
        unsigned slots=0;
        for(unsigned j=0;j<16;j++)slots+=p->channels[j]==channels[i];
        if(slots>most || (slots && slots==most && channels[i]==s->channel)) {
            most=slots; want=channels[i];
        }
    }
    return want;
}

/* Multichannel: the social channel fresh peers use most in their own
 * sequences, 0 when none has told us. Ties keep the current channel. */
uint8_t owly_link_peer_channel(struct owly_native_link *s,uint64_t now)
{
    static const uint8_t channels[3]={6,44,149};
    unsigned count[3]={0,0,0},most=0;
    uint8_t want=0;
    if(!s)return 0;
    expire(s,now);
    for(unsigned i=0;i<OWLY_LINK_PEERS;i++) {
        const struct owly_link_peer *p=&s->peers[i];
        if(!fresh(p,now))continue;
        for(unsigned j=0;j<16u;j++)
            for(unsigned k=0;k<3u;k++)count[k]+=p->channels[j]==channels[k];
    }
    for(unsigned k=0;k<3u;k++)
        if(count[k]>most || (count[k] && count[k]==most && channels[k]==s->channel)) {
            most=count[k];want=channels[k];
        }
    return want;
}

static bool peer_window(const struct owly_link_peer *p,uint64_t now,uint16_t *seq,uint16_t *phase) {
    if(!p || !clock_fresh(p,now) || !fresh(p,now))return false;
    if(now<p->anchor_us) {
        const uint64_t lead=p->anchor_us-now;
        if(lead>OWLY_LINK_AW_US)return false;
        *seq=(uint16_t)(p->next_seq-1u);
        *phase=(uint16_t)(OWLY_LINK_AW_US-lead);
    } else {
        const uint64_t elapsed=now-p->anchor_us;
        *seq=(uint16_t)(p->next_seq+(uint16_t)(elapsed/OWLY_LINK_AW_US));
        *phase=(uint16_t)(elapsed%OWLY_LINK_AW_US);
    }return true;
}

static bool shared_slot_open(const struct owly_link_peer *p,uint8_t channel,
                             uint16_t seq,uint16_t phase,uint64_t now,
                             enum owly_link_tx_kind kind)
{
    const unsigned slot=(seq/4u)&15u;
    if(p->channels[slot]!=channel)return false;
    /* A real MIF or IPv6 packet in this AW gives us an opportunity to
     * transmit even after the initial wake interval. */
    const uint64_t heard=p->last_mif_rx_us>p->last_data_rx_us ?
        p->last_mif_rx_us : p->last_data_rx_us;
    const bool peer_here=heard && now>=heard && now-heard<=phase;
    /* Only proactive discovery needs the early wake interval. Replies
     * and connection traffic can use the rest of the confirmed slot. */
    const bool idle=kind==OWLY_LINK_TX_MDNS_QUERY && p->local_slots<=OWLY_LINK_IDLE_MAX_SLOTS &&
        !peer_here && (!p->last_data_rx_us ||
                      (now>=p->last_data_rx_us && now-p->last_data_rx_us>OWLY_LINK_PEER_AWAKE_US));
    if(idle && phase>=OWLY_LINK_IDLE_AW_US)return false;
    const unsigned until_slot=(unsigned)((OWLY_LINK_AW_US-phase+1023u)/1024u)+
        (3u-(seq&3u))*16u;
    if(until_slot<=3u && p->channels[(slot+1u)&15u]!=channel)return false;
    if(!(seq&3u) && p->channels[(slot+15u)&15u]!=channel) {
        /* Our SCC radio stays tuned. Give a returning idle peer 1 TU to
         * settle, leaving room for discovery even in the first AW. */
        if(idle || peer_here) {
            if(phase<OWLY_LINK_IDLE_RETURN_GUARD_US)return false;
        } else if(until_slot>=61u)return false;
    }
    return true;
}

static bool in_clock_domain(const struct owly_link_peer *p,
                            const struct owly_link_peer *root,uint64_t now)
{
    return fresh(p,now) && p->local_slots && !memcmp(p->master,root->mac,6);
}

static bool domain_slot_open(const struct owly_native_link *s,
                             const struct owly_link_peer *root,
                             uint16_t seq,uint16_t phase,uint64_t now,
                             enum owly_link_tx_kind kind,bool *scheduled)
{
    *scheduled=false;
    for(unsigned i=0;i<OWLY_LINK_PEERS;i++) {
        const struct owly_link_peer *p=&s->peers[i];
        if(!in_clock_domain(p,root,now))continue;
        *scheduled=true;
        if(shared_slot_open(p,s->channel,seq,phase,now,kind))return true;
    }
    return false;
}

bool owly_link_action_tx_ready(struct owly_native_link *s,uint64_t now)
{
    struct owly_link_peer *p=master_peer(s,now);
    uint16_t seq,phase;
    bool scheduled;
    /* Send initial discovery normally. A known peer schedule can delay
     * an advertisement until the peer is listening. */
    return !peer_window(p,now,&seq,&phase) ||
           domain_slot_open(s,p,seq,phase,now,OWLY_LINK_TX_MDNS_QUERY,&scheduled) ||
           !scheduled;
}

bool owly_link_root_election(struct owly_native_link *s,uint64_t now,uint8_t root[24])
{
    if(!root)return false;
    memset(root,0,24);
    if(!s || !s->active || !s->sync_enabled || s->tx_paused)return false;
    struct owly_link_peer *p=master_peer(s,now);
    if(!p || !p->has_election)return false;
    memcpy(root,p->election,24);return true;
}

uint16_t owly_link_shared_slots(struct owly_native_link *s, uint64_t now)
{
    uint16_t slots = 0;
    if (!s || !s->active || !s->sync_enabled || s->tx_paused)
        return 0;
    const struct owly_link_peer *peer = master_peer(s, now);
    if (!peer)
        return 0;
    for (unsigned i = 0; i < OWLY_LINK_PEERS; ++i) {
        const struct owly_link_peer *p=&s->peers[i];
        if(!in_clock_domain(p,peer,now))continue;
        for (unsigned j = 0; j < sizeof(p->channels); ++j)
            if (p->channels[j] == s->channel)
                slots |= (uint16_t)(1u << j);
    }
    return slots;
}

/* Multichannel schedule clock. Unlike owly_link_window it ignores the TX
 * pause: while the radio is with the access point the link is paused, yet
 * the schedule must still say when to come back. Uses the same root as the
 * advertised sync parameters, else the local clock (now / AW). */
bool owly_link_clock(struct owly_native_link *s,uint64_t now,uint16_t *seq,
                     uint32_t *phase_us,uint16_t *social_slots,unsigned *peers)
{
    uint16_t sequence,phase,slots=0;
    unsigned count=0;
    if(!s || !seq || !phase_us)return false;
    expire(s,now);
    for(unsigned i=0;i<OWLY_LINK_PEERS;i++)if(s->peers[i].used)++count;
    struct owly_link_peer *root=s->active && s->sync_enabled ? master_peer(s,now) : NULL;
    if(root && peer_window(root,now,&sequence,&phase)) {
        for(unsigned i=0;i<OWLY_LINK_PEERS;i++) {
            const struct owly_link_peer *p=&s->peers[i];
            if(!in_clock_domain(p,root,now))continue;
            for(unsigned j=0;j<16u;j++)
                if(p->channels[j]==s->channel)slots|=(uint16_t)(1u<<j);
        }
        *seq=sequence;*phase_us=phase;
    } else {
        /* No root to follow: the peers follow our clock (we are master)
         * or have not told us theirs yet. Use every fresh peer's own
         * sequence for where it will be on our channel. */
        for(unsigned i=0;i<OWLY_LINK_PEERS;i++) {
            const struct owly_link_peer *p=&s->peers[i];
            if(!fresh(p,now) || !p->local_slots)continue;
            for(unsigned j=0;j<16u;j++)
                if(p->channels[j]==s->channel)slots|=(uint16_t)(1u<<j);
        }
        *seq=(uint16_t)(now/OWLY_LINK_AW_US);
        *phase_us=(uint32_t)(now%OWLY_LINK_AW_US);
    }
    if(social_slots)*social_slots=slots;
    if(peers)*peers=count;
    return root!=NULL;
}

bool owly_link_window(struct owly_native_link *s,uint64_t now,struct owly_link_window *out) {
    struct owly_link_peer *p;
    unsigned i;
    if(!s || !out)return false;
    memset(out,0,sizeof(*out));expire(s,now);
    out->actions=s->actions;out->data_rx_admitted=s->data_rx_admitted;
    out->tx_enqueued=s->tx_enqueued;out->tx_handoffs=s->tx_handoffs;
    out->tx_refused=s->tx_refused;out->tx_expired=s->tx_expired;out->tx_radio_acked=s->tx_radio_acked;
    out->queued=s->count;
    for(i=0;i<OWLY_LINK_PEERS;i++)if(s->peers[i].used)++out->peers;
    if(!s->active || s->tx_paused)return false;
    /* The native frontend needs the bound radio identity to request its
     * first sync template. Only active=true grants an actual AW. */
    out->channel=s->channel;out->generation=s->generation;out->sampled_us=now;
    memcpy(out->local,s->local,6);
    if(!s->sync_enabled)return false;
    p=master_peer(s,now);
    if(!p && waiting_for_master(s,now))return false;
    out->active=true;
    uint16_t phase;
    if(p && peer_window(p,now,&out->sequence,&phase)) {
        out->until_next_tu=(uint16_t)((OWLY_LINK_AW_US-phase+1023u)/1024u);
        out->remote=true;out->master_channel=p->master_channel;memcpy(out->master,p->master,6);
        out->has_master_election=p->has_election;
        if(p->has_election)memcpy(out->master_election,p->election,20);
    } else {
        memcpy(out->master,s->local,6);out->master_channel=s->channel;out->sequence=(uint16_t)(now/OWLY_LINK_AW_US);
        out->until_next_tu=(uint16_t)((OWLY_LINK_AW_US-now%OWLY_LINK_AW_US+1023u)/1024u);
    }return true;
}
enum owly_link_ipv6_result owly_link_admit_ipv6(
    struct owly_native_link *s,const uint8_t src[6],const uint8_t dst[6],
    const uint8_t *ip,size_t n,uint64_t now)
{
    enum owly_link_ipv6_result result=OWLY_LINK_IPV6_ACCEPTED;
    if(!s || !src || !dst)return OWLY_LINK_IPV6_INVALID;
    const uint64_t current=rx_housekeeping_time(s,now);
    expire(s,current);
    struct owly_link_peer *p=find(s,src);
    if(!s->active || !now || current-now>OWLY_LINK_PEER_TTL_US)
        result=OWLY_LINK_IPV6_INACTIVE;
    else if(!(dst[0]&1u) && (!s->sync_enabled || s->tx_paused))
        result=OWLY_LINK_IPV6_INACTIVE;
    else if(!p || !fresh(p,current))
        result=OWLY_LINK_IPV6_NO_PEER;
    else if(!ip_ok(ip,n))
        result=OWLY_LINK_IPV6_INVALID;
    else if(memcmp(dst,s->local,6) &&
            !(dst[0]==0x33 && dst[1]==0x33 && ip[24]==0xff && !memcmp(dst+2,ip+36,4)))
        result=OWLY_LINK_IPV6_BAD_DEST;
    if(result==OWLY_LINK_IPV6_ACCEPTED) {
        if(!(dst[0]&1u))s->last_unicast_activity_us=current;
        if(now>p->last_data_rx_us)p->last_data_rx_us=now;
        ++s->data_rx_admitted;
    }
    else ++s->data_rx_rejected;
    return result;
}
int owly_link_build_tx(const uint8_t *eth,size_t n,const uint8_t local[6],uint16_t wifi,uint16_t awdl,uint8_t *out,size_t cap,size_t *length) {
    const uint8_t *ip,*payload;size_t iplen,payload_len,need;bool wrapped;uint16_t type;
    if(!length || overlap(length,sizeof(*length),eth,n) || overlap(length,sizeof(*length),out,cap))return -EINVAL;
    *length=0;
    if(!eth || n<55 || !out || !mac_ok(local) || memcmp(eth+6,local,6) ||
       overlap(out,cap,eth,n) || overlap(out,cap,local,6))return -EINVAL;
    type=be16(eth+12);wrapped=type<=1500u;
    if(wrapped) {
        if(type!=n-14 || n<71 || memcmp(eth+14,snap,8) || eth[22]!=3 || (eth[23]!=0 && eth[23]!=4) || eth[26] || eth[27] || eth[28]!=0x86 || eth[29]!=0xdd)return -EINVAL;
        ip=eth+30;iplen=n-30;payload=eth+14;payload_len=n-14;
    } else {
        if(type!=0x86dd)return -EOPNOTSUPP;
        ip=eth+14;iplen=n-14;payload=NULL;payload_len=16+iplen;
    }
    if(!ip_ok(ip,iplen))return -EINVAL;
    need=24+payload_len;if(need>cap || need>OWLY_LINK_FRAME_MAX)return -EMSGSIZE;
    memset(out,0,24);out[0]=8;memcpy(out+4,eth,6);memcpy(out+10,local,6);memcpy(out+16,bssid,6);put16(out+22,(uint16_t)((wifi&4095u)<<4));
    if(ip[24]==0xff) {out[4]=out[5]=0x33;memcpy(out+6,ip+36,4);}
    else if(!mac_ok(eth))return -EINVAL;
    if(wrapped) {
        memcpy(out+24,payload,payload_len);
        /* The native wrapper can be 03 00. Peers use the wire head 0x0403. */
        out[33]=4;
        /* Apple's native wrapper contains driver/offload metadata, not our
         * software transmitter's per-node sequence. Allocate the same real
         * sequence for wrapped and unwrapped packets; preserving the native
         * placeholder can give every SYN/mDNS packet the same AWDL sequence. */
        put16(out+34,awdl);
    }
    else {memcpy(out+24,snap,8);out[32]=3;out[33]=4;put16(out+34,awdl);out[36]=out[37]=0;out[38]=0x86;out[39]=0xdd;memcpy(out+40,ip,iplen);}
    *length=need;return 0;
}
static enum owly_link_tx_kind tx_kind(const uint8_t destination[6],const uint8_t *ip,size_t n)
{
    static const uint8_t group[16]={0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0xfb};
    /* The caller has already validated the IPv6 header and payload size. */
    if(!(destination[0]&1u))return OWLY_LINK_TX_UNICAST;
    if(n<60u || ip[6]!=17u || memcmp(ip+24,group,sizeof(group)) ||
       be16(ip+42)!=5353u || be16(ip+44)!=n-40u)
        return OWLY_LINK_TX_OTHER;
    if(ip[50]&0x80u)return OWLY_LINK_TX_MDNS_REPLY;
    return be16(ip+52) ? OWLY_LINK_TX_MDNS_QUERY : OWLY_LINK_TX_OTHER;
}

int owly_link_enqueue(struct owly_native_link *s,const uint8_t *eth,size_t n,uint64_t now) {
    struct owly_link_frame *f;size_t size;unsigned at;int rc;
    if(!s || !s->active || (!s->sync_enabled && !s->starting))return -ENETDOWN;
    expire(s,now);
    if(s->count==OWLY_LINK_QUEUE) {++s->tx_refused;return -ENOBUFS;}
    /* Reuse payload storage freed by replies that passed a held query. */
    at=(unsigned)__builtin_ctz(~s->queue_used);f=&s->queue[at];
    rc=owly_link_build_tx(eth,n,s->local,0,0,f->bytes,sizeof(f->bytes),&size);
    if(rc) {++s->tx_refused;return rc;}
    memcpy(f->destination,f->bytes+4,6);
    f->kind=tx_kind(f->destination,f->bytes+40,size-40);
    /* BSD can emit the first Bonjour query or announcement as soon as the
     * VIF comes up, before Apple finishes SET151/117. Keep it on the bound
     * radio's queue until the normal sync gate opens. */
    if(!s->sync_enabled && f->kind!=OWLY_LINK_TX_MDNS_QUERY &&
       f->kind!=OWLY_LINK_TX_MDNS_REPLY)
        return -ENETDOWN;
    f->awaiting_first_mif=!s->sync_enabled;
    if(!(f->destination[0]&1u) && !find(s,f->destination)) {++s->tx_refused;return -EHOSTUNREACH;}
    f->length=(uint16_t)size;f->queued_us=now;f->pause_credit_us=0;f->generation=s->generation;
    s->queue_used|=1u<<at;
    s->queue_order[(s->head+s->count)%OWLY_LINK_QUEUE]=(uint8_t)at;
    ++s->count;++s->tx_enqueued;
    if(f->kind==OWLY_LINK_TX_UNICAST)s->last_unicast_activity_us=now;
    return 0;
}
bool owly_link_data_busy(const struct owly_native_link *s,uint64_t now)
{
    if(!s || !s->active || !s->sync_enabled)return false;
    if(s->last_unicast_activity_us && now>=s->last_unicast_activity_us &&
       now-s->last_unicast_activity_us<=OWLY_NATIVE_DATA_HOLD_US)return true;
    for(unsigned i=0;i<s->count;i++) {
        const struct owly_link_frame *f=&s->queue[s->queue_order[(s->head+i)%OWLY_LINK_QUEUE]];
        if(f->kind==OWLY_LINK_TX_UNICAST && now>=f->queued_us &&
           now-f->queued_us<=OWLY_LINK_TX_TTL_US+OWLY_LINK_SCAN_CREDIT_US)return true;
    }
    return false;
}
static bool can_send(struct owly_native_link *s,const uint8_t destination[6],uint64_t now,
                     enum owly_link_tx_kind kind) {
    const bool multicast=(destination[0]&1u)!=0;
    struct owly_link_peer *clock=multicast ? master_peer(s,now) : NULL;
    struct owly_link_peer *p=multicast ? clock : find(s,destination);
    uint16_t seq,phase;
    if(multicast && peer_window(clock,now,&seq,&phase)) {
        bool scheduled;
        const bool open=domain_slot_open(s,clock,seq,phase,now,kind,&scheduled);
        if(scheduled)return open;
    }
    if(multicast && !p) {
        for(unsigned i=0;i<OWLY_LINK_PEERS;i++) {
            struct owly_link_peer *candidate=&s->peers[i];
            if(fresh(candidate,now) && (!p || candidate->last_rx_us>p->last_rx_us))
                p=candidate;
        }
    }
    if(!p)return multicast;
    if(!fresh(p,now))return false;
    bool have_window=peer_window(p,now,&seq,&phase);
    if(!have_window) {
        if(!multicast)clock=master_peer(s,now);
        have_window=clock && !memcmp(clock->master,p->master,6) && peer_window(clock,now,&seq,&phase);
        if(!clock && !waiting_for_master(s,now) && !memcmp(p->master,s->local,6)) {
            /* This peer follows the clock we already advertise in PSF/MIF.
             * Its observed slot map still decides whether it is listening. */
            seq=(uint16_t)(now/OWLY_LINK_AW_US);
            phase=(uint16_t)(now%OWLY_LINK_AW_US);
            have_window=true;
        }
    }
    /* A fixed-channel VIF can use the first shared AW for Bonjour. It
     * already advertises that channel and need not wait for slot 0 or 10. */
    if(have_window && p->local_slots)
        return shared_slot_open(p,s->channel,seq,phase,now,kind);
    /* When timing is unknown, use a brief opportunity after hearing the
     * destination on this SCC radio. IPv6 admission already checked it. */
    const uint64_t heard=p->last_data_rx_us>p->last_rx_us ?
        p->last_data_rx_us : p->last_rx_us;
    return p->channel==s->channel && now>=heard && now-heard<=OWLY_LINK_RECENT_ACTION_US;
}

bool owly_link_unicast_action_tx_ready(struct owly_native_link *s,
                                      const uint8_t destination[6], uint64_t now)
{
    return s && s->active && s->sync_enabled && !s->tx_paused &&
           mac_ok(destination) && can_send(s,destination,now,OWLY_LINK_TX_MDNS_QUERY);
}

bool owly_link_unicast_reply_tx_ready(struct owly_native_link *s,
                                     const uint8_t destination[6], uint64_t now)
{
    return s && s->active && s->sync_enabled && !s->tx_paused &&
           mac_ok(destination) && can_send(s,destination,now,OWLY_LINK_TX_UNICAST);
}

static void remove_queued(struct owly_native_link *s,unsigned offset)
{
    const unsigned at=(s->head+offset)%OWLY_LINK_QUEUE;
    s->queue_used&=~(1u<<s->queue_order[at]);
    --s->count;
    if(!offset) {
        s->head=(s->head+1u)%OWLY_LINK_QUEUE;
        return;
    }
    for(unsigned i=offset;i<s->count;++i)
        s->queue_order[(s->head+i)%OWLY_LINK_QUEUE]=s->queue_order[(s->head+i+1u)%OWLY_LINK_QUEUE];
}

int owly_link_next_tx(struct owly_native_link *s,uint64_t now,bool first_mif_submitted,
                      uint8_t *out,
                      size_t cap,size_t *n,unsigned *offset,uint64_t *generation) {
    struct owly_link_frame *f;
    if(!s || !out || !n || !offset || !generation || cap<OWLY_LINK_FRAME_MAX)return -EINVAL;
    *n=0;expire(s,now);
    if(!s->active || !s->sync_enabled || s->tx_paused)return 0;
    for(unsigned i=0;i<s->count;) {
        f=&s->queue[s->queue_order[(s->head+i)%OWLY_LINK_QUEUE]];
        if(now<f->queued_us || now-f->queued_us>OWLY_LINK_TX_TTL_US+f->pause_credit_us ||
           f->generation!=s->generation) {
            remove_queued(s,i);++s->tx_expired;continue;
        }
        if((f->awaiting_first_mif && !first_mif_submitted) ||
           !can_send(s,f->destination,now,f->kind)) {
            /* A held startup announcement or peer must not block a ready
             * unicast reply to a different peer. */
            ++i;
            continue;
        }
        memcpy(out,f->bytes,f->length);*n=f->length;
        /* Assign sequence numbers in handoff order, including when a
         * ready reply passed a multicast query. */
        put16(out+22,(uint16_t)((s->wifi_sequence&4095u)<<4));
        put16(out+34,s->awdl_sequence);
        *offset=i;
        *generation=s->generation;
        return 1;
    }return 0;
}
void owly_link_tx_result(struct owly_native_link *s,unsigned offset,uint64_t generation,int rc)
{
    if(!s || generation!=s->generation || offset>=s->count ||
       rc==-ENOMEM || rc==-ENOSPC || rc==-EBUSY)
        return;
    remove_queued(s,offset);
    if(rc) {
        ++s->tx_refused;
    } else {
        ++s->wifi_sequence;
        ++s->awdl_sequence;
        ++s->tx_handoffs;
    }
}
void owly_link_prefer(struct owly_native_link *s,const uint8_t master[6]) {
    if(s && mac_ok(master)) {
        uint8_t desired[6]={0};
        /* Native configure names us during local warmup. Non-election-master
         * mode is not supported, so that is not a permanent self-election.
         * A foreign native choice is still honored and must earn a clock. */
        if(memcmp(master,s->local,6))memcpy(desired,master,6);
        if(memcmp(s->preferred,desired,6)) {
            memcpy(s->preferred,desired,6);
            s->preferred_us=s->last_now_us;
        }
    }
}
