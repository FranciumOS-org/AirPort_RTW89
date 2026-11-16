/* SPDX-License-Identifier: GPL-2.0 */
#include "owly_native_config.h"
#include <string.h>
#if defined(RTW89_MACOS)
#include <sys/errno.h>
#else
#include <errno.h>
#endif
static const uint8_t bssid[6]={0,0x25,0,0xff,0x94,0x73};
static bool social(uint8_t ch) { return ch==6 || ch==44 || ch==149; }
static bool valid_mac(const uint8_t *p)
{ return p && !(p[0]&1u) && (p[0]|p[1]|p[2]|p[3]|p[4]|p[5]); }

int owly_config_request(struct owly_native_config *c,bool set,unsigned number,
                       void *data,const uint8_t local[6],uint8_t bound)
{
    uint32_t version;struct owly_native_config next;
    bool stopping;
    if (!c || !data || !owly_cfg_known(number)) return -EINVAL;
    stopping=set && number==134 && ((struct owly_cfg_sync *)data)->state==0;
    if (!stopping && !valid_mac(local)) return -EINVAL;
    if (!stopping && !social(bound)) return -ENETDOWN;
    if (set) { memcpy(&version,data,4);if (version>1) return -EINVAL; }
    next=*c;
    switch (number) {
    case 125: {
        struct owly_cfg_bssid *d=data;
        if (set) {
            if (memcmp(d->bssid,bssid,6)) return -EOPNOTSUPP;
            memcpy(next.bssid_opaque,d->opaque_mac,6);
            next.committed|=OWLY_CFG_BSSID;
        } else { memset(d,0,sizeof(*d));d->version=1;memcpy(d->bssid,bssid,6);memcpy(d->opaque_mac,c->bssid_opaque,6); }
        break;
    }
    case 122: {
        struct owly_cfg_u32 *d=data;
        if (set) { next.election_id=d->value;next.committed|=OWLY_CFG_ELECTION; }
        else { d->version=1;d->value=c->election_id; }
        break;
    }
    case 132: {
        struct owly_cfg_u32 *d=data;
        if (set) {
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
            /* Cluster-master metadata is distinct from our actual SCC RF
             * channel. A master heard on 149 can itself name channel44. */
            if(!social((uint8_t)d->value) || d->value>255)return -EOPNOTSUPP;
            next.master_channel=(uint8_t)d->value;next.committed|=OWLY_CFG_MASTER;
#else
            if (d->value!=bound) return -EOPNOTSUPP;
            next.master_channel=bound;next.committed|=OWLY_CFG_MASTER;
#endif
        } else {
            d->version=1;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
            d->value=(c->committed&OWLY_CFG_MASTER) ? c->master_channel : bound;
#else
            d->value=bound;
#endif
        }
        break;
    }
    case 135: {
        struct owly_cfg_rssi *d=data;
        if (set) {
            if (d->threshold < -128 || d->threshold>0) return -EINVAL;
            if (d->reserved[0] || d->reserved[1] || d->reserved[2]) return -EOPNOTSUPP;
            next.peer_rssi=d->threshold;next.committed|=OWLY_CFG_RSSI;
        } else {
            memset(d,0,sizeof(*d));d->version=1;
            d->threshold=(c->committed&OWLY_CFG_RSSI) ? c->peer_rssi : -128;
        }
        break;
    }
    case 134: {
        struct owly_cfg_sync *d=data;
        if (set) {
            if (d->state>1) return -EOPNOTSUPP;
            /* Legacy configure emits flags bit0 for local warmup. No
             * foreign-master acquisition or undocumented mode is promised. */
            if (d->state && (
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
                !valid_mac(d->master) ||
#else
                memcmp(d->master,local,6) ||
#endif
                (d->flags&~1u) || d->mode_flags)) return -EOPNOTSUPP;
            if (d->reserved[0] || d->reserved[1] || d->reserved2[0] || d->reserved2[1] || d->reserved2[2]) return -EINVAL;
            next.sync=*d;next.sync.version=1;next.committed|=OWLY_CFG_SYNC;
        } else { *d=c->sync;d->version=1; }
        break;
    }
    case 116: {
        struct owly_cfg_params *d=data;
        if (set) {
            if (d->aw_length!=16 || d->aw_period!=16 || d->extension!=16 ||
                d->non_election_master || (d->psf_period!=110 && d->psf_period!=440)) return -EOPNOTSUPP;
            next.psf_period_ms=d->psf_period;next.committed|=OWLY_CFG_PARAMS;
        } else {
            memset(d,0,sizeof(*d));d->version=1;d->aw_length=d->aw_period=d->extension=16;
            d->psf_period=c->psf_period_ms ? c->psf_period_ms : 110;
        }
        break;
    }
    case 129: {
        struct owly_cfg_sequence *d=data;unsigned i;
        if (set) {
            if (d->length!=16 || d->encoding>1 || d->step!=3 || d->duplicate || d->fill!=255) return -EOPNOTSUPP;
            if (d->pad || d->reserved[0] || d->reserved[1] ||
                d->tail[0] || d->tail[1] || d->tail[2] || d->tail[3]) return -EOPNOTSUPP;
            for (i=0;i<16;i++)
                if (d->channels[i].version>1 || d->channels[i].channel!=bound ||
                    (d->channels[i].flags&~(bound>14 ? 0x12u : 0xau))) return -EOPNOTSUPP;
            for (i=16;i<32;i++)
                if (d->channels[i].version || d->channels[i].channel || d->channels[i].flags) return -EOPNOTSUPP;
#if !defined(OWLY_NATIVE_PEER_DATA) || !OWLY_NATIVE_PEER_DATA
            next.master_channel=bound;
#endif
            next.committed|=OWLY_CFG_SEQUENCE;
        } else owly_config_sequence(d,bound);
        break;
    }
    case 213: {
        struct owly_cfg_rate *d=data;
        if (set && d->half_mbps!=12) return -EOPNOTSUPP;
        if (!set) { d->version=1;d->half_mbps=12; }
        break;
    }
    default:return -EOPNOTSUPP;
    }
    if (set) *c=next;
    return 0;
}

bool owly_config_rx_allowed(int threshold,int signal)
{
    return signal>=threshold;
}
