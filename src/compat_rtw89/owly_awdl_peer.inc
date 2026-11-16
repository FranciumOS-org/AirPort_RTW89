/* SPDX-License-Identifier: GPL-2.0 */ /* Modified 2026-11-15: BlockAck reply/dynamic-CAM fixes; see MODIFICATIONS.md. */
/* Real observed AWDL radio peers. Wiphy owns CAM/firmware; RX only queues
 * control requests or packet ownership. No AP join, TDLS, synthetic TCP/TLS. */
#include "owly_awdl_ba.h"
#define OWLY_RADIO_PEERS 4u
#define OWLY_CONTROL_QUEUE 8u
struct owly_awdl_radio_peer {
 struct ieee80211_sta *sta;enum ieee80211_sta_state state;bool blocked;
 uint8_t mac[6],own[6];uint16_t ba_map;
 struct owly_ba_request requests[16];struct owly_ba_ring reorder[16];
};
struct owly_awdl_control {uint8_t bytes[64];size_t length;uint64_t received,generation;};
static struct owly_awdl_radio_peer owly_radio_peers[4];
static struct owly_awdl_control owly_controls[8];
static unsigned owly_control_head,owly_control_count;
static spinlock_t owly_peer_lock;
static uint64_t owly_peer_generation,owly_peer_check_us;
static uint16_t owly_control_sequence;
static bool owly_peer_fault,owly_peer_accepting;
static struct work_struct owly_peer_delivery_work;
static struct {struct sk_buff *skb;uint64_t generation;} owly_peer_ready[128];
static unsigned owly_peer_ready_head,owly_peer_ready_count;
static void owly_peer_delivery_run(struct work_struct *work);
static void owly_awdl_deliver_rx(struct sk_buff *skb);
static struct ieee80211_channel *owly_sync_bound_channel(void);
static int owly_sync_submit(struct ieee80211_channel *ch,const uint8_t *p,size_t n,bool data);
static void owly_peer_init(void)
{
 spin_lock_init(&owly_peer_lock);memset(owly_radio_peers,0,sizeof(owly_radio_peers));
 owly_control_head=owly_control_count=0;owly_peer_generation=owly_peer_check_us=0;
 owly_peer_fault=owly_peer_accepting=false;owly_control_sequence=0;
 owly_peer_ready_head=owly_peer_ready_count=0;INIT_WORK(&owly_peer_delivery_work,owly_peer_delivery_run);
}
struct owly_peer_packet_queues {struct list_head good,drop;};
static void owly_peer_good(void *ctx,void *packet)
{list_add_tail(&((struct sk_buff *)packet)->list,&((struct owly_peer_packet_queues *)ctx)->good);}
static void owly_peer_bad(void *ctx,void *packet)
{list_add_tail(&((struct sk_buff *)packet)->list,&((struct owly_peer_packet_queues *)ctx)->drop);}
static void owly_peer_queues_init(struct owly_peer_packet_queues *q)
{INIT_LIST_HEAD(&q->good);INIT_LIST_HEAD(&q->drop);}
static void owly_peer_queues_finish(struct owly_peer_packet_queues *q)
{
 struct sk_buff *skb;
 while(!list_empty(&q->drop)){skb=list_first_entry(&q->drop,struct sk_buff,list);list_del(&skb->list);kfree_skb(skb);}
 while(!list_empty(&q->good)){
  skb=list_first_entry(&q->good,struct sk_buff,list);list_del(&skb->list);bool queued=false;
  spin_lock(&owly_peer_lock);
  if(glue.up && glue.awdl_rx_wq && owly_peer_accepting && owly_peer_ready_count<128){
   const unsigned at=(owly_peer_ready_head+owly_peer_ready_count)%128;
   owly_peer_ready[at].skb=skb;owly_peer_ready[at].generation=owly_peer_generation;++owly_peer_ready_count;queued=true;
  }
  spin_unlock(&owly_peer_lock);
  if(queued)queue_work(glue.awdl_rx_wq,&owly_peer_delivery_work);else kfree_skb(skb);
 }
}
static void owly_peer_delivery_run(struct work_struct *work)
{
 (void)work;
 /* Ordinary RX work: Apple's input may call back into cmd/wiphy. */
 for(;;){
  struct sk_buff *skb=NULL;bool deliver=false;spin_lock(&owly_peer_lock);
  if(owly_peer_ready_count){
   const unsigned at=owly_peer_ready_head;skb=owly_peer_ready[at].skb;
   deliver=glue.up && owly_peer_accepting && owly_peer_ready[at].generation==owly_peer_generation;
   owly_peer_ready_head=(at+1u)%128;--owly_peer_ready_count;
  }
  spin_unlock(&owly_peer_lock);
  if(!skb)break;
  if(deliver)owly_awdl_deliver_rx(skb);else kfree_skb(skb);
 }
}
static void owly_peer_clear_delivery(void)
{
 struct owly_peer_packet_queues q;owly_peer_queues_init(&q);spin_lock(&owly_peer_lock);owly_peer_accepting=false;
 while(owly_peer_ready_count){owly_peer_bad(&q,owly_peer_ready[owly_peer_ready_head].skb);owly_peer_ready_head=(owly_peer_ready_head+1u)%128;--owly_peer_ready_count;}
 spin_unlock(&owly_peer_lock);owly_peer_queues_finish(&q);
}
static void owly_peer_drain_rx(void)
{ /* Only after up=false, outside command/wiphy locks. */
 owly_peer_clear_delivery();cancel_work_sync(&owly_peer_delivery_work);
}
static void owly_peer_fini(void){spin_lock_destroy(&owly_peer_lock);}
static struct owly_awdl_radio_peer *owly_peer_find(const uint8_t mac[6])
{
 for(unsigned i=0;i<4;i++)if(owly_radio_peers[i].sta && !memcmp(owly_radio_peers[i].mac,mac,6))return &owly_radio_peers[i];
 return NULL;
}
static struct ieee80211_sta *owly_peer_tx_station(const uint8_t destination[6])
{
 struct owly_awdl_radio_peer *p=owly_peer_find(destination);
 return p && !p->blocked && p->state>=IEEE80211_STA_ASSOC ? p->sta:NULL;
}
static int owly_peer_ba_firmware(struct owly_awdl_radio_peer *p,unsigned tid,bool start,uint16_t ssn,uint16_t window)
{
 struct rtw89_sta *rs=sta_to_rtwsta(p->sta);struct rtw89_sta_link *sl=rs->links[p->sta->deflink.link_id];
 struct rtw89_dev *dev=glue_hw()->priv;
 struct ieee80211_ampdu_params a={.sta=p->sta,.tid=(u16)tid,.ssn=ssn,.buf_size=window,.amsdu=false};
 struct rtw89_ba_cam_entry *entry;bool found=false;int rc;lockdep_assert_wiphy(glue_hw()->wiphy);
 if(!sl || tid>=16 || dev->chip->chip_id!=RTL8852B)return -EOPNOTSUPP;
 /* Preserve H2C errors. Upstream intentionally returns success when static
  * BA CAM is full: RTL8852B can create dynamic entries automatically.
  * A missing static entry is only an error without that hardware fallback. */
 rc=rtw89_fw_h2c_ba_cam(dev,sl->rtwvif_link,sl,start,&a);
 if(!rc && start){list_for_each_entry(entry,&sl->ba_cam_list,list)if(entry->tid==tid){found=true;break;}if(!found && !dev->chip->bacam_dynamic_num)rc=-ENOSPC;}
 if(rc && start){const int undo=rtw89_fw_h2c_ba_cam(dev,sl->rtwvif_link,sl,false,&a);if(undo)p->blocked=true;}
 if(rc && !start)p->blocked=true;
 if(!rc)rtw89_core_tid_rx_stats_ctrl(dev,rs,&a,start);
 return rc;
}
static void owly_peer_drop(struct owly_awdl_radio_peer *p)
{
 struct ieee80211_hw *hw=glue_hw();struct rtw89_m80211_local *local=hw_to_local(hw);
 struct owly_peer_packet_queues q;owly_peer_queues_init(&q);if(!p->sta)return;
 rtw89_m80211_sta_set_uploaded(p->sta,false);spin_lock(&owly_peer_lock);
 const uint16_t active=p->ba_map;p->ba_map=0;
 for(unsigned t=0;t<16;t++)owly_ba_clear(&p->reorder[t],owly_peer_bad,&q);
 spin_unlock(&owly_peer_lock);owly_peer_queues_finish(&q);
 for(unsigned t=0;t<16;t++)if(active&(1u<<t))if(owly_peer_ba_firmware(p,t,false,0,0))owly_peer_fault=true;
 rtw89_m80211_sta_purge_txqs(p->sta);
 if(local->ops->flush)local->ops->flush(hw,owly_core04c_vif,BIT(hw->queues)-1,false);
 while(p->state>IEEE80211_STA_NOTEXIST){
  enum ieee80211_sta_state next=(enum ieee80211_sta_state)(p->state-1);
  const int rc=local->ops->sta_state(hw,owly_core04c_vif,p->sta,p->state,next);
  if(rc){owly_peer_fault=true;IOLog("OWLY radio peer remove: state=%u rc=%d\n",(unsigned)p->state,rc);}p->state=next;
 }
 spin_lock(&owly_peer_lock);struct ieee80211_sta *sta=p->sta;memset(p,0,sizeof(*p));spin_unlock(&owly_peer_lock);
 rtw89_m80211_sta_free(sta);
}
static int owly_peer_open(struct owly_awdl_radio_peer *p,const uint8_t mac[6])
{
 struct ieee80211_hw *hw=glue_hw();struct rtw89_m80211_local *local=hw_to_local(hw);
 struct ieee80211_sta *sta=rtw89_m80211_sta_alloc(owly_core04c_vif,mac);if(!sta)return -ENOMEM;
 /* Radio context readiness only. Never ieee80211_sta.tdls or an AP join. */
 sta_to_rtwsta(sta)->owly_awdl=true;sta->wme=true;sta->deflink.bandwidth=IEEE80211_STA_RX_BW_20;
 sta->deflink.rx_nss=1;sta->max_rx_aggregation_subframes=64;struct ieee80211_channel *ch=owly_sync_bound_channel();
 if(ch){struct ieee80211_supported_band *band=hw->wiphy->bands[ch->band];
  for(unsigned i=0;band && i<band->n_bitrates && i<32;i++)if(band->bitrates[i].bitrate>=60)sta->deflink.supp_rates[ch->band]|=BIT(i);}
 spin_lock(&owly_peer_lock);memcpy(p->mac,mac,6);memcpy(p->own,owly_core04c_vif->addr,6);
 p->state=IEEE80211_STA_NOTEXIST;p->sta=sta;spin_unlock(&owly_peer_lock);
 while(p->state<IEEE80211_STA_ASSOC){
  enum ieee80211_sta_state next=(enum ieee80211_sta_state)(p->state+1);
  const int rc=local->ops->sta_state(hw,owly_core04c_vif,sta,p->state,next);
  if(rc){
   owly_peer_fault=true;
   if(p->state==IEEE80211_STA_AUTH){const int undo=local->ops->sta_state(hw,owly_core04c_vif,sta,IEEE80211_STA_AUTH,IEEE80211_STA_NONE);if(undo)IOLog("OWLY radio peer rollback refused: rc=%d\n",undo);p->state=IEEE80211_STA_NONE;}
   owly_peer_drop(p);return rc;
  }p->state=next;
 }
 rtw89_m80211_sta_set_uploaded(sta,true);struct rtw89_sta_link *sl=sta_to_rtwsta(sta)->links[sta->deflink.link_id];
 IOLog("OWLY radio peer ready: peer=%02x:%02x:%02x:%02x:%02x:%02x macid=%u cam=%u (not IP/TLS proof)\n",
  mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],(unsigned)sl->mac_id,(unsigned)sl->addr_cam.addr_cam_idx);return 0;
}
static void owly_peer_close_all(void)
{
 lockdep_assert_wiphy(glue_hw()->wiphy);owly_peer_clear_delivery();
 spin_lock(&owly_peer_lock);owly_control_head=owly_control_count=0;spin_unlock(&owly_peer_lock);
 for(unsigned i=0;i<4;i++)owly_peer_drop(&owly_radio_peers[i]);
 owly_peer_check_us=0;spin_lock(&owly_peer_lock);owly_peer_generation=0;spin_unlock(&owly_peer_lock);
}
static bool owly_peer_known_locked(const uint8_t mac[6],uint64_t now)
{
 if(!owly_link_state.active)return false;
 for(unsigned i=0;i<OWLY_LINK_PEERS;i++)if(!memcmp(owly_link_state.peers[i].mac,mac,6) && owly_link_peer_alive(&owly_link_state.peers[i],now))return true;
 return false;
}
static bool owly_peer_reply_due(const struct owly_awdl_control *c)
{
 const uint64_t now=glue_now_us();spin_lock(&owly_link_lock);
 const bool ready=c->generation==owly_link_state.generation && now>=c->received && now-c->received<=OWLY_LINK_PEER_TTL_US &&
  owly_peer_known_locked(c->bytes+10,now) && owly_link_unicast_reply_tx_ready(&owly_link_state,c->bytes+10,now);
 spin_unlock(&owly_link_lock);return ready;
}
static bool owly_peer_control_rx(struct sk_buff *skb)
{
 uint8_t own[6];uint64_t generation;bool valid;struct owly_ba_request request;
 const size_t n=skb->len-FCS_LEN;const uint8_t *raw=skb->data;
 if(n<26 || raw[0]!=0xd0 || raw[24]!=3)return false;
 const uint64_t now=glue_now_us();spin_lock(&owly_link_lock);memcpy(own,owly_link_state.local,6);generation=owly_link_state.generation;
 valid=owly_peer_known_locked(raw+10,now);spin_unlock(&owly_link_lock);
 if(!valid || !owly_ba_parse(raw,n,own,&request))return false;
 spin_lock(&owly_peer_lock);
 if(owly_control_count<8){struct owly_awdl_control *c=&owly_controls[(owly_control_head+owly_control_count)%8];
  c->length=n<64?n:64;memcpy(c->bytes,raw,c->length);c->received=now;c->generation=generation;++owly_control_count;}
 spin_unlock(&owly_peer_lock);wiphy_delayed_work_queue(glue_hw()->wiphy,&owly_sync_work,0);kfree_skb(skb);return true;
}
static bool owly_peer_data_rx(struct sk_buff *skb)
{
 const uint8_t *raw=skb->data;const size_t n=skb->len-FCS_LEN;
 if(n<26 || raw[0]!=0x88 || (raw[1]&0x47) || (raw[4]&1u) || (owly_ba_le16(raw+22)&15u))return false;
 static const uint8_t b[6]={0,0x25,0,0xff,0x94,0x73};if(memcmp(raw+16,b,6))return false;
 struct owly_peer_packet_queues q;owly_peer_queues_init(&q);bool consumed=false;spin_lock(&owly_peer_lock);
 struct owly_awdl_radio_peer *p=owly_peer_find(raw+10);const unsigned tid=raw[24]&15u;
 if(p && !memcmp(raw+4,p->own,6) && (p->ba_map&(1u<<tid))){
  owly_ba_push(&p->reorder[tid],owly_ba_le16(raw+22)>>4,skb,glue_now_us(),owly_peer_good,owly_peer_bad,&q);consumed=true;}
 spin_unlock(&owly_peer_lock);owly_peer_queues_finish(&q);return consumed;
}
static bool owly_peer_bar_rx(struct sk_buff *skb)
{
 const uint8_t *raw=skb->data;const size_t n=skb->len-FCS_LEN;if(n<20 || raw[0]!=0x84 || (raw[1]&0x47))return false;
 struct owly_peer_packet_queues q;owly_peer_queues_init(&q);bool consumed=false;spin_lock(&owly_peer_lock);
 struct owly_awdl_radio_peer *p=owly_peer_find(raw+10);const uint16_t control=owly_ba_le16(raw+16);const unsigned tid=control>>12;
 if(p && (p->ba_map&(1u<<tid)) && !(control&2u) && !memcmp(raw+4,p->own,6)){
  owly_ba_bar(&p->reorder[tid],owly_ba_le16(raw+18)>>4,owly_peer_good,&q);consumed=true;}
 spin_unlock(&owly_peer_lock);owly_peer_queues_finish(&q);if(consumed)kfree_skb(skb);
 return consumed;
}
static void owly_peer_tick(struct ieee80211_channel *ch,uint64_t now)
{
 lockdep_assert_wiphy(glue_hw()->wiphy);if(!ch || glue.scanning || !owly_core04c_vif || !glue.awdl_rx_wq)return;
 uint8_t addresses[OWLY_LINK_PEERS][6],own[6];unsigned count=0;uint64_t generation;
 spin_lock(&owly_link_lock);generation=owly_link_state.generation;memcpy(own,owly_link_state.local,6);
 for(unsigned i=0;i<OWLY_LINK_PEERS;i++)if(owly_peer_known_locked(owly_link_state.peers[i].mac,now))memcpy(addresses[count++],owly_link_state.peers[i].mac,6);
 spin_unlock(&owly_link_lock);
 if(generation!=owly_peer_generation){owly_peer_close_all();spin_lock(&owly_peer_lock);owly_peer_generation=generation;spin_unlock(&owly_peer_lock);}
 spin_lock(&owly_peer_lock);owly_peer_accepting=true;const bool control_pending=owly_control_count!=0;spin_unlock(&owly_peer_lock);
 if(control_pending || now<owly_peer_check_us || now-owly_peer_check_us>=200000u){
  owly_peer_check_us=now;
  for(unsigned i=0;i<4;i++)if(owly_radio_peers[i].sta){bool found=false;
   for(unsigned j=0;j<count;j++)if(!memcmp(addresses[j],owly_radio_peers[i].mac,6))found=true;
   if(!found)owly_peer_drop(&owly_radio_peers[i]);}
  if(!owly_peer_fault)for(unsigned j=0;j<count;j++)if(!owly_peer_find(addresses[j]))
   for(unsigned i=0;i<4;i++)if(!owly_radio_peers[i].sta){const int rc=owly_peer_open(&owly_radio_peers[i],addresses[j]);if(rc)IOLog("OWLY radio peer create refused: rc=%d\n",rc);break;}
 }
 struct owly_peer_packet_queues q;owly_peer_queues_init(&q);spin_lock(&owly_peer_lock);
 for(unsigned i=0;i<4;i++)for(unsigned t=0;t<16;t++)if(owly_radio_peers[i].ba_map&(1u<<t))owly_ba_timeout(&owly_radio_peers[i].reorder[t],now,owly_peer_good,&q);
 spin_unlock(&owly_peer_lock);owly_peer_queues_finish(&q);
 for(unsigned done=0;done<8;done++){
  struct owly_awdl_control c;bool pending;spin_lock(&owly_peer_lock);pending=owly_control_count!=0;
  if(pending)c=owly_controls[owly_control_head];
  spin_unlock(&owly_peer_lock);if(!pending)break;
  bool due=false;spin_lock(&owly_link_lock);const bool known=owly_peer_known_locked(c.bytes+10,now);
  if(known)due=owly_link_unicast_reply_tx_ready(&owly_link_state,c.bytes+10,now);
  spin_unlock(&owly_link_lock);
  const bool stale=c.generation!=generation || now<c.received || now-c.received>OWLY_LINK_PEER_TTL_US || !known;
  if(!stale && !due)break;
  struct owly_ba_request r;uint8_t response[33];int rc=0;uint16_t status=37;struct owly_awdl_radio_peer *p=owly_peer_find(c.bytes+10);
  if(!stale && owly_ba_parse(c.bytes,c.length,own,&r) && p && !p->blocked){
   if(r.action==0){
    const unsigned tid=r.tid;const struct owly_ba_request *old=&p->requests[tid];
    const bool duplicate=(p->ba_map&(1u<<tid)) && old->token==r.token && old->ssn==r.ssn && old->window==r.window && old->timeout==r.timeout;
    if(r.immediate && !duplicate){
     spin_lock(&owly_peer_lock);const bool active=p->ba_map&(1u<<tid);p->ba_map&=~(1u<<tid);owly_ba_clear(&p->reorder[tid],owly_peer_bad,&q);spin_unlock(&owly_peer_lock);owly_peer_queues_finish(&q);
     if(active)rc=owly_peer_ba_firmware(p,tid,false,0,0);
     if(!rc)rc=owly_peer_ba_firmware(p,tid,true,r.ssn,r.window);
     if(!rc){spin_lock(&owly_peer_lock);owly_ba_start(&p->reorder[tid],r.ssn,r.window);p->requests[tid]=r;p->ba_map|=1u<<tid;spin_unlock(&owly_peer_lock);status=0;}
    }else if(r.immediate && duplicate)status=0;else status=38;
    if(!owly_peer_reply_due(&c))break; /* H2C may cross the end of a shared AW. */
    owly_ba_response(c.bytes,own,&r,status,owly_control_sequence++,response);const int tx=owly_sync_submit(ch,response,33,false);
    IOLog("OWLY AWDL BlockAck: tid=%u token=%u window=%u status=%u firmware=%d tx=%d peer=%02x:%02x:%02x:%02x:%02x:%02x delay_us=%llu (not TCP/TLS)\n",
     (unsigned)r.tid,(unsigned)r.token,(unsigned)r.window,(unsigned)status,rc,tx,
     c.bytes[10],c.bytes[11],c.bytes[12],c.bytes[13],c.bytes[14],c.bytes[15],
     (unsigned long long)(glue_now_us()-c.received));
    if(tx==-ENOMEM || tx==-ENOSPC || tx==-EBUSY)break;
   }else if(r.action==2 && r.initiator){
    const unsigned tid=r.tid;spin_lock(&owly_peer_lock);const bool active=p->ba_map&(1u<<tid);p->ba_map&=~(1u<<tid);
    while(p->reorder[tid].active && p->reorder[tid].stored)owly_ba_advance(&p->reorder[tid],owly_peer_good,&q);
    owly_ba_clear(&p->reorder[tid],owly_peer_bad,&q);spin_unlock(&owly_peer_lock);owly_peer_queues_finish(&q);
    if(active)(void)owly_peer_ba_firmware(p,tid,false,0,0);
   }
  }
  spin_lock(&owly_peer_lock);owly_control_head=(owly_control_head+1u)%8;--owly_control_count;spin_unlock(&owly_peer_lock);
 }
}
