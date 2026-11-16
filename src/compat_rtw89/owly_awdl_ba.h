/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_AWDL_BA_H
#define OWLY_AWDL_BA_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define OWLY_BA_WINDOW 64u
#define OWLY_BA_HOLE_US 100000ull
struct owly_ba_request {uint8_t action,token,tid;uint16_t capability,timeout,ssn,window;bool immediate,initiator;};
static inline uint16_t owly_ba_le16(const uint8_t *p){return (uint16_t)(p[0]|(uint16_t)p[1]<<8);}
static inline void owly_ba_put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static inline bool owly_ba_addressed(const uint8_t *p,size_t n,const uint8_t own[6])
{
 static const uint8_t b[6]={0,0x25,0,0xff,0x94,0x73};
 return p && own && n>=26 && p[0]==0xd0 && !(p[1]&0x47) && !(owly_ba_le16(p+22)&15u) &&
  !memcmp(p+4,own,6) && !(p[10]&1u) && memcmp(p+10,own,6) && !memcmp(p+16,b,6) && p[24]==3;
}
static inline bool owly_ba_parse(const uint8_t *p,size_t n,const uint8_t own[6],struct owly_ba_request *r)
{
 if(!r || !owly_ba_addressed(p,n,own))return false;
 memset(r,0,sizeof(*r));r->action=p[25];
 if(r->action==0){
  if(n<33)return false;
  r->token=p[26];r->capability=owly_ba_le16(p+27);r->tid=(uint8_t)((r->capability>>2)&15u);
  r->immediate=(r->capability&2u)!=0;r->window=r->capability>>6;
  if(!r->window || r->window>OWLY_BA_WINDOW)r->window=OWLY_BA_WINDOW;
  r->timeout=owly_ba_le16(p+29);r->ssn=owly_ba_le16(p+31)>>4;return !(owly_ba_le16(p+31)&15u);
 }
 if(r->action==1){
  if(n<33)return false;
  r->token=p[26];r->capability=owly_ba_le16(p+29);r->tid=(uint8_t)((r->capability>>2)&15u);return true;
 }
 if(r->action==2){
  if(n<30)return false;
  r->capability=owly_ba_le16(p+26);r->tid=(uint8_t)(r->capability>>12);r->initiator=(r->capability&0x800u)!=0;return true;
 }
 return false;
}
static inline size_t owly_ba_response(const uint8_t request[33],const uint8_t own[6],
 const struct owly_ba_request *r,uint16_t status,uint16_t sequence,uint8_t out[33])
{
 if(!request || !own || !r || !out || r->action!=0)return 0;
 memset(out,0,33);out[0]=0xd0;memcpy(out+4,request+10,6);memcpy(out+10,own,6);memcpy(out+16,request+16,6);
 owly_ba_put16(out+22,(uint16_t)((sequence&4095u)<<4));out[24]=3;out[25]=1;out[26]=r->token;
 owly_ba_put16(out+27,status);owly_ba_put16(out+29,(uint16_t)(2u|(uint16_t)r->tid<<2|r->window<<6));
 owly_ba_put16(out+31,r->timeout);return 33;
}
/* Caller serializes; callbacks queue ownership transfers, never input/free under its lock. */
typedef void (*owly_ba_emit)(void *ctx,void *packet);
struct owly_ba_ring {bool active;uint16_t head,index,size,stored;void *slots[64];uint64_t arrived[64];};
static inline void owly_ba_advance(struct owly_ba_ring *s,owly_ba_emit emit,void *ctx)
{
 if(s->slots[s->index]){emit(ctx,s->slots[s->index]);s->slots[s->index]=NULL;s->arrived[s->index]=0;--s->stored;}
 s->head=(uint16_t)((s->head+1u)&4095u);s->index=(uint16_t)((s->index+1u)%s->size);
}
static inline void owly_ba_release(struct owly_ba_ring *s,owly_ba_emit emit,void *ctx)
{while(s->stored && s->slots[s->index])owly_ba_advance(s,emit,ctx);}
static inline void owly_ba_clear(struct owly_ba_ring *s,owly_ba_emit drop,void *ctx)
{for(unsigned i=0;i<64;i++)if(s->slots[i])drop(ctx,s->slots[i]);memset(s,0,sizeof(*s));}
static inline bool owly_ba_start(struct owly_ba_ring *s,uint16_t ssn,uint16_t window)
{
 if(!s || s->stored || !window || window>64 || ssn>4095)return false;
 memset(s,0,sizeof(*s));s->active=true;s->head=ssn;s->size=window;return true;
}
static inline void owly_ba_push(struct owly_ba_ring *s,uint16_t sn,void *packet,uint64_t now,
 owly_ba_emit emit,owly_ba_emit drop,void *ctx)
{
 if(!s->active){emit(ctx,packet);return;}
 sn&=4095u;unsigned delta=(sn-s->head)&4095u;
 if(delta>=2048u){drop(ctx,packet);return;}
 while(delta>=s->size){owly_ba_advance(s,emit,ctx);--delta;}
 const unsigned at=(s->index+delta)%s->size;
 if(s->slots[at]){drop(ctx,packet);return;}
 s->slots[at]=packet;s->arrived[at]=now;++s->stored;owly_ba_release(s,emit,ctx);
}
static inline void owly_ba_bar(struct owly_ba_ring *s,uint16_t ssn,owly_ba_emit emit,void *ctx)
{
 if(!s->active || ssn>4095 || ((ssn-s->head)&4095u)>=2048u)return;
 while(s->head!=ssn)owly_ba_advance(s,emit,ctx);
 owly_ba_release(s,emit,ctx);
}
static inline void owly_ba_timeout(struct owly_ba_ring *s,uint64_t now,owly_ba_emit emit,void *ctx)
{
 if(!s->active || !s->stored)return;
 bool found=false;
 for(unsigned i=0;i<s->size;i++)if(s->slots[i] && now>=s->arrived[i] && now-s->arrived[i]>=OWLY_BA_HOLE_US){found=true;break;}
 if(!found)return;
 while(s->stored && !s->slots[s->index])owly_ba_advance(s,emit,ctx);
 owly_ba_release(s,emit,ctx);
}
#endif
