/* SPDX-License-Identifier: GPL-2.0-only */
#include "owly_event_core.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned tests;
#define TEST(name) do { name(); tests++; puts("PASS " #name); } while (0)

static uint16_t le16(const unsigned char *p) { return p[0] | (uint16_t)p[1] << 8; }
static uint32_t le32(const unsigned char *p)
{ return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static void store32(unsigned char *p, uint32_t v)
{ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }

/* Independent consumer derived from the pinned Apple callback, not from the
 * producer's ring_copy/offset helpers. Its advancement includes BOTH u16s at
 * +24/+26. A 0x50 word skips four bytes. A 0x57 record has a contiguous 48B
 * header and may split its payload around the byte ring.
 */
static int apple_consume(unsigned char *bytes, uint32_t capacity,
    struct owly_event_control *control, uint32_t *event, unsigned char *out,
    size_t *length)
{
    uint32_t head = __atomic_load_n(&control->head, __ATOMIC_ACQUIRE);
    const uint32_t tail = __atomic_load_n(&control->tail, __ATOMIC_ACQUIRE);
    unsigned skipped = 0;
    while (head != tail) {
        assert(head < capacity && !(head & 3));
        if (le32(bytes + head) == 0x50 || capacity - head < 48) {
            head = (head + 4) % capacity;
            assert(++skipped <= capacity / 4);
            __atomic_store_n(&control->head, head, __ATOMIC_RELEASE);
            continue;
        }
        assert(le32(bytes + head) == 0x57);
        const uint16_t n = le16(bytes + head + 24);
        const uint16_t padding = le16(bytes + head + 26);
        assert(n <= 4096 && padding < 4 && *length >= n);
        assert(((48U + n + padding) & 3) == 0);
        assert(!memcmp(bytes + head + 32, "awdl0\0\0\0\0\0\0\0\0\0\0", 16));
        *event = le32(bytes + head + 28);
        for (uint32_t i = 0; i < n; i++) out[i] = bytes[(head + 48 + i) % capacity];
        *length = n;
        head = (head + 48 + n + padding) % capacity;
        assert(!(head & 3));
        __atomic_store_n(&control->head, head, __ATOMIC_RELEASE);
        return 1;
    }
    return 0;
}

static void setup(struct owly_event_core *core, unsigned char *bytes,
    uint32_t capacity, struct owly_event_control *control)
{
    assert(owly_event_init(core, bytes, capacity, control, "awdl0") == OWLY_EVENT_OK);
    assert(owly_event_start(core) == OWLY_EVENT_OK);
    assert(owly_event_register(core) == OWLY_EVENT_OK);
}

static void test_exact_wire_record(void)
{
    uint32_t storage[64], event; unsigned char out[8]; size_t n = sizeof(out);
    unsigned char expected[52] = {0x57};
    struct owly_event_control control; struct owly_event_core core;
    setup(&core, (unsigned char *)storage, sizeof(storage), &control);
    expected[24]=3; expected[26]=1; expected[28]=0x34; expected[29]=0x12;
    memcpy(expected+32,"awdl0",5); expected[48]=0xde; expected[49]=0xad; expected[50]=0xbe;
    const unsigned char payload[]={0xde,0xad,0xbe};
    assert(owly_event_push(&core,0x1234,payload,3)==OWLY_EVENT_OK);
    assert(control.head==0 && control.tail==52);
    assert(!memcmp(storage,expected,sizeof(expected)));
    assert(apple_consume((unsigned char *)storage,sizeof(storage),&control,&event,out,&n));
    assert(event==0x1234 && n==3 && !memcmp(out,payload,3));
    assert(control.head==control.tail);
}

static void test_zero_payload(void)
{
    uint32_t bytes[32],event; unsigned char out[1]; size_t n=1;
    struct owly_event_control control; struct owly_event_core core;
    setup(&core,(unsigned char *)bytes,sizeof(bytes),&control);
    assert(owly_event_push(&core,41,NULL,0)==OWLY_EVENT_OK);
    assert(control.tail==48);
    assert(apple_consume((unsigned char *)bytes,sizeof(bytes),&control,&event,out,&n));
    assert(event==41 && n==0);
}

static void test_all_payload_alignments(void)
{
    uint32_t bytes[128],event; unsigned char in[9]={1,2,3,4,5,6,7,8,9},out[16];
    struct owly_event_control control; struct owly_event_core core;
    setup(&core,(unsigned char *)bytes,sizeof(bytes),&control);
    for(size_t k=1;k<=9;k++){
        size_t n=sizeof(out); assert(owly_event_push(&core,(uint32_t)k,in,k)==OWLY_EVENT_OK);
        assert(apple_consume((unsigned char *)bytes,sizeof(bytes),&control,&event,out,&n));
        assert(n==k && event==k && !memcmp(in,out,k));
    }
}

static void seed_empty(struct owly_event_core *core,uint32_t head)
{
    core->trusted_tail=head;
    __atomic_store_n(&core->control->head,head,__ATOMIC_RELEASE);
    __atomic_store_n(&core->control->tail,head,__ATOMIC_RELEASE);
}

static void test_payload_wrap(void)
{
    uint32_t bytes[32],event; unsigned char in[20],out[20]; size_t n=20;
    for(unsigned i=0;i<20;i++)in[i]=(unsigned char)i;
    struct owly_event_control control; struct owly_event_core core;
    setup(&core,(unsigned char *)bytes,sizeof(bytes),&control); seed_empty(&core,76);
    assert(owly_event_push(&core,84,in,20)==OWLY_EVENT_OK);
    assert(control.tail==16);
    assert(apple_consume((unsigned char *)bytes,sizeof(bytes),&control,&event,out,&n));
    assert(event==84 && n==20 && !memcmp(in,out,20));
}

static void test_header_wrap_padding(void)
{
    uint32_t bytes[32],event; unsigned char out[4]; size_t n=4;
    struct owly_event_control control; struct owly_event_core core;
    setup(&core,(unsigned char *)bytes,sizeof(bytes),&control);seed_empty(&core,120);
    assert(owly_event_push(&core,55,"x",1)==OWLY_EVENT_OK);
    assert(bytes[30]==0x50 && bytes[31]==0x50 && control.tail==52);
    assert(apple_consume((unsigned char *)bytes,sizeof(bytes),&control,&event,out,&n));
    assert(event==55 && n==1 && out[0]=='x' && control.head==52);
}

static void test_full_is_atomic(void)
{
    uint32_t bytes[32],snapshot[32]; struct owly_event_control control;
    struct owly_event_core core;setup(&core,(unsigned char *)bytes,sizeof(bytes),&control);
    assert(owly_event_push(&core,1,"abc",3)==OWLY_EVENT_OK);
    assert(owly_event_push(&core,2,"def",3)==OWLY_EVENT_OK);
    memcpy(snapshot,bytes,sizeof(bytes));const uint32_t tail=control.tail;
    assert(owly_event_push(&core,3,"ghi",3)==OWLY_EVENT_FULL);
    assert(control.tail==tail && !memcmp(bytes,snapshot,sizeof(bytes)));
    assert(core.stats.enqueued==2 && core.stats.full==1);
}

static void test_resume_after_full(void)
{
    uint32_t bytes[32],event;unsigned char out[4];size_t n=4;
    struct owly_event_control control;struct owly_event_core core;
    setup(&core,(unsigned char *)bytes,sizeof(bytes),&control);
    assert(owly_event_push(&core,1,NULL,0)==OWLY_EVENT_OK);
    assert(owly_event_push(&core,2,NULL,0)==OWLY_EVENT_OK);
    assert(owly_event_push(&core,3,NULL,0)==OWLY_EVENT_FULL);
    assert(apple_consume((unsigned char *)bytes,sizeof(bytes),&control,&event,out,&n));
    assert(event==1);
    /* Header wrap would otherwise publish tail == head (ambiguous empty). */
    assert(owly_event_push(&core,3,NULL,0)==OWLY_EVENT_FULL);
    n=sizeof(out);
    assert(apple_consume((unsigned char *)bytes,sizeof(bytes),&control,&event,out,&n));
    assert(event==2);
    assert(owly_event_push(&core,3,NULL,0)==OWLY_EVENT_OK);
}

static void test_payload_limits(void)
{
    uint32_t bytes[2048],event;unsigned char in[4097],out[4096];size_t n=4096;
    memset(in,0xa5,sizeof(in));struct owly_event_control control;struct owly_event_core core;
    setup(&core,(unsigned char *)bytes,sizeof(bytes),&control);
    assert(owly_event_push(&core,1,in,4097)==OWLY_EVENT_BAD_ARGUMENT);
    assert(owly_event_push(&core,1,NULL,1)==OWLY_EVENT_BAD_ARGUMENT);
    assert(owly_event_push(&core,0xffffffffU,in,4096)==OWLY_EVENT_OK);
    assert(apple_consume((unsigned char *)bytes,sizeof(bytes),&control,&event,out,&n));
    assert(n==4096 && event==0xffffffffU && !memcmp(in,out,n));
}

static void test_corrupt_head(void)
{
    for(unsigned k=0;k<2;k++){
        uint32_t bytes[32];struct owly_event_control control;struct owly_event_core core;
        setup(&core,(unsigned char *)bytes,sizeof(bytes),&control);
        control.head=k?3:128;
        assert(owly_event_push(&core,1,NULL,0)==OWLY_EVENT_CORRUPT);
        assert(core.faulted && !core.registered && core.stats.corrupt==1);
        assert(owly_event_start(&core)==OWLY_EVENT_NOT_READY);
    }
}

static void test_corrupt_tail(void)
{
    uint32_t bytes[32];struct owly_event_control control;struct owly_event_core core;
    setup(&core,(unsigned char *)bytes,sizeof(bytes),&control);control.tail=4;
    assert(owly_event_push(&core,1,NULL,0)==OWLY_EVENT_CORRUPT);
    assert(core.trusted_tail==0 && core.stats.enqueued==0);
}

static void test_lifecycle(void)
{
    uint32_t bytes[32];struct owly_event_control control;struct owly_event_core core;
    assert(owly_event_init(&core,bytes,sizeof(bytes),&control,"awdl0")==OWLY_EVENT_OK);
    assert(owly_event_register(&core)==OWLY_EVENT_NOT_READY);
    assert(owly_event_push(&core,1,NULL,0)==OWLY_EVENT_NOT_READY);
    assert(owly_event_start(&core)==OWLY_EVENT_OK);
    assert(owly_event_push(&core,1,NULL,0)==OWLY_EVENT_NOT_READY);
    assert(owly_event_register(&core)==OWLY_EVENT_OK);
    assert(owly_event_push(&core,1,NULL,0)==OWLY_EVENT_OK);
    assert(owly_event_start(&core)==OWLY_EVENT_BUSY && control.tail==48);
    owly_event_halt(&core);assert(owly_event_push(&core,2,NULL,0)==OWLY_EVENT_NOT_READY);
    assert(owly_event_start(&core)==OWLY_EVENT_OK && control.head==0 && control.tail==0);
    owly_event_close(&core);owly_event_close(&core);
    assert(owly_event_register(&core)==OWLY_EVENT_NOT_READY);
    assert(owly_event_start(&core)==OWLY_EVENT_NOT_READY);
}

static void test_capabilities_are_specific(void)
{
    uint8_t answer=0xa5;
    assert(owly_event_query(5,0,&answer)==OWLY_EVENT_OK && answer==0);
    assert(owly_event_query(5,1,&answer)==OWLY_EVENT_OK && answer==1);
    assert(owly_event_query(1,1,&answer)==OWLY_EVENT_OK && answer==0);
    assert(owly_event_query(7,1,&answer)==OWLY_EVENT_OK && answer==0);
    answer=0xa5;assert(owly_event_query(99,1,&answer)==OWLY_EVENT_UNSUPPORTED && answer==0xa5);
    assert(owly_event_query(5,1,NULL)==OWLY_EVENT_BAD_ARGUMENT);
}

struct reader { unsigned char *bytes;size_t length;size_t fail_offset; };
static int read_fixture(void *cookie,size_t offset,void *out,size_t n)
{
    struct reader *r=cookie;
    if(offset==r->fail_offset || offset>r->length || n>r->length-offset)return 0;
    memcpy(out,r->bytes+offset,n);return 1;
}
static void test_sanity_request(void)
{
    unsigned char *input=calloc(1,OWLY_IOUC_SANITY_INPUT_SIZE);
    unsigned char output[OWLY_IOUC_SANITY_OUTPUT_SIZE];size_t n=sizeof(output);
    struct reader r={input,OWLY_IOUC_SANITY_INPUT_SIZE,(size_t)-1};assert(input);
    store32(input,0xc02869c9);memcpy(input+0x3c08,"awdl0",5);store32(input+0x3c18,43);
    assert(owly_event_sanity(read_fixture,&r,r.length,"awdl0",output,&n)==OWLY_EVENT_OK);
    assert(n==0x180 && !strcmp((char*)output,"Owly AirLink EventBridge EB1 / event-only IOUC"));
    for(size_t i=strlen((char*)output)+1;i<n;i++)assert(output[i]==0);
    const size_t fail[]={0,0x3c08,0x3c18};
    for(unsigned k=0;k<3;k++){
        r.fail_offset=fail[k];memset(output,0xa5,sizeof(output));n=sizeof(output);
        assert(owly_event_sanity(read_fixture,&r,r.length,"awdl0",output,&n)==OWLY_EVENT_BAD_ARGUMENT);
        for(size_t i=0;i<sizeof(output);i++)assert(output[i]==0xa5);
    }
    r.fail_offset=(size_t)-1;n=sizeof(output);
    assert(owly_event_sanity(read_fixture,&r,r.length,"awdl1",output,&n)==OWLY_EVENT_BAD_ARGUMENT);
    store32(input+0x3c18,44);
    assert(owly_event_sanity(read_fixture,&r,r.length,"awdl0",output,&n)==OWLY_EVENT_UNSUPPORTED);
    store32(input+0x3c18,43);store32(input,0);
    assert(owly_event_sanity(read_fixture,&r,r.length,"awdl0",output,&n)==OWLY_EVENT_UNSUPPORTED);
    store32(input,0xc02869c9);n=0x17f;
    assert(owly_event_sanity(read_fixture,&r,r.length,"awdl0",output,&n)==OWLY_EVENT_BAD_ARGUMENT);
    n=sizeof(output);
    assert(owly_event_sanity(read_fixture,&r,r.length-1,"awdl0",output,&n)==OWLY_EVENT_BAD_ARGUMENT);
    free(input);
}

static void test_bounds_and_names(void)
{
    uint32_t bytes[32];struct owly_event_control control;struct owly_event_core core;
    const char *bad[]={"","awdl/0","abcdefghijklmnop",NULL};
    for(unsigned k=0;k<4;k++)assert(owly_event_init(&core,bytes,sizeof(bytes),&control,bad[k])==OWLY_EVENT_BAD_ARGUMENT);
    assert(owly_event_init(&core,bytes,60,&control,"awdl0")==OWLY_EVENT_BAD_ARGUMENT);
    assert(owly_event_init(&core,bytes,127,&control,"awdl0")==OWLY_EVENT_BAD_ARGUMENT);
    assert(owly_event_init(&core,(unsigned char*)bytes+1,64,&control,"awdl0")==OWLY_EVENT_BAD_ARGUMENT);
    assert(owly_event_init(&core,bytes,64,(void*)((unsigned char*)&control+1),"awdl0")==OWLY_EVENT_BAD_ARGUMENT);
}

static uint32_t random_state=0x12345678;
static uint32_t rnd(void)
{ random_state^=random_state<<13;random_state^=random_state>>17;random_state^=random_state<<5;return random_state; }
static void test_randomized_fifo(void)
{
    uint32_t bytes[2048],queue[4096],expected_size[4096],read_index=0,write_index=0;
    unsigned char payload[4096],out[4096];struct owly_event_control control;struct owly_event_core core;
    setup(&core,(unsigned char *)bytes,sizeof(bytes),&control);
    for(unsigned iteration=0;iteration<100000;iteration++){
        if((rnd()&3)!=0){
            const uint32_t size=rnd()%4097,id=write_index+1;memset(payload,(int)(id&255),size);
            const enum owly_event_result r=owly_event_push(&core,id,payload,size);
            assert(r==OWLY_EVENT_OK || r==OWLY_EVENT_FULL);
            if(r==OWLY_EVENT_OK){queue[write_index%4096]=id;expected_size[write_index%4096]=size;write_index++;}
        }else{
            uint32_t event;size_t size=sizeof(out);
            if(apple_consume((unsigned char*)bytes,sizeof(bytes),&control,&event,out,&size)){
                assert(read_index<write_index && event==queue[read_index%4096] && size==expected_size[read_index%4096]);
                for(size_t k=0;k<size;k++) { assert(out[k]==(event&255)); }
                read_index++;
            }else assert(read_index==write_index);
        }
    }
    while(read_index<write_index){
        uint32_t event;size_t size=sizeof(out);
        assert(apple_consume((unsigned char*)bytes,sizeof(bytes),&control,&event,out,&size));
        assert(event==queue[read_index%4096] && size==expected_size[read_index%4096]);read_index++;
    }
    assert(control.head==control.tail && core.stats.enqueued==write_index);
}

struct concurrent {uint32_t bytes[2048];struct owly_event_control control;struct owly_event_core core;};
static void *produce_thread(void *arg)
{
    struct concurrent *c=arg;unsigned char data[71];
    for(uint32_t id=1;id<=100000;id++){
        const size_t n=id%sizeof(data);memset(data,(int)(id&255),n);
        enum owly_event_result r;
        while((r=owly_event_push(&c->core,id,data,n))==OWLY_EVENT_FULL)sched_yield();
        assert(r==OWLY_EVENT_OK);
    }
    return NULL;
}
static void test_concurrent_spsc(void)
{
    struct concurrent *c=calloc(1,sizeof(*c));assert(c);setup(&c->core,(void*)c->bytes,sizeof(c->bytes),&c->control);
    pthread_t thread;assert(!pthread_create(&thread,NULL,produce_thread,c));
    for(uint32_t id=1;id<=100000;id++){
        uint32_t event;unsigned char data[71];size_t n=sizeof(data);
        while(!apple_consume((void*)c->bytes,sizeof(c->bytes),&c->control,&event,data,&n))sched_yield();
        assert(event==id && n==id%sizeof(data));for(size_t i=0;i<n;i++)assert(data[i]==(id&255));
    }
    assert(!pthread_join(thread,NULL));assert(c->core.stats.enqueued==100000);free(c);
}

int main(void)
{
    TEST(test_exact_wire_record);TEST(test_zero_payload);TEST(test_all_payload_alignments);
    TEST(test_payload_wrap);TEST(test_header_wrap_padding);TEST(test_full_is_atomic);
    TEST(test_resume_after_full);TEST(test_payload_limits);TEST(test_corrupt_head);
    TEST(test_corrupt_tail);TEST(test_lifecycle);TEST(test_capabilities_are_specific);
    TEST(test_sanity_request);TEST(test_bounds_and_names);TEST(test_randomized_fifo);
    TEST(test_concurrent_spsc);
    printf("RESULT %u test groups passed; native kernel/AirDrop not validated\n",tests);
    return 0;
}
