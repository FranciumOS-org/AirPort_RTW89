/* SPDX-License-Identifier: GPL-2.0 */ /* Modified 2026-11-15: BlockAck reply/dynamic-CAM fixes; see MODIFICATIONS.md. */
#ifndef OWLY_NATIVE_LINK_H
#define OWLY_NATIVE_LINK_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Caller serializes this core. It never allocates or touches kernel objects.
 * A peer here is observed link-layer state, not authenticated AirDrop identity.
 * Host RX time gives software timing; it is not a hardware TSF measurement. */
#define OWLY_LINK_PEERS 8u
#define OWLY_LINK_QUEUE 32u
#define OWLY_LINK_FRAME_MAX 2048u
#define OWLY_LINK_PEER_TTL_US 2000000ull
#define OWLY_LINK_AW_US 16384ull
struct owly_link_peer {
    bool used, clock_valid;
    uint8_t mac[6], master[6], channels[16], channel, master_channel, local_slots;
    bool has_election;
    /* Private RX state: includes the root metric at value offset 20.
     * The exported owly_link_window below deliberately stays ABI7/20 bytes. */
    uint8_t election[24];
    int8_t rssi;
    uint16_t next_seq, consistent;
    uint8_t outliers;  /* samples ignored in a row while the clock held */
    uint64_t last_rx_us, clock_rx_us, anchor_us, last_mif_rx_us, last_data_rx_us;
};
/* Data keeps the peer alive, never its separately aged action clock. */
static inline bool owly_link_peer_alive(const struct owly_link_peer *p,uint64_t now)
{
    const uint64_t last=p->last_data_rx_us>p->last_rx_us ? p->last_data_rx_us:p->last_rx_us;
    return p->used && now>=last && now-last<=OWLY_LINK_PEER_TTL_US;
}
enum owly_link_tx_kind {
    OWLY_LINK_TX_OTHER,
    OWLY_LINK_TX_MDNS_QUERY,
    OWLY_LINK_TX_MDNS_REPLY,
    OWLY_LINK_TX_UNICAST
};
struct owly_link_frame {
    uint16_t length;
    uint8_t destination[6];
    enum owly_link_tx_kind kind;
    bool awaiting_first_mif;
    uint64_t queued_us, pause_credit_us, generation;
    uint8_t bytes[OWLY_LINK_FRAME_MAX];
};
struct owly_link_window {
    bool active, remote;
    uint8_t channel, master_channel, local[6], master[6];
    uint16_t sequence, until_next_tu;
    uint64_t generation, sampled_us;
    bool has_master_election;
    uint8_t master_election[20];
    uint64_t actions, data_rx_admitted, tx_enqueued, tx_handoffs, tx_refused, tx_expired, tx_radio_acked;
    unsigned peers, queued;
};
struct owly_native_link {
    bool active, sync_enabled, tx_paused, starting;
    uint8_t local[6], channel, preferred[6];
    uint16_t wifi_sequence, awdl_sequence;
    uint64_t generation, last_now_us, pause_started_us, preferred_us;
    uint64_t last_unicast_activity_us;
    struct owly_link_peer peers[OWLY_LINK_PEERS];
    struct owly_link_frame queue[OWLY_LINK_QUEUE];
    unsigned head, count;
    uint8_t queue_order[OWLY_LINK_QUEUE];
    uint32_t queue_used;
    uint64_t actions, rejected_actions, data_rx_admitted, data_rx_rejected;
    uint64_t tx_enqueued, tx_handoffs, tx_refused, tx_expired, tx_radio_acked;
    /* Why a peer's clock was or was not taken: diagnostics only. */
    uint64_t clock_not_root, clock_no_countdown, clock_outlier, clock_reset, clock_ok;
};
void owly_link_reset(struct owly_native_link *s);
void owly_link_reconcile(struct owly_native_link *s,bool active,
                         const uint8_t local[6],uint8_t channel,uint64_t now);
void owly_link_set_tx_paused(struct owly_native_link *s,bool paused,uint64_t now);
bool owly_link_observe(struct owly_native_link *s,const uint8_t *raw,size_t len,
                       uint8_t channel,int8_t rssi,uint64_t received_us);
enum owly_link_ipv6_result {
    OWLY_LINK_IPV6_ACCEPTED,
    OWLY_LINK_IPV6_INACTIVE,
    OWLY_LINK_IPV6_NO_PEER,
    OWLY_LINK_IPV6_BAD_DEST,
    OWLY_LINK_IPV6_INVALID,
    OWLY_LINK_IPV6_RESULT_COUNT
};
enum owly_link_ipv6_result owly_link_admit_ipv6(
    struct owly_native_link *s,const uint8_t src[6],const uint8_t dst[6],
    const uint8_t *ip,size_t len,uint64_t now);
/* A bound channel/local MAC may be present with no active AW yet. */
bool owly_link_window(struct owly_native_link *s,uint64_t now,
                      struct owly_link_window *out);
bool owly_link_action_tx_ready(struct owly_native_link *s,uint64_t now);
bool owly_link_unicast_action_tx_ready(struct owly_native_link *s,
                                      const uint8_t destination[6], uint64_t now);
/* A control reply can use the full confirmed slot, like connection traffic.
 * It still obeys channel, clock, pause and end-of-slot guards. */
bool owly_link_unicast_reply_tx_ready(struct owly_native_link *s,
                                     const uint8_t destination[6], uint64_t now);
/* Backend-only snapshot of a directly observed root's complete election
 * prefix. Does not change the shared frontend snapshot or callback ABI. */
bool owly_link_root_election(struct owly_native_link *s,uint64_t now,
                              uint8_t root[24]);
/* Shared slots in the followed clock's timing domain, on the associated channel. */
uint16_t owly_link_shared_slots(struct owly_native_link *s, uint64_t now);
/* Multichannel: the advertised clock (followed root, else local) and the
 * slots in which that root's domain is on our channel, ignoring the TX pause.
 * Returns true when following a root. */
bool owly_link_clock(struct owly_native_link *s,uint64_t now,uint16_t *seq,
                     uint32_t *phase_us,uint16_t *social_slots,unsigned *peers);
/* Accept IPv6 Ethernet and Apple's wrapped 802.3 frames. Preserve the
 * IPv6 payload and write the supplied on-air sequence and AWDL head. */
int owly_link_build_tx(const uint8_t *eth,size_t len,const uint8_t local[6],
                       uint16_t wifi_seq,uint16_t awdl_seq,
                       uint8_t *out,size_t cap,size_t *out_len);
bool owly_link_data_busy(const struct owly_native_link *s,uint64_t now);
int owly_link_enqueue(struct owly_native_link *s,const uint8_t *eth,size_t len,
                      uint64_t now);
/* Select one due frame. Before the first MIF, hold only Bonjour that was
 * queued before sync started. The caller serializes selection and completion.
 * Transient allocation or ring failures leave the selected frame in the queue.
 * A concurrent RX clock reset invalidates the selection by generation. */
int owly_link_next_tx(struct owly_native_link *s,uint64_t now,bool first_mif_submitted,
                      uint8_t *out,size_t cap,size_t *len,unsigned *offset,
                      uint64_t *generation);
void owly_link_tx_result(struct owly_native_link *s,unsigned offset,uint64_t generation,int result);
void owly_link_prefer(struct owly_native_link *s,const uint8_t master[6]);
/* Idle radio policy: follow the most common channel of a real fresh root;
 * otherwise return the discovery channel. The caller validates RF limits. */
uint8_t owly_link_follow_channel(struct owly_native_link *s,uint64_t now);
/* The social channel fresh peers' own sequences use most; 0 if unknown. */
uint8_t owly_link_peer_channel(struct owly_native_link *s,uint64_t now);
uint8_t owly_link_data_channel(struct owly_native_link *s,uint64_t now);
#endif
