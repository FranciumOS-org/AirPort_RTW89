// SPDX-License-Identifier: GPL-2.0
/*
 * Platform glue, Linux side: see rtw89_glue.h. Turns the platform's services
 * into the struct pci_dev and the PCI/DMA ops the compat layer expects, then
 * drives the driver's own pci_driver.
 */
#include "rtw89_net80211.h"
#include "rtw89_glue.h"
#if defined(RTW89_MACOS) && defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
#include "owly_unicast_observe.h"
#include "owly_radio_timing.h"
static struct owly_radio_sequence owly_radio_tx_sequence;
static struct owly_radio_rx_clock owly_radio_rx_clock;
static void owly_unicast_note(unsigned stage,const uint8_t *ip,size_t n,int result,bool delivered)
{
    static volatile unsigned long samples[3];
    if(stage>=3)return;
    const unsigned long count=__sync_add_and_fetch(&samples[stage],1ul);
    if(count>8ul && (count&(count-1ul)))return;
    const struct owly_tcp_observation o=owly_observe_ip(ip,n);
    IOLog("OWLY unicast stage: stage=%u count=%lu ipv6=%u tcp=%u flags=0x%02x srcp=%u dstp=%u seq=%u ack=%u result=%d delivered=%u bytes=%lu\n",
          stage,count,(unsigned)o.ipv6,(unsigned)o.tcp,(unsigned)o.flags,(unsigned)o.source,
          (unsigned)o.destination,(unsigned)o.sequence,(unsigned)o.acknowledgment,result,
          (unsigned)delivered,(unsigned long)n);
}
#endif
/* OWLY_CORE04F_DIAGNOSTIC: fixed 40B vendor-action transport probe.
 * A bounded incomplete frame; NEVER claim an AWDL protocol handshake.
 */
#if defined(RTW89_AWDL_CORE04F_ONE_SHOT) && RTW89_AWDL_CORE04F_ONE_SHOT
#include "rtw89_awdl_core04f_probe.h"
/* OWLY_CORE04F_R1_2GHZ_POLICY: no change to driver regulatory limits. */
#include "rtw89_awdl_core04f_r1_policy.h"
#if !defined(RTW89_AWDL_VIF_REGISTER) || !RTW89_AWDL_VIF_REGISTER || \
    !defined(RTW89_AWDL_CHANCTX_ATTACH) || !RTW89_AWDL_CHANCTX_ATTACH || \
    !defined(RTW89_AWDL_MGMT_BRIDGE) || !RTW89_AWDL_MGMT_BRIDGE || \
    !defined(RTW89_AWDL_MGMT_RF_TX) || !RTW89_AWDL_MGMT_RF_TX
#error "Core-04F requires VIF+chanctx+bridge and explicit RF TX opt-in"
#endif
#endif

/* OWLY_CORE04C_VIF_STAGE_BEGIN: optional P2P-client shim, never awdl0. */
#if defined(RTW89_AWDL_VIF_STAGE) && RTW89_AWDL_VIF_STAGE
#include "rtw89_awdl_vif_stage.h"
#ifndef RTW89_AWDL_VIF_REGISTER
#define RTW89_AWDL_VIF_REGISTER 0
#endif
#endif
/* OWLY_CORE04C_VIF_STAGE_INCLUDES_END */

#if defined(OWLY_AWDL_RX_SHADOW) && OWLY_AWDL_RX_SHADOW
#include "owly_awdl_shadow.h"
#endif
#if defined(OWLY_ABI6_RX_DEMUX) && OWLY_ABI6_RX_DEMUX
#if !defined(OWLY_SCC_SOCIAL_RX) || !OWLY_SCC_SOCIAL_RX
#error "ABI6 demux requires SCC social RX"
#endif
#include "owly_abi6_rx.h"
#endif
#if defined(OWLY_ABI6_C3_SCAN_OBSERVER) && OWLY_ABI6_C3_SCAN_OBSERVER
#if !defined(OWLY_ABI6_RX_DEMUX) || !OWLY_ABI6_RX_DEMUX || \
    !defined(OWLY_ABI6_FRONT_BRIDGE) || !OWLY_ABI6_FRONT_BRIDGE
#error "C3 scan observer requires C2 RX demux and frontend bridge"
#endif
#include "owly_gatec3_scan_action.h"
#endif
/* OWLY_PHASE_G_PROBE_START -- OFF unless RTW89_AWDL_RX_PROBE=1. */
#if defined(RTW89_AWDL_RX_PROBE) && RTW89_AWDL_RX_PROBE
#include "rtw89_awdl_rx_probe.h"
#if defined(RTW89_AWDL_ACTION_DECODE) && RTW89_AWDL_ACTION_DECODE
#include "rtw89_awdl_action_decode.h"
/* OWLY_CORE04_TX_FORMAT: header is compiled only if explicitly enabled.
 * No frame is transmitted by this patch. */
#if defined(RTW89_AWDL_TX_FRAME) && RTW89_AWDL_TX_FRAME
#include "rtw89_awdl_tx_frame.h"
#endif
#if defined(RTW89_AWDL_PEER_TRACK) && RTW89_AWDL_PEER_TRACK
#include "rtw89_awdl_peer_table.h"
static struct owly_peer_table owly_peer_state;
/* Core-03: opt-in, passive sequence/uptime estimator, no radio control. */
#if defined(RTW89_AWDL_CLOCK_TRACK) && RTW89_AWDL_CLOCK_TRACK
#include <kern/clock.h>
#include <mach/mach_time.h>
#include "rtw89_awdl_clock.h"
static struct owly_clock_peer owly_clock_peers[OWLY_PEER_CAPACITY];
#endif
#endif
#endif
static volatile unsigned long rtw89_awdl_rx_total_observed;
static volatile unsigned long rtw89_awdl_bssid_observed;
static volatile unsigned long rtw89_awdl_action_observed;
static volatile unsigned long rtw89_awdl_data_observed;
#if defined(RTW89_AWDL_ACTION_DECODE) && RTW89_AWDL_ACTION_DECODE
static volatile unsigned long owly_actions_decoded;
static volatile unsigned long owly_actions_bad;
#endif

/* Restrict total-RX log to 1, 2, 4, 8, ...; AWDL candidates are rarer,
 * so report the first 64 individually and later only milestones.
 * NO packet contents or hardware addresses are logged. */
static int rtw89_awdl_is_log_milestone(unsigned long count)
{
    return count && (count & (count - 1ul)) == 0;
}

static int rtw89_awdl_should_log_candidate(unsigned long count)
{
    return count <= 64ul || rtw89_awdl_is_log_milestone(count);
}

static void rtw89_awdl_probe_note(const unsigned char *frame, size_t len,
                                  unsigned int freq_mhz)
{
    enum rtw89_awdl_rx_kind kind;
    unsigned long count;
    volatile unsigned long *counter;

    /* Caller validated CRC and minimum length. The macOS compat skb is
     * linear; observation never owns or stores an skb. The frequency is
     * derived from RX status and is diagnostic, NOT verified RF channel. */
    count = __sync_add_and_fetch(&rtw89_awdl_rx_total_observed, 1ul);
    if (rtw89_awdl_is_log_milestone(count))
        IOLog("RTW89 AWDL probe: metric=rx_total count=%lu (UNVERIFIED)\n", count);

    if (!rtw89_awdl_rx_has_bssid(frame, len))
        return;
    count = __sync_add_and_fetch(&rtw89_awdl_bssid_observed, 1ul);
    if (rtw89_awdl_should_log_candidate(count))
        IOLog("RTW89 AWDL probe: metric=awdl_bssid count=%lu freq_mhz=%u (UNVERIFIED)\n",
              count, freq_mhz);

    kind = rtw89_awdl_rx_classify(frame, len);
    if (kind == RTW89_AWDL_RX_OTHER)
        return;
    /* OWLY_CORE01_ACTION_BEGIN: passive structured AWDL Action decode.
     * OFF by default. No packet ownership, TX, RX-filter or channel changes.
     * Parsed metadata alone cannot authenticate a peer or establish an AWDL session.
     * No device identifiers, packet bytes or hostnames in diagnostics. */
#if defined(RTW89_AWDL_ACTION_DECODE) && RTW89_AWDL_ACTION_DECODE
    if (kind == RTW89_AWDL_RX_ACTION) {
        struct owly_action_info decoded;
        enum owly_action_result decoded_result =
            owly_decode_action(frame, len, &decoded);
        unsigned long decoded_count = __sync_add_and_fetch(
            decoded_result == OWLY_ACTION_DECODED ?
            &owly_actions_decoded : &owly_actions_bad, 1ul);
        /* OWLY_CORE02_PEER_HOOK: update on EVERY decoded frame, not only
         * when the rate-limited diagnostic is printed. Never log addresses. */
#if defined(RTW89_AWDL_PEER_TRACK) && RTW89_AWDL_PEER_TRACK
        if (decoded_result == OWLY_ACTION_DECODED) {
            struct owly_peer_event pe;
            /* MAC 802.11 addr2: [10,16), checked by decoder (len >= 40). */
            if (owly_peer_observe(&owly_peer_state, frame + 10, &decoded, &pe)) {
                /* OWLY_CORE03_CLOCK_HOOK: only a monotonic observation, not
                 * hardware TSF. Never schedules radio activity or packets. */
#if defined(RTW89_AWDL_CLOCK_TRACK) && RTW89_AWDL_CLOCK_TRACK
                if (decoded.has_sync && pe.slot >= 1u &&
                    pe.slot <= OWLY_PEER_CAPACITY) {
                    uint64_t uptime_ticks = 0;
                    uint64_t uptime_ns = 0;
                    struct owly_clock_event clk;
                    uptime_ticks = mach_absolute_time();
                    absolutetime_to_nanoseconds(uptime_ticks, &uptime_ns);
                    clk = owly_clock_observe(&owly_clock_peers[pe.slot - 1u],
                                             (unsigned long long)(uptime_ns / 1000ull),
                                             decoded.next_aw_seq, decoded.aw_period_tu,
                                             pe.newly_seen || pe.evicted);
                    /* Print mismatches and first 64 candidates; no peer MACs. */
                    if (rtw89_awdl_should_log_candidate(decoded_count) ||
                        clk.status == 3u || clk.status == 5u) {
                        IOLog("OWLY core03: slot=%u state=%u pairs=%u "
                              "seq_step=%u expected_us=%llu actual_us=%llu "
                              "error_us=%llu (ESTIMATE_NOT_TSF)\n",
                              pe.slot, clk.status, clk.good_pairs,
                              clk.seq_delta, clk.expected_us,
                              clk.actual_us, clk.abs_error_us);
                    }
                }
#endif
                if (rtw89_awdl_should_log_candidate(decoded_count)) {
                    IOLog("OWLY core02: peer_slot=%u new=%u evicted=%u "
                          "psf=%lu mif=%lu saw_mif=%u next_seq=%u "
                          "freq_mhz=%u (OBSERVED_UNVERIFIED)\n",
                          pe.slot, (unsigned int)pe.newly_seen,
                          (unsigned int)pe.evicted, pe.psf_count,
                          pe.mif_count, (unsigned int)pe.saw_mif,
                          (unsigned int)pe.last_aw_seq, freq_mhz);
                }
            }
        }
#endif
        if (rtw89_awdl_should_log_candidate(decoded_count)) {
            if (decoded_result == OWLY_ACTION_DECODED) {
                IOLog("OWLY core01: action_decoded=%lu subtype=%u freq_mhz=%u "
                      "sync=%u aw_period_tu=%u tx_down_tu=%u next_seq=%u "
                      "chanseq=%u social_mask=%u awdl_ver=%u device_class=%u "
                      "complete=%u (UNVERIFIED)\n",
                      decoded_count, (unsigned int)decoded.subtype, freq_mhz,
                      (unsigned int)decoded.has_sync,
                      (unsigned int)decoded.aw_period_tu,
                      (unsigned int)decoded.tx_down_tu,
                      (unsigned int)decoded.next_aw_seq,
                      (unsigned int)decoded.has_chanseq,
                      (unsigned int)decoded.social_mask,
                      (unsigned int)decoded.awdl_version,
                      (unsigned int)decoded.device_class,
                      (unsigned int)decoded.complete);
            } else {
                IOLog("OWLY core01: action_malformed_or_unmatched=%lu freq_mhz=%u "
                      "(UNVERIFIED)\n", decoded_count, freq_mhz);
            }
        }
    }
#endif
    /* OWLY_CORE01_ACTION_END */
    counter = kind == RTW89_AWDL_RX_ACTION ?
        &rtw89_awdl_action_observed : &rtw89_awdl_data_observed;
    count = __sync_add_and_fetch(counter, 1ul);
    if (rtw89_awdl_should_log_candidate(count))
        IOLog("RTW89 AWDL probe: metric=%s count=%lu freq_mhz=%u (UNVERIFIED)\n",
              kind == RTW89_AWDL_RX_ACTION ? "action" : "ipv6", count, freq_mhz);
}
#endif
/* OWLY_PHASE_G_PROBE_END */
#include "rtw89_crypto.h"
#include "core.h"
#include "coex.h"
#include "phy.h"
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
#include "cam.h"
#include "fw.h"
#include "reg.h"
#endif

void rtw88_trigger_interrupt(void);
void rtw89_compat_debug_init(void);
/* src/compat/rtw88_compat.c */
extern void (*rtw88_napi_post_poll)(int done);
bool rtw88_queue_datapath_delayed_work(struct delayed_work *dwork, unsigned long delay);
/* rtw89_core_wrap.c */
unsigned int rtw89_compat_flush_ppdu_rx(struct rtw89_dev *rtwdev);
/* The address the chip answers to; see rtw89_core_wrap.c. */
int rtw89_compat_set_self_addr(struct ieee80211_vif *vif, const u8 *addr);

/* ------------------------------------------------------------------ */
/*  State                                                               */
/* ------------------------------------------------------------------ */

/*
 * A DMA mapping. dma_alloc_coherent() memory is one platform allocation.
 * dma_map_single() of arbitrary kernel memory is done by bouncing: the device
 * gets a platform allocation and the data is copied in or out at map, sync
 * and unmap time (what Linux's swiotlb does), because kernel heap memory here
 * is neither guaranteed contiguous nor below 4 GB.
 */
struct rtw89_glue_dma {
    struct hlist_node node;     /* in dma_hash, keyed by bus address */
    u64 bus;
    void *virt;                 /* platform allocation */
    void *orig;                 /* caller's buffer for bounce mappings, else NULL */
    size_t size;
    void *cookie;
};

#define RTW89_GLUE_DMA_BUCKETS 256
#define RTW89_GLUE_MAX_BSS 128
#define RTW89_GLUE_MAX_IES 1024
#define GLUE_SCAN_SLICE 8               /* channels per scan while connected */

/* A network heard in a scan: what callers see plus what a join needs. */
struct rtw89_glue_bss_entry {
    struct rtw89_glue_bss pub;
    unsigned long last_seen;    /* jiffies of the last frame heard from it */
    u32 scan_gen;               /* the scan it was last heard in */
    u16 beacon_int;
    u16 ies_len;
    u8 ies[RTW89_GLUE_MAX_IES];
};

static struct {
    bool active;
    struct rtw89_glue_platform plat;
    struct pci_dev pdev;
    struct pci_driver *drv;
    bool probed;

    spinlock_t dma_lock;
    struct hlist_head dma_hash[RTW89_GLUE_DMA_BUCKETS];
    unsigned int dma_count;

    /* radio up: one station interface */
    bool up;
    struct ieee80211_vif *vif;
    bool have_mac;                      /* rtw89_glue_set_mac() */
    u8 mac[ETH_ALEN];

    /* scan */
    bool scanning;
    struct ieee80211_scan_request *scan_req;    /* kept until the next scan */
    spinlock_t bss_lock;
    struct rtw89_glue_bss_entry bss[RTW89_GLUE_MAX_BSS];
    unsigned int n_bss;
    u32 scan_gen;               /* counts the scans started */

    /* The network the user asked for, kept to join it again when the
     * connection is lost: once it has worked, so that a wrong password is
     * not tried for ever. */
    struct mutex cmd_lock;              /* up, down, scan, join, leave and the rejoin work */
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
    /* macOS keeps the logical VIF across radio power cycles. cmd_lock owns
     * this accepted address until the logical VIF is explicitly destroyed. */
    u8 awdl_vif_mac[ETH_ALEN];
#endif
    struct {
        bool valid;
        bool proven;                    /* has been connected with these */
        u8 ssid[IEEE80211_MAX_SSID_LEN];
        u8 ssid_len;
        bool have_pmk;
        u8 pmk[32];
        u8 password[RTW89_GLUE_MAX_PASSWORD];  /* for SAE (WPA3-Personal) */
        u8 password_len;
    } want;
    u8 asked_bssid[ETH_ALEN];           /* macOS's choice, when a better one was joined */
    bool rejoin_off;                    /* rtw89_glue_set_rejoin(false) */
    bool rejoining;                     /* trying to get back */
    bool rejoin_scanned;                /* this attempt has had its scan */
    unsigned int rejoin_tries;          /* attempts since the connection was lost */
    u32 rejoins;                        /* times it came back */
    unsigned long scan_started;
    bool scan_connected;                /* the scan started while associated */
    bool awdl_other_bss;                /* the AWDL receive filter is relaxed */
    unsigned int scan_slice_pos;        /* where the next connected scan starts */
    u32 last_scan_channels;
    u32 scans_connected;
    u32 scan_ms_connected;
    u32 last_scan_ms;
    /* On a thread of its own: the driver's works run on the shared queue,
     * and the scan and join started from here wait for some of them. */
    struct workqueue_struct *rejoin_wq;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    struct workqueue_struct *awdl_rx_wq;
#endif
    struct delayed_work rejoin_work;
    u8 awdl_mac_asked[ETH_ALEN];        /* the self address last asked for */
    int awdl_mac_last;                  /* and what came back, so a change is logged */

    /* the rate of the last frame the AP sent to us alone, see glue_rx_rate() */
    u32 rx_rate;

    /* frames the driver holds for a PPDU status report, see rtw89_core_wrap.c */
    bool ppdu_flush;                    /* pass them on after a short wait */
    struct delayed_work ppdu_flush_work;
    u32 ppdu_flushed;

    /* How long frames take from the chip's receive timestamp to here. The
     * chip's clock and ours are compared through the smallest difference seen
     * lately (two windows, so drift between the clocks cannot build up). */
    u32 rx_base, rx_base_prev;
    bool rx_base_valid, rx_base_prev_valid;
    u64 rx_base_since;
    u32 rx_late;                        /* frames more than 5 ms late */
    u32 rx_late_irq;                    /* ... of which an interrupt came when they arrived */
    u32 rx_late_max;                    /* ms */
    u64 irq_time[16];                   /* our clock, us, of the last interrupts */
    unsigned int irq_next;
} glue;

#define RTW89_GLUE_PPDU_WAIT    1       /* ms a frame may wait for its status report */
#define RTW89_GLUE_LATE_US      5000

#if defined(OWLY_SCC_SOCIAL_RX) && OWLY_SCC_SOCIAL_RX
#if !defined(RTW89_AWDL_VIF_STAGE) || !RTW89_AWDL_VIF_STAGE
#error "OWLY SCC social RX requires ABI5 staged hardware VIF"
#endif
#if defined(RTW89_AWDL_RX_OTHER_BSS_TRIAL) && RTW89_AWDL_RX_OTHER_BSS_TRIAL
#error "OWLY SCC social RX cannot be combined with unguarded legacy OTHER_BSS"
#endif
#if !defined(OWLY_AWDL_RX_SHADOW) || !OWLY_AWDL_RX_SHADOW
#error "OWLY SCC social RX requires passive RX Shadow for comparison"
#endif
#if defined(RTW89_AWDL_CHANCTX_ATTACH) && RTW89_AWDL_CHANCTX_ATTACH
#error "OWLY SCC social RX must not attach channel contexts"
#endif
#if defined(RTW89_AWDL_MGMT_RF_TX) && RTW89_AWDL_MGMT_RF_TX
#error "OWLY SCC social RX may not transmit RF"
#endif
#if defined(RTW89_AWDL_CORE04F_ONE_SHOT) && RTW89_AWDL_CORE04F_ONE_SHOT
#error "OWLY SCC social RX may not arm an RF diagnostic TX"
#endif
#include "owly_scc_rx_policy.h"
static bool owly_scc_aux_ready;
static bool owly_scc_filter_reported;
static void owly_scc_filter_set(bool should_enable, unsigned int freq);
#endif
static struct ieee80211_hw *glue_hw(void);
static void glue_deliver(const u8 *frame, size_t len);
static void glue_tx_wake(void);
struct rtw89_glue_bss_entry;
static void glue_bss_describe(struct rtw89_glue_bss_entry *e);
static void glue_rejoin_work(struct work_struct *work);
static void glue_rejoin_queue(unsigned long delay);

#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
#if !defined(OWLY_BACKEND_REAL_VIF) || !OWLY_BACKEND_REAL_VIF || \
    !defined(RTW89_AWDL_CHANCTX_GUARD) || !RTW89_AWDL_CHANCTX_GUARD
#error "Radio SCC requires on-demand VIF and guarded assignment"
#endif
#if RTW89_AWDL_CHANCTX_ATTACH || RTW89_AWDL_VIF_REGISTER
#error "Radio SCC must not use the old automatic VIF/channel trial"
#endif
#if (defined(RTW89_AWDL_MGMT_RF_TX) && RTW89_AWDL_MGMT_RF_TX) || \
    (defined(RTW89_AWDL_CORE04F_ONE_SHOT) && RTW89_AWDL_CORE04F_ONE_SHOT)
#error "Radio SCC lifecycle revision has no qualified RF TX path"
#endif
#include "owly_awdl_radio_lifecycle.h"
static struct owly_radio_lease owly_radio_state;
static struct wiphy_work owly_radio_work;
static uint64_t owly_idle_policy_us;
static uint64_t owly_idle_move_us;
static void owly_radio_maybe_attach(void);
static void owly_radio_work_run(struct wiphy *wiphy, struct wiphy_work *work);
static void owly_radio_detach(struct ieee80211_chanctx_conf *primary);
#if defined(OWLY_AWDL_SOFTWARE_SYNC) && OWLY_AWDL_SOFTWARE_SYNC
#include "owly_awdl_sync.h"
static struct owly_sync owly_sync_state;
/* The receive worker does not hold the command mutex. Publish only its
 * 32-bit threshold atomically; never race a whole configuration copy. */
static int owly_cfg_rssi_floor=-128;
static unsigned int owly_cfg_rssi_drops;
static struct wiphy_delayed_work owly_sync_work;
static uint8_t owly_sync_txbuf[OWLY_SYNC_FRAME_MAX];
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
static struct owly_native_link owly_link_state;
static spinlock_t owly_link_lock;
static uint8_t owly_link_txbuf[OWLY_LINK_FRAME_MAX];
static struct ieee80211_vif *owly_core04c_vif;
static void owly_peer_init(void);
static void owly_peer_drain_rx(void);
static void owly_peer_fini(void);
struct owly_native_rx_meta {
    uint8_t channel;
    int8_t rssi;
    uint64_t received_us;
    unsigned int ipv6_results[OWLY_LINK_IPV6_RESULT_COUNT];
    unsigned int ipv6_front_refused;
};
static void owly_link_update_locked(struct ieee80211_channel *channel, uint64_t now);
/* Multichannel AWDL (owly_awdl_mc.h): visits to channel 6 while the
 * station is associated on a channel AWDL does not use. */
#define OWLY_MC_BUILT 1
#include "owly_awdl_mc.h"
static struct {
    bool enabled;   /* associated off the social channels: AWDL bound to ch 6 */
    bool present;   /* visiting: the radio is on the AWDL channel right now */
    bool home;      /* the AWDL channel is the AP's own: no visits needed */
    bool off;       /* boot-arg -owlynomc */
    uint8_t channel; /* social channel visited: 6, 44 or 149 (0 = not chosen) */
    uint16_t slots, root_slots;
    uint64_t visits, null_failures, slow_switches, max_switch_us;
    uint64_t moved_us, root_us, slot_log_us;
    uint32_t switch_avg_us, lead_us;
    uint64_t data_rx_seen, data_rx_us;  /* AWDL data from peers: busy too */
    uint64_t peer_log_us;
    uint8_t last_follow, last_data_ch;
    bool last_rooted;
} owly_mc;
static unsigned owly_mc_freq(uint8_t ch)
{
    return ch == 149 ? 5745u : ch == 44 ? 5220u : 2437u;
}
static struct wiphy_delayed_work owly_mc_work;
static void owly_mc_work_run(struct wiphy *wiphy, struct wiphy_work *work);
static void owly_mc_leave(void);
static void owly_mc_end_hook(void);
static void owly_mc_stop(void);
static void owly_mc_kick(void);
#if defined(RTW89_MACOS)
#include <pexpert/pexpert.h>
#else
static inline int PE_parse_boot_argn(const char *n, void *v, int l)
{ (void)n; (void)v; (void)l; return 0; }
#endif
#endif
static void owly_sync_work_run(struct wiphy *wiphy, struct wiphy_work *work);
static void owly_sync_recheck(void);
static void owly_sync_pause(bool clear);
#endif
#endif

/* ------------------------------------------------------------------ */
/*  PCI ops                                                             */
/* ------------------------------------------------------------------ */

static int glue_read_config_byte(struct pci_dev *dev, int where, u8 *val)
{
    *val = (u8)glue.plat.cfg_read(glue.plat.ctx, where, 1);
    return 0;
}

static int glue_read_config_word(struct pci_dev *dev, int where, u16 *val)
{
    *val = (u16)glue.plat.cfg_read(glue.plat.ctx, where, 2);
    return 0;
}

static int glue_read_config_dword(struct pci_dev *dev, int where, u32 *val)
{
    *val = glue.plat.cfg_read(glue.plat.ctx, where, 4);
    return 0;
}

static int glue_write_config_byte(struct pci_dev *dev, int where, u8 val)
{
    glue.plat.cfg_write(glue.plat.ctx, where, 1, val);
    return 0;
}

static int glue_write_config_word(struct pci_dev *dev, int where, u16 val)
{
    glue.plat.cfg_write(glue.plat.ctx, where, 2, val);
    return 0;
}

static int glue_write_config_dword(struct pci_dev *dev, int where, u32 val)
{
    glue.plat.cfg_write(glue.plat.ctx, where, 4, val);
    return 0;
}

/* The platform maps the BAR once; the driver just gets that mapping. */
static void *glue_ioremap(struct pci_dev *dev, int bar, size_t len)
{
    return (void *)dev->resource[bar];
}

static void glue_iounmap(struct pci_dev *dev, void *addr)
{
}

/* The platform picks the interrupt (MSI where available) on its own. */
static int glue_enable_msi(struct pci_dev *dev)
{
    return 0;
}

static void glue_disable_msi(struct pci_dev *dev)
{
}

/* Walk the classic capability list in the first 256 bytes of config space. */
static int glue_find_capability(struct pci_dev *dev, int cap)
{
    int ttl = 48;
    u16 status;
    u8 pos, id;

    glue_read_config_word(dev, PCI_STATUS, &status);
    if (!(status & PCI_STATUS_CAP_LIST))
        return 0;

    glue_read_config_byte(dev, PCI_CAPABILITY_LIST, &pos);
    while (ttl-- && pos >= 0x40) {
        pos &= ~3;
        glue_read_config_byte(dev, pos + PCI_CAP_LIST_ID, &id);
        if (id == 0xff)
            break;
        if (id == cap)
            return pos;
        glue_read_config_byte(dev, pos + PCI_CAP_LIST_NEXT, &pos);
    }
    return 0;
}

static struct pci_ops_rtw88 glue_pci_ops = {
    .read_config_byte    = glue_read_config_byte,
    .read_config_word    = glue_read_config_word,
    .read_config_dword   = glue_read_config_dword,
    .write_config_byte   = glue_write_config_byte,
    .write_config_word   = glue_write_config_word,
    .write_config_dword  = glue_write_config_dword,
    .ioremap             = glue_ioremap,
    .iounmap             = glue_iounmap,
    .enable_msi          = glue_enable_msi,
    .disable_msi         = glue_disable_msi,
    .pci_find_capability = glue_find_capability,
};

/* ------------------------------------------------------------------ */
/*  DMA ops                                                             */
/* ------------------------------------------------------------------ */

static struct hlist_head *glue_dma_bucket(u64 bus)
{
    /* Platform allocations are page-aligned, so skip the low bits. */
    return &glue.dma_hash[(bus >> 12) % RTW89_GLUE_DMA_BUCKETS];
}

static struct rtw89_glue_dma *glue_dma_new(size_t size, void *orig)
{
    struct rtw89_glue_dma *d;

    d = kzalloc(sizeof(*d), GFP_KERNEL);
    if (!d)
        return NULL;

    d->virt = glue.plat.dma_alloc(glue.plat.ctx, size, &d->bus, &d->cookie);
    if (!d->virt) {
        kfree(d);
        return NULL;
    }
    d->size = size;
    d->orig = orig;

    spin_lock(&glue.dma_lock);
    hlist_add_head(&d->node, glue_dma_bucket(d->bus));
    glue.dma_count++;
    spin_unlock(&glue.dma_lock);

    return d;
}

/* Look a mapping up by bus address; unlink it if @remove. */
static struct rtw89_glue_dma *glue_dma_find(u64 bus, bool remove)
{
    struct rtw89_glue_dma *d, *found = NULL;

    spin_lock(&glue.dma_lock);
    hlist_for_each_entry(d, glue_dma_bucket(bus), node) {
        if (d->bus == bus) {
            found = d;
            break;
        }
    }
    if (found && remove) {
        hlist_del_init(&found->node);
        glue.dma_count--;
    }
    spin_unlock(&glue.dma_lock);

    return found;
}

static void glue_dma_release(struct rtw89_glue_dma *d)
{
    glue.plat.dma_free(glue.plat.ctx, d->cookie);
    kfree(d);
}

static void *glue_dma_alloc_coherent(struct device *dev, size_t size,
                                     dma_addr_t *dma_handle, gfp_t flag)
{
    struct rtw89_glue_dma *d = glue_dma_new(size, NULL);

    if (!d)
        return NULL;
    memset(d->virt, 0, size);
    *dma_handle = (dma_addr_t)d->bus;
    return d->virt;
}

static void glue_dma_free_coherent(struct device *dev, size_t size,
                                   void *cpu_addr, dma_addr_t dma_handle)
{
    struct rtw89_glue_dma *d;

    /* Like Linux: freeing nothing is fine (rtw89 does it for rings it never
     * allocated, e.g. the firmware-command channel has no WD ring). */
    if (!cpu_addr)
        return;

    d = glue_dma_find(dma_handle, true);
    if (WARN_ON(!d))
        return;
    glue_dma_release(d);
}

static dma_addr_t glue_dma_map_single(struct device *dev, void *ptr,
                                      size_t size, int dir)
{
    struct rtw89_glue_dma *d;

    if (!ptr || !size)
        return 0;   /* dma_mapping_error() treats 0 as failure */

    d = glue_dma_new(size, ptr);
    if (!d)
        return 0;
    if (dir != DMA_FROM_DEVICE)
        memcpy(d->virt, ptr, size);
    return (dma_addr_t)d->bus;
}

static void glue_dma_unmap_single(struct device *dev, dma_addr_t addr,
                                  size_t size, int dir)
{
    struct rtw89_glue_dma *d = glue_dma_find(addr, true);

    if (WARN_ON(!d))
        return;
    if (dir != DMA_TO_DEVICE && d->orig)
        memcpy(d->orig, d->virt, min(size, d->size));
    glue_dma_release(d);
}

static void glue_dma_sync_for_cpu(struct device *dev, dma_addr_t addr,
                                  size_t size, int dir)
{
    struct rtw89_glue_dma *d = glue_dma_find(addr, false);

    if (d && d->orig && dir != DMA_TO_DEVICE)
        memcpy(d->orig, d->virt, min(size, d->size));
}

static void glue_dma_sync_for_device(struct device *dev, dma_addr_t addr,
                                     size_t size, int dir)
{
    struct rtw89_glue_dma *d = glue_dma_find(addr, false);

    if (d && d->orig && dir != DMA_FROM_DEVICE)
        memcpy(d->virt, d->orig, min(size, d->size));
}

static struct rtw88_dma_alloc_ops glue_dma_ops = {
    .alloc_coherent         = glue_dma_alloc_coherent,
    .free_coherent          = glue_dma_free_coherent,
    .map_single             = glue_dma_map_single,
    .unmap_single           = glue_dma_unmap_single,
    .sync_single_for_cpu    = glue_dma_sync_for_cpu,
    .sync_single_for_device = glue_dma_sync_for_device,
};

/* Free what the driver left mapped; returns how many there were. */
static unsigned int glue_dma_reap(void)
{
    struct rtw89_glue_dma *d;
    unsigned int n = 0;
    int i;

    for (i = 0; i < RTW89_GLUE_DMA_BUCKETS; i++) {
        for (;;) {
            spin_lock(&glue.dma_lock);
            d = hlist_empty(&glue.dma_hash[i]) ? NULL :
                container_of(glue.dma_hash[i].first, struct rtw89_glue_dma, node);
            if (d) {
                hlist_del_init(&d->node);
                glue.dma_count--;
            }
            spin_unlock(&glue.dma_lock);
            if (!d)
                break;
            glue_dma_release(d);
            n++;
        }
    }
    return n;
}

/* ------------------------------------------------------------------ */
/*  Probe / remove                                                      */
/* ------------------------------------------------------------------ */

/* The PCI front ends built in (module_pci_driver() in rtw89_compat.h). */
#define GLUE_PCI_DRIVERS(x) \
    x(rtw89_8851be_driver) x(rtw89_8852ae_driver) x(rtw89_8852be_driver) \
    x(rtw89_8852bte_driver) x(rtw89_8852ce_driver) x(rtw89_8922ae_driver) \
    x(rtw89_8922de_driver)
#define GLUE_DECLARE(d) struct pci_driver *rtw89_compat_pci_##d(void);
#define GLUE_ENTRY(d) rtw89_compat_pci_##d,
GLUE_PCI_DRIVERS(GLUE_DECLARE)
static struct pci_driver *(*const glue_pci_drivers[])(void) = {
    GLUE_PCI_DRIVERS(GLUE_ENTRY)
};

/* The front end for this device and its id_table entry, or NULL. */
static const struct pci_device_id *glue_match(uint16_t vendor, uint16_t device,
                                              struct pci_driver **drv)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(glue_pci_drivers); i++) {
        struct pci_driver *d = glue_pci_drivers[i]();
        const struct pci_device_id *id = d->id_table;

        for (; id->vendor; id++) {
            if (id->vendor == vendor && id->device == device) {
                if (drv)
                    *drv = d;
                return id;
            }
        }
    }
    return NULL;
}

bool rtw89_glue_supports(uint16_t vendor, uint16_t device)
{
    return glue_match(vendor, device, NULL) != NULL;
}

static void glue_teardown(void)
{
    unsigned int leaked;

#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    owly_peer_drain_rx();
    if(glue.awdl_rx_wq)destroy_workqueue(glue.awdl_rx_wq);
    owly_peer_fini();
#endif
    /* while the work queue machinery is still there */
    if (glue.rejoin_wq) {
        destroy_workqueue(glue.rejoin_wq);
    }
    rtw88_compat_exit();

    kfree(glue.scan_req);
    spin_lock_destroy(&glue.bss_lock);
    mutex_destroy(&glue.cmd_lock);

    leaked = glue_dma_reap();
    if (leaked)
        IOLog("[rtw89] released %u DMA mapping(s) the driver left behind\n", leaked);
    spin_lock_destroy(&glue.dma_lock);

    rtw88_pci_io_ops = NULL;
    rtw88_dma_ops = NULL;
    memset(&glue, 0, sizeof(glue));
}

int rtw89_glue_probe(const struct rtw89_glue_platform *platform,
                     const struct rtw89_glue_device *device)
{
    const struct pci_device_id *id;
    struct pci_driver *drv;
    int ret, i;

    if (glue.active)
        return -EBUSY;
    if (!platform->cfg_read || !platform->cfg_write || !platform->dma_alloc ||
        !platform->dma_free || !device->mmio_base || !device->mmio_len)
        return -EINVAL;

    id = glue_match(device->vendor, device->device, &drv);
    if (!id)
        return -ENODEV;

    ret = rtw88_compat_init();
    if (ret)
        return ret;
    rtw89_compat_debug_init();

    memset(&glue, 0, sizeof(glue));
    glue.active = true;
    glue.plat = *platform;
    glue.drv = drv;
    spin_lock_init(&glue.dma_lock);
    spin_lock_init(&glue.bss_lock);
    mutex_init(&glue.cmd_lock);
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
    memset(&owly_radio_state, 0, sizeof(owly_radio_state));
    wiphy_work_init(&owly_radio_work, owly_radio_work_run);
#if defined(OWLY_AWDL_SOFTWARE_SYNC) && OWLY_AWDL_SOFTWARE_SYNC
    owly_sync_reset(&owly_sync_state);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    spin_lock_init(&owly_link_lock);
    owly_peer_init();
    owly_link_reset(&owly_link_state);
#endif
    __atomic_store_n(&owly_cfg_rssi_floor,-128,__ATOMIC_RELEASE);
    __atomic_store_n(&owly_cfg_rssi_drops,0u,__ATOMIC_RELAXED);
    wiphy_delayed_work_init(&owly_sync_work, owly_sync_work_run);
#ifdef OWLY_MC_BUILT
    memset(&owly_mc, 0, sizeof(owly_mc));
    {
        char flag[8];
        owly_mc.off = PE_parse_boot_argn("-owlynomc", flag, sizeof(flag));
    }
    wiphy_delayed_work_init(&owly_mc_work, owly_mc_work_run);
#endif
#endif
#endif
    INIT_DELAYED_WORK(&glue.rejoin_work, glue_rejoin_work);
    glue.rejoin_wq = alloc_ordered_workqueue("rtw89_rejoin", 0);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    glue.awdl_rx_wq=alloc_ordered_workqueue("owly_awdl_rx",0);
#endif
    for (i = 0; i < RTW89_GLUE_DMA_BUCKETS; i++)
        INIT_HLIST_HEAD(&glue.dma_hash[i]);

    glue.pdev.vendor = device->vendor;
    glue.pdev.device = device->device;
    glue.pdev.subsystem_vendor = device->subsystem_vendor;
    glue.pdev.subsystem_device = device->subsystem_device;
    glue.pdev.revision = device->revision;
    glue.pdev.dev.name = glue.drv->name;
    /* rtw89 uses BAR 2 on every PCIe chip (rtw89_pci_setup_mapping). */
    glue.pdev.resource[2] = (resource_size_t)(uintptr_t)device->mmio_base;
    glue.pdev.resource_len[2] = device->mmio_len;

    rtw88_pci_io_ops = &glue_pci_ops;
    rtw88_dma_ops = &glue_dma_ops;

    ret = glue.drv->probe(&glue.pdev, id);
    if (ret) {
        glue_teardown();
        return ret;
    }

    rtw89_data_init(glue_hw(), glue_deliver, glue_tx_wake);
    glue.probed = true;
    return 0;
}

void rtw89_glue_remove(void)
{
    if (!glue.active)
        return;

    rtw89_glue_down();

    if (glue.probed) {
        glue.probed = false;
        rtw89_data_exit();
        glue.drv->remove(&glue.pdev);
    }
    glue_teardown();
}

static u64 glue_now_us(void)
{
    return ktime_get_boottime_ns() / 1000;
}

void rtw89_glue_interrupt(void)
{
    if (!glue.probed)
        return;
    glue.irq_time[glue.irq_next++ % ARRAY_SIZE(glue.irq_time)] = glue_now_us();
    rtw88_trigger_interrupt();
}

/* The datapath thread, RTW89_GLUE_PPDU_WAIT after a poll left frames parked. */
static void glue_ppdu_flush_work(struct work_struct *work)
{
    if (glue.up && glue.ppdu_flush)
        glue.ppdu_flushed += rtw89_compat_flush_ppdu_rx(glue_hw()->priv);
}

/* The datapath thread, after every NAPI poll. */
static void glue_napi_post_poll(int done)
{
    struct rtw89_dev *rtwdev;

    if (!glue.up || !glue.ppdu_flush)
        return;
    rtwdev = glue_hw()->priv;
    if (!skb_queue_empty(&rtwdev->ppdu_sts.rx_queue[RTW89_PHY_0]))
        rtw88_queue_datapath_delayed_work(&glue.ppdu_flush_work, RTW89_GLUE_PPDU_WAIT);
}

void rtw89_glue_set_ppdu_flush(bool on)
{
    glue.ppdu_flush = on;
}

void rtw89_glue_set_ax(bool on)
{
    rtw89_mlme_set_he(on);
}

void rtw89_glue_set_country(const char *alpha2)
{
    struct ieee80211_hw *hw;
    char cc[2];
    int i;

    if (!glue.probed || !alpha2)
        return;
    for (i = 0; i < 2; i++)
        cc[i] = alpha2[i] >= 'a' && alpha2[i] <= 'z' ? (char)(alpha2[i] - 'a' + 'A') : alpha2[i];
    hw = glue_hw();
    wiphy_lock(hw->wiphy);
    rtw89_cfg80211_set_country(hw->wiphy, cc);
    wiphy_unlock(hw->wiphy);
}

/*
 * Remember how a frame was sent to us: mode, rate index, streams, width and
 * guard interval in one word, so that readers on other threads never see half
 * of an update. glue_rate_info() turns it back.
 */
static void glue_rx_rate(const struct ieee80211_rx_status *status)
{
    glue.rx_rate = BIT(31) | (u32)status->encoding | (u32)status->rate_idx << 4 |
                   (u32)status->nss << 12 | (u32)status->bw << 16 | (u32)status->he_gi << 20 |
                   (status->enc_flags & RX_ENC_FLAG_SHORT_GI ? BIT(22) : 0) |
                   (u32)status->band << 24;
}

/* sta_set_rate_info_rx() */
static bool glue_rate_info(u32 word, struct rate_info *ri)
{
    struct ieee80211_supported_band *sband;
    unsigned int idx = (word >> 4) & 0xff;

    memset(ri, 0, sizeof(*ri));
    if (!(word & BIT(31)))
        return false;
    ri->bw = (word >> 16) & 0xf;
    ri->nss = (word >> 12) & 0xf;
    switch (word & 0xf) {
    case RX_ENC_HE:
        ri->flags = RATE_INFO_FLAGS_HE_MCS;
        ri->mcs = (u8)idx;
        ri->he_gi = (word >> 20) & 3;
        break;
    case RX_ENC_VHT:
        ri->flags = RATE_INFO_FLAGS_VHT_MCS;
        ri->mcs = (u8)idx;
        break;
    case RX_ENC_HT:
        ri->flags = RATE_INFO_FLAGS_MCS;
        ri->mcs = (u8)idx;
        break;
    default:
        sband = glue_hw()->wiphy->bands[(word >> 24) & 0xf];
        if (!sband || idx >= (unsigned int)sband->n_bitrates)
            return false;
        ri->legacy = sband->bitrates[idx].bitrate;
        break;
    }
    if (word & BIT(22))
        ri->flags |= RATE_INFO_FLAGS_SHORT_GI;
    return true;
}

/* A rate for the outside: 802.11 mode, index, streams, width and the bit rate. */
static void glue_rate_describe(const struct rate_info *ri, struct rtw89_glue_rate *out)
{
    static const u16 mhz[] = {
        [RATE_INFO_BW_20] = 20, [RATE_INFO_BW_40] = 40, [RATE_INFO_BW_80] = 80,
        [RATE_INFO_BW_160] = 160, [RATE_INFO_BW_320] = 320,
    };

    memset(out, 0, sizeof(*out));
    out->kbps = cfg80211_calculate_bitrate((struct rate_info *)ri) * 100;
    if (!out->kbps)
        return;
    out->mode = ri->flags & RATE_INFO_FLAGS_EHT_MCS ? 4 : ri->flags & RATE_INFO_FLAGS_HE_MCS ? 3 : ri->flags & RATE_INFO_FLAGS_VHT_MCS ? 2 :
                ri->flags & RATE_INFO_FLAGS_MCS ? 1 : 0;
    out->mcs = out->mode ? ri->mcs : 0;
    /* 802.11n numbers its rates through the streams: 8 to a stream */
    out->nss = out->mode == 1 ? (u8)(ri->mcs / 8 + 1) : out->mode ? ri->nss : 1;
    out->width = ri->bw < ARRAY_SIZE(mhz) && mhz[ri->bw] ? mhz[ri->bw] : 20;
}

/* Measure how late a frame is, by the chip's own receive timestamp. */
static void glue_rx_timing(const struct ieee80211_rx_status *status)
{
    u64 now = glue_now_us();
    u32 offset = (u32)now - (u32)status->mactime;
    u32 base;
    s32 late;

    /* a new window every five seconds */
    if (now - glue.rx_base_since > 5000000) {
        glue.rx_base_prev = glue.rx_base;
        glue.rx_base_prev_valid = glue.rx_base_valid;
        glue.rx_base_valid = false;
        glue.rx_base_since = now;
    }
    if (!glue.rx_base_valid || (s32)(offset - glue.rx_base) < 0) {
        glue.rx_base = offset;
        glue.rx_base_valid = true;
    }
    base = glue.rx_base;
    if (glue.rx_base_prev_valid && (s32)(glue.rx_base_prev - base) < 0)
        base = glue.rx_base_prev;

    late = (s32)(offset - base);
    if (late > RTW89_GLUE_LATE_US) {
        u64 arrived = now - (u32)late;
        unsigned int i;

        glue.rx_late++;
        if ((u32)late / 1000 > glue.rx_late_max)
            glue.rx_late_max = (u32)late / 1000;
        /* did the chip interrupt us when it arrived? then it was read from
         * the ring at once and waited inside the driver */
        for (i = 0; i < ARRAY_SIZE(glue.irq_time); i++) {
            if (glue.irq_time[i] + 1000 >= arrived && glue.irq_time[i] <= arrived + 3000) {
                glue.rx_late_irq++;
                break;
            }
        }
    }
}

/*
 * A frame's hardware arrival time, in the clock the rest of the driver keeps.
 *
 * The chip stamps a frame when it arrives; the driver sees it some
 * milliseconds later, and how many varies. Timing the master's availability
 * window from the software arrival produced corrections scattered right
 * across a 16 ms window -- 12961 us, then 340, then 14794 -- which is the
 * processing delay and nothing else.
 *
 * glue_rx_timing() already keeps what is needed: the smallest offset between
 * local time and the chip's clock seen in the last few seconds, which is the
 * one with the least software delay in it and so the best estimate of the
 * difference between the two clocks.
 */
bool rtw89_glue_rx_local_us(u64 mactime, u64 *local_us)
{
    u32 base;

    if (!glue.rx_base_valid && !glue.rx_base_prev_valid)
        return false;
    base = glue.rx_base_valid ? glue.rx_base : glue.rx_base_prev;
    if (glue.rx_base_valid && glue.rx_base_prev_valid &&
        (s32)(glue.rx_base_prev - base) < 0)
        base = glue.rx_base_prev;
    if (local_us)
        *local_us = mactime + base;
    return true;
}

bool rtw89_glue_get_info(struct rtw89_glue_info *info)
{
    struct ieee80211_hw *hw;
    struct rtw89_dev *rtwdev;
    struct rtw89_fw_suit *suit;

    if (!glue.probed)
        return false;

    hw = pci_get_drvdata(&glue.pdev);
    rtwdev = hw->priv;
    suit = rtw89_fw_suit_get(rtwdev, RTW89_FW_NORMAL);

    memset(info, 0, sizeof(*info));
    memcpy(info->mac, hw->wiphy->perm_addr, ETH_ALEN);
    snprintf(info->fw_version, sizeof(info->fw_version), "%u.%u.%u.%u",
             suit->major_ver, suit->minor_ver, suit->sub_ver, suit->sub_idex);
    info->fw_commit = suit->commitid;
    info->chip_cut = rtwdev->hal.cv;
    info->rfe_type = rtwdev->efuse.rfe_type;
    info->tx_streams = rtwdev->hal.tx_nss;
    info->rx_streams = rtwdev->hal.rx_nss;
    return true;
}

size_t rtw89_glue_coex_info(char *buf, size_t max)
{
    struct ieee80211_hw *hw;
    ssize_t n;

    if (!glue.probed || !max)
        return 0;
    hw = pci_get_drvdata(&glue.pdev);
    wiphy_lock(hw->wiphy);
    n = rtw89_btc_dump_info(hw->priv, buf, max);
    wiphy_unlock(hw->wiphy);
    return n > 0 ? (size_t)n : 0;
}

/* ------------------------------------------------------------------ */
/*  Upcalls from the mac80211 stand-in                                  */
/* ------------------------------------------------------------------ */

static struct ieee80211_hw *glue_hw(void)
{
    return pci_get_drvdata(&glue.pdev);
}

#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
#include "owly_awdl_peer.inc"
#endif

/*
 * Remember a network from a beacon or probe response. Non-static so the smoke
 * test can feed it frames; everything else reaches it through glue_rx().
 */
void rtw89_glue_note_bss(const u8 *frame, size_t len, u16 freq, s8 signal);
void rtw89_glue_note_bss(const u8 *frame, size_t len, u16 freq, s8 signal)
{
    const struct ieee80211_mgmt *mgmt = (const void *)frame;
    const size_t fixed = offsetof(struct ieee80211_mgmt, u.beacon.variable);
    struct rtw89_glue_bss_entry *e = NULL;
    const struct element *ssid;
    bool has_ssid;
    unsigned int i;

    if (len < fixed)
        return;
    if (!ieee80211_is_beacon(mgmt->frame_control) &&
        !ieee80211_is_probe_resp(mgmt->frame_control))
        return;

    ssid = cfg80211_find_elem(WLAN_EID_SSID, frame + fixed, len - fixed);
    /* A hidden network beacons an empty or all-zero SSID. */
    has_ssid = ssid && ssid->datalen && ssid->datalen <= IEEE80211_MAX_SSID_LEN &&
               ssid->data[0];

    spin_lock(&glue.bss_lock);
    for (i = 0; i < glue.n_bss; i++) {
        if (ether_addr_equal(glue.bss[i].pub.bssid, mgmt->bssid)) {
            e = &glue.bss[i];
            break;
        }
    }
    if (!e) {
        if (glue.n_bss < RTW89_GLUE_MAX_BSS) {
            e = &glue.bss[glue.n_bss++];
        } else {
            /* full: the one heard least recently makes room */
            e = &glue.bss[0];
            for (i = 1; i < glue.n_bss; i++)
                if (time_before(glue.bss[i].last_seen, e->last_seen))
                    e = &glue.bss[i];
        }
        memset(e, 0, sizeof(*e));
        memcpy(e->pub.bssid, mgmt->bssid, ETH_ALEN);
        e->pub.signal = signal;
        e->scan_gen = glue.scan_gen;
    }
    if (e) {
        if (has_ssid) {
            e->pub.ssid_len = ssid->datalen;
            memcpy(e->pub.ssid, ssid->data, ssid->datalen);
            e->pub.ssid[ssid->datalen] = 0;
        }
        /* Keep the elements of a frame that names the network, if any did. */
        if ((has_ssid || !e->pub.ssid_len) && len - fixed <= RTW89_GLUE_MAX_IES) {
            e->ies_len = (u16)(len - fixed);
            memcpy(e->ies, frame + fixed, len - fixed);
            e->beacon_int = le16_to_cpu(mgmt->u.beacon.beacon_int);
            e->pub.capability = le16_to_cpu(mgmt->u.beacon.capab_info);
            glue_bss_describe(e);
        }
        e->pub.freq = freq;
        e->pub.channel = (u8)ieee80211_frequency_to_channel(freq);
        /* the newest signal at the first frame of each scan, the strongest
         * after that: the list outlives scans, a best-ever value would not
         * follow the machine moving away */
        if (e->scan_gen != glue.scan_gen || signal > e->pub.signal)
            e->pub.signal = signal;
        e->scan_gen = glue.scan_gen;
        e->last_seen = jiffies;
        e->pub.seen++;
    }
    spin_unlock(&glue.bss_lock);
}

/*
 * Whether a scan visits @chan: every channel that is allowed, but on 6 GHz the
 * 15 preferred scanning channels only (every fourth 20 MHz channel: 5, 21,
 * ..., 229). Access points there are expected on them, macOS shows networks
 * found elsewhere only when a 2.4/5 GHz neighbour report points to them, and
 * listening on all 59 would add seconds to each scan.
 */
static bool glue_scan_channel(const struct ieee80211_channel *chan)
{
    if (chan->flags & IEEE80211_CHAN_DISABLED)
        return false;
    return chan->band != NL80211_BAND_6GHZ || chan->hw_value % 16 == 5;
}

/* Mode, width and security of a network, from its elements. */
static void glue_bss_describe(struct rtw89_glue_bss_entry *e)
{
    const struct element *elem;
    const u8 *p, *end;
    u16 count;

    e->pub.mode = 0;
    e->pub.width = 20;
    e->pub.security = e->pub.capability & WLAN_CAPABILITY_PRIVACY ? RTW89_GLUE_SEC_WEP_WPA1 : 0;

    elem = cfg80211_find_elem(WLAN_EID_HT_OPERATION, e->ies, e->ies_len);
    if (elem && elem->datalen >= sizeof(struct ieee80211_ht_operation) &&
        cfg80211_find_elem(WLAN_EID_HT_CAPABILITY, e->ies, e->ies_len)) {
        e->pub.mode = 1;
        if (elem->data[1] & IEEE80211_HT_PARAM_CHA_SEC_OFFSET)
            e->pub.width = 40;
    }
    elem = cfg80211_find_elem(WLAN_EID_VHT_OPERATION, e->ies, e->ies_len);
    if (e->pub.mode && elem && elem->datalen >= sizeof(struct ieee80211_vht_operation) &&
        cfg80211_find_elem(WLAN_EID_VHT_CAPABILITY, e->ies, e->ies_len)) {
        const struct ieee80211_vht_operation *oper = (const void *)elem->data;

        e->pub.mode = 2;
        if (oper->chan_width == IEEE80211_VHT_CHANWIDTH_80MHZ)
            /* a second centre eight channels away means 160 MHz */
            e->pub.width = oper->center_freq_seg1_idx &&
                           abs(oper->center_freq_seg1_idx - oper->center_freq_seg0_idx) == 8 ?
                           160 : 80;
        else if (oper->chan_width == IEEE80211_VHT_CHANWIDTH_160MHZ)
            e->pub.width = 160;
    }
    if (cfg80211_find_ext_elem(WLAN_EID_EXT_HE_CAPABILITY, e->ies, e->ies_len)) {
        const struct ieee80211_he_6ghz_oper *op6 = NULL;

        e->pub.mode = 3;
        /* 6 GHz has no HT or VHT: the width is in the HE operation element */
        elem = cfg80211_find_ext_elem(WLAN_EID_EXT_HE_OPERATION, e->ies, e->ies_len);
        if (elem && elem->datalen >= 1 + sizeof(struct ieee80211_he_operation) &&
            elem->datalen >= ieee80211_he_oper_size(elem->data + 1))
            op6 = ieee80211_he_6ghz_oper((const void *)(elem->data + 1));
        if (op6) {
            static const u8 widths[] = { 20, 40, 80, 160 };

            e->pub.width = widths[op6->control & IEEE80211_HE_6GHZ_OPER_CTRL_CHANWIDTH];
        }
        if (cfg80211_find_ext_elem(WLAN_EID_EXT_EHT_CAPABILITY, e->ies, e->ies_len))
            e->pub.mode = 4;
    }

    /* RSN: version, group cipher, pairwise list, AKM list, capabilities */
    elem = cfg80211_find_elem(WLAN_EID_RSN, e->ies, e->ies_len);
    if (!elem)
        return;
    e->pub.security = 0;
    p = elem->data;
    end = p + elem->datalen;
    if (end - p < 8)
        return;
    p += 6;
    count = get_unaligned_le16(p);
    p += 2;
    if (end - p < count * 4 + 2)
        return;
    p += count * 4;
    count = get_unaligned_le16(p);
    p += 2;
    if (end - p < count * 4)
        return;
    for (; count; count--, p += 4) {
        if (p[0] != 0x00 || p[1] != 0x0f || p[2] != 0xac)
            continue;
        switch (p[3]) {
        case 2: case 4: case 6:             /* PSK, FT-PSK, PSK-SHA256 */
            e->pub.security |= RTW89_GLUE_SEC_WPA2_PSK;
            break;
        case 8: case 9: case 24: case 25:   /* SAE and its variants */
            e->pub.security |= RTW89_GLUE_SEC_WPA3_SAE;
            break;
        default:
            e->pub.security |= RTW89_GLUE_SEC_ENTERPRISE;
            break;
        }
    }
    if (end - p >= 2 && (get_unaligned_le16(p) & BIT(6)))
        e->pub.security |= RTW89_GLUE_SEC_PMF_REQUIRED;
}

/* ABI6 bridge into platform callbacks. Never assume that passing a frame
 * here makes the peer authenticated or makes awdl0 receive the packet. */
#if defined(OWLY_ABI6_RX_DEMUX) && OWLY_ABI6_RX_DEMUX
static bool owly_abi6_action_to_platform(void *opaque, const uint8_t source[6],
                                         const struct owly_action_info *decoded,
                                         const uint8_t *raw, size_t raw_len)
{
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    const struct owly_native_rx_meta *meta=opaque;bool admitted;
    if(!meta || !glue.plat.native_rx)return false;
    spin_lock(&owly_link_lock);
    admitted=owly_link_observe(&owly_link_state,raw,raw_len,meta->channel,meta->rssi,meta->received_us);
    spin_unlock(&owly_link_lock);
    if(!admitted) {
        static volatile unsigned long rejected_samples;
        const unsigned long count=__sync_add_and_fetch(&rejected_samples,1ul);
        if(count<=8ul || (count&(count-1ul))==0ul)
            IOLog("OWLY native action rejected: count=%lu ch=%u rssi=%d "
                  "bytes=%lu complete=%u period_tu=%u master_ch=%u "
                  "(NO APPLE DELIVERY)\n",count,(unsigned)meta->channel,
                  (int)meta->rssi,(unsigned long)raw_len,(unsigned)decoded->complete,
                  (unsigned)decoded->aw_period_tu,(unsigned)decoded->master_channel);
        return false;
    }
    return glue.plat.native_rx(glue.plat.ctx,1,raw,raw_len,source,raw+4,
                               meta->channel,meta->rssi,meta->received_us);
#else
    (void)opaque;
    if (!glue.plat.awdl_rx_action) return false;
    return glue.plat.awdl_rx_action(glue.plat.ctx, source, decoded->subtype,
                                   decoded->social_mask, raw, raw_len);
#endif
}
static bool owly_abi6_ipv6_to_platform(void *opaque, const uint8_t da[6],
                                       const uint8_t sa[6], const uint8_t *ip6,
                                       size_t len)
{
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    struct owly_native_rx_meta *meta=opaque;
    if(!meta)return false;
    spin_lock(&owly_link_lock);
    const enum owly_link_ipv6_result result=
        owly_link_admit_ipv6(&owly_link_state,sa,da,ip6,len,meta->received_us);
    spin_unlock(&owly_link_lock);
    ++meta->ipv6_results[result];
    if(result!=OWLY_LINK_IPV6_ACCEPTED) {
#if defined(RTW89_MACOS)
        if(!(da[0]&1u))owly_unicast_note(2,ip6,len,result,false);
#endif
        return false;
    }
    const bool submitted=glue.plat.native_rx &&
        glue.plat.native_rx(glue.plat.ctx,2,ip6,len,sa,da,
                           meta->channel,meta->rssi,meta->received_us);
    if(!submitted)++meta->ipv6_front_refused;
#if defined(RTW89_MACOS)
    if(!(da[0]&1u))owly_unicast_note(2,ip6,len,result,submitted);
#endif
    return submitted;
#else
    (void)opaque;
    if (!glue.plat.awdl_rx_ipv6) return false;
    return glue.plat.awdl_rx_ipv6(glue.plat.ctx, da, sa, ip6, len);
#endif
}
#endif

#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
/* Own an AWDL skb, after optional per-peer reordering. */
static void owly_awdl_deliver_rx(struct sk_buff *skb)
{
    struct ieee80211_rx_status *status=IEEE80211_SKB_RXCB(skb);
    const size_t len=skb->len;
    if((status->flag&(RX_FLAG_FAILED_FCS_CRC|RX_FLAG_NO_PSDU)) || len<28u) {kfree_skb(skb);return;}
    /* Keep MLME status queries off the 100k+ frames/sec ordinary STA path;
     * only the fixed AWDL BSSID is worth a more expensive decode. */
    if (owly_scc_aux_ready && !glue.scanning &&
        len >= 24u + FCS_LEN &&
        skb->data[16] == 0x00 && skb->data[17] == 0x25 &&
        skb->data[18] == 0x00 && skb->data[19] == 0xff &&
        skb->data[20] == 0x94 && skb->data[21] == 0x73) {
#if defined(OWLY_AWDL_SOFTWARE_SYNC) && OWLY_AWDL_SOFTWARE_SYNC
        /* Discovery policy applies only to actual AWDL action candidates.
         * Ordinary station traffic, C3 scan observation and IPv6 are intact. */
        if (skb->data[0]==0xd0u &&
            !owly_config_rx_allowed(__atomic_load_n(&owly_cfg_rssi_floor,__ATOMIC_ACQUIRE),
                                    status->signal)) {
            __atomic_fetch_add(&owly_cfg_rssi_drops,1u,__ATOMIC_RELAXED);
            kfree_skb(skb);
            return;
        }
#endif
        struct rtw89_mlme_status st;
        struct owly_abi6_rx_context state;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        struct owly_native_rx_meta meta={0};
#endif
        const struct owly_abi6_rx_sinks handlers = {
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
            .ctx = &meta,
#else
            .ctx = NULL,
#endif
            .action = owly_abi6_action_to_platform,
            .ipv6 = owly_abi6_ipv6_to_platform,
        };
        struct owly_abi6_rx_result result;
        rtw89_mlme_get_status(&st);
#ifdef OWLY_MC_BUILT
        /* Visiting ch 6 for multichannel AWDL: judge the frame against the
         * social channel we are on, not the AP's. */
        if (owly_mc.enabled && status->freq == owly_mc_freq(owly_mc.channel)) {
            st.freq = status->freq;
            st.center_freq = status->freq;
            st.width = 20;
        }
#endif
        state.rx_freq_mhz = (unsigned int)status->freq;
        state.sta_freq_mhz = (unsigned int)st.freq;
        state.sta_center_freq_mhz = (unsigned int)st.center_freq;
        state.sta_width_mhz = (unsigned int)st.width;
        state.crc_ok = true; /* CRC and NO_PSDU rejected above */
        state.sta_connected = (st.state == RTW89_MLME_CONNECTED);
        state.standalone_channel = st.awdl_channel_owned;
        state.aux_present = owly_scc_aux_ready;
        state.scanning = glue.scanning;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        meta.channel=(uint8_t)(st.freq==2437 ? 6 : st.freq==5220 ? 44 : st.freq==5745 ? 149 : 0);
        meta.rssi=status->signal;
        meta.received_us=status->boottime_ns ? status->boottime_ns/1000u : glue_now_us();
#endif
        result = owly_abi6_demux((const uint8_t *)skb->data,
                                 len - FCS_LEN, &state, &handlers);
        if (result.kind == OWLY_ABI6_RX_IPV6) {
            static volatile unsigned long ipv6_demux_samples;
            const unsigned long count = __sync_add_and_fetch(&ipv6_demux_samples,1ul);
            if (count <= 12u || !(count & (count-1u))) {
                IOLog("OWLY IPv6 demux: count=%lu valid=%u admitted_to_front=%u\n",
                      count,result.valid_units,result.sink_accepted);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
                IOLog("OWLY IPv6 decisions: count=%lu inactive=%u no_peer=%u "
                      "wrong_destination=%u invalid=%u front_refused=%u\n",count,
                      meta.ipv6_results[OWLY_LINK_IPV6_INACTIVE],
                      meta.ipv6_results[OWLY_LINK_IPV6_NO_PEER],
                      meta.ipv6_results[OWLY_LINK_IPV6_BAD_DEST],
                      meta.ipv6_results[OWLY_LINK_IPV6_INVALID],meta.ipv6_front_refused);
#endif
            }
        }
        if (result.consumed) {
            /* Any accepted AWDL unit bypasses STA; partial A-MSDU cannot be double-routed. */
            kfree_skb(skb);
            return;
        }
        /* There is intentionally NO fallback to a fake native awdl0 sink. */
    }
    kfree_skb(skb);
}
#endif

/* Every received frame lands here, on the driver's receive thread. */
static void glue_rx(void *ctx, struct ieee80211_sta *sta, struct sk_buff *skb)
{
    struct ieee80211_rx_status *status = IEEE80211_SKB_RXCB(skb);
    const struct ieee80211_hdr *hdr = (const void *)skb->data;
    size_t len = skb->len;

    if ((status->flag & (RX_FLAG_FAILED_FCS_CRC | RX_FLAG_NO_PSDU)) || len < 2 + FCS_LEN) {
        kfree_skb(skb);
        return;
    }
#if defined(RTW89_MACOS) && defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    const uint64_t host_received_us=glue_now_us();
    const uint64_t radio_received_us=owly_radio_rx_time(&owly_radio_rx_clock,
        host_received_us,(uint32_t)status->mactime,(status->flag&RX_FLAG_MACTIME)!=0);
    /* Keep the per-packet sample when BA/delivery work queues this skb. */
    if(len>=24u+FCS_LEN && !memcmp(skb->data+16,"\x00\x25\x00\xff\x94\x73",6)) {
        status->boottime_ns=radio_received_us*1000u;
        static unsigned long timing_samples;
        const unsigned long count=++timing_samples;
        if(count<=4ul || !(count&(count-1ul)))
            IOLog("OWLY radio RX time: count=%lu hardware=%u correction_us=%llu\n",count,
                (unsigned)((status->flag&RX_FLAG_MACTIME)!=0),
                (unsigned long long)(host_received_us-radio_received_us));
    }
    if(owly_observe_unicast_frame(skb->data,len-FCS_LEN)) {
        size_t size;const uint8_t *ip=owly_observe_frame_ip(skb->data,len-FCS_LEN,&size);
        owly_unicast_note(1,ip,size,0,false);
    }
#endif
    /* OWLY RX SHADOW: one synchronous, borrowed read of a CRC-good skb.
     * No skb ownership, retain, inputPacket, firmware operation or TX.
     * The original STA RX path below executes UNCHANGED. */
#if defined(OWLY_AWDL_RX_SHADOW) && OWLY_AWDL_RX_SHADOW
    {
        struct owly_shadow_event e;
        owly_shadow_note((const uint8_t *)skb->data, len - FCS_LEN, &e);
        if (e.kind == OWLY_SHADOW_IPV6 && (e.ipv6_frames <= 12u ||
            !(e.ipv6_frames & (e.ipv6_frames - 1u))))
            IOLog("OWLY IPv6 radio RX: count=%llu freq=%u scanning=%u\n",
                  (unsigned long long)e.ipv6_frames, (unsigned)status->freq,
                  (unsigned)glue.scanning);
        if (e.log_milestone)
            IOLog("OWLY RX shadow: total=%llu candidates=%llu action=%llu "
                  "ipv6=%llu msdu=%llu bad=%llu unsupported=%llu "
                  "kind=%u freq_mhz=%u (OBSERVED_NOT_ON_AWDL0)\n",
                  (unsigned long long)e.total,
                  (unsigned long long)e.candidates,
                  (unsigned long long)e.actions,
                  (unsigned long long)e.ipv6_frames,
                  (unsigned long long)e.ipv6_subframes,
                  (unsigned long long)e.bad_data,
                  (unsigned long long)e.unsupported,
                  e.kind, (unsigned int)status->freq);
    }
#endif
#if defined(OWLY_ABI6_C3_SCAN_OBSERVER) && OWLY_ABI6_C3_SCAN_OBSERVER
    /* Scan-safe OBSERVER, intentionally separate from C2 eligible().
     * It never frees skb, never returns early, never changes RX filtering,
     * channels, scan state, ownership or Apple inputPacket. Signature !=
     * complete TLVs; the frontend has a dedicated candidate packet kind. */
    if (len >= 31u + FCS_LEN &&
        skb->data[0] == 0xd0u &&
        (skb->data[1] & (0x01u|0x02u|0x40u)) == 0u &&
        skb->data[16] == 0u && skb->data[17] == 0x25u &&
        skb->data[18] == 0u && skb->data[19] == 0xffu &&
        skb->data[20] == 0x94u && skb->data[21] == 0x73u &&
        skb->data[24] == 127u && skb->data[25] == 0u &&
        skb->data[26] == 0x17u && skb->data[27] == 0xf2u &&
        skb->data[28] == 8u &&
        (skb->data[30] == 0u || skb->data[30] == 3u)) {
        static volatile unsigned long c3_signatures_seen = 0;
        const unsigned long count = __sync_add_and_fetch(&c3_signatures_seen, 1ul);
        const unsigned int freq = (unsigned int)status->freq;
        const bool scan = glue.scanning;
        const bool aux = owly_scc_aux_ready;
        const size_t payload_len = len - FCS_LEN;
        const enum owly_c3_scan_class cls = owly_c3_scan_classify(
            (const uint8_t *)skb->data, payload_len, freq, true, scan, aux);
        const bool callback_present = glue.plat.awdl_rx_scan_signature != NULL;
        /* No consumer ACK: this callback always returns false, even when the
         * frontend counted the frame. NEVER consume or double-route skb. */
        if (cls != OWLY_C3_SCAN_REJECT && callback_present)
            (void)glue.plat.awdl_rx_scan_signature(glue.plat.ctx,
                                                   (const uint8_t *)skb->data+10,
                                                   (const uint8_t *)skb->data,
                                                   payload_len);
        /* Rare candidate diagnostics, rate-limited to avoid RX-thread spam.
         * Reasons for rejection are visible (scan/aux/freq/size/class). */
        if (count <= 16ul || (count & (count - 1ul)) == 0ul)
            IOLog("OWLY C3 scan candidate: seen=%lu class=%u scan=%u aux=%u "
                  "freq_mhz=%u bytes=%lu callback=%u (NO APPLE RX/TX)\n",
                  count, (unsigned int)cls, (unsigned int)scan,
                  (unsigned int)aux, freq, (unsigned long)payload_len,
                  (unsigned int)callback_present);
    }
#endif
#if defined(OWLY_ABI6_RX_DEMUX) && OWLY_ABI6_RX_DEMUX
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    if(owly_peer_control_rx(skb))return;
    if(owly_scc_aux_ready && !glue.scanning && len>=28u &&
       !memcmp(skb->data+16,"\x00\x25\x00\xff\x94\x73",6)) {
        if(owly_peer_data_rx(skb))return;
        owly_awdl_deliver_rx(skb);return;
    }
#else
    /* Keep MLME status queries off the 100k+ frames/sec ordinary STA path;
     * only the fixed AWDL BSSID is worth a more expensive decode. */
    if (owly_scc_aux_ready && !glue.scanning &&
        len >= 24u + FCS_LEN &&
        skb->data[16] == 0x00 && skb->data[17] == 0x25 &&
        skb->data[18] == 0x00 && skb->data[19] == 0xff &&
        skb->data[20] == 0x94 && skb->data[21] == 0x73) {
#if defined(OWLY_AWDL_SOFTWARE_SYNC) && OWLY_AWDL_SOFTWARE_SYNC
        /* Discovery policy applies only to actual AWDL action candidates.
         * Ordinary station traffic, C3 scan observation and IPv6 are intact. */
        if (skb->data[0]==0xd0u &&
            !owly_config_rx_allowed(__atomic_load_n(&owly_cfg_rssi_floor,__ATOMIC_ACQUIRE),
                                    status->signal)) {
            __atomic_fetch_add(&owly_cfg_rssi_drops,1u,__ATOMIC_RELAXED);
            kfree_skb(skb);
            return;
        }
#endif
        struct rtw89_mlme_status st;
        struct owly_abi6_rx_context state;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        struct owly_native_rx_meta meta={0};
#endif
        const struct owly_abi6_rx_sinks handlers = {
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
            .ctx = &meta,
#else
            .ctx = NULL,
#endif
            .action = owly_abi6_action_to_platform,
            .ipv6 = owly_abi6_ipv6_to_platform,
        };
        struct owly_abi6_rx_result result;
        rtw89_mlme_get_status(&st);
#ifdef OWLY_MC_BUILT
        /* Visiting ch 6 for multichannel AWDL: judge the frame against the
         * social channel we are on, not the AP's. */
        if (owly_mc.enabled && status->freq == owly_mc_freq(owly_mc.channel)) {
            st.freq = status->freq;
            st.center_freq = status->freq;
            st.width = 20;
        }
#endif
        state.rx_freq_mhz = (unsigned int)status->freq;
        state.sta_freq_mhz = (unsigned int)st.freq;
        state.sta_center_freq_mhz = (unsigned int)st.center_freq;
        state.sta_width_mhz = (unsigned int)st.width;
        state.crc_ok = true; /* CRC and NO_PSDU rejected above */
        state.sta_connected = (st.state == RTW89_MLME_CONNECTED);
        state.standalone_channel = st.awdl_channel_owned;
        state.aux_present = owly_scc_aux_ready;
        state.scanning = glue.scanning;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        meta.channel=(uint8_t)(st.freq==2437 ? 6 : st.freq==5220 ? 44 : st.freq==5745 ? 149 : 0);
        meta.rssi=status->signal;
        meta.received_us=status->boottime_ns ? status->boottime_ns/1000u : glue_now_us();
#endif
        result = owly_abi6_demux((const uint8_t *)skb->data,
                                 len - FCS_LEN, &state, &handlers);
        if (result.kind == OWLY_ABI6_RX_IPV6) {
            static volatile unsigned long ipv6_demux_samples;
            const unsigned long count = __sync_add_and_fetch(&ipv6_demux_samples,1ul);
            if (count <= 12u || !(count & (count-1u))) {
                IOLog("OWLY IPv6 demux: count=%lu valid=%u admitted_to_front=%u\n",
                      count,result.valid_units,result.sink_accepted);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
                IOLog("OWLY IPv6 decisions: count=%lu inactive=%u no_peer=%u "
                      "wrong_destination=%u invalid=%u front_refused=%u\n",count,
                      meta.ipv6_results[OWLY_LINK_IPV6_INACTIVE],
                      meta.ipv6_results[OWLY_LINK_IPV6_NO_PEER],
                      meta.ipv6_results[OWLY_LINK_IPV6_BAD_DEST],
                      meta.ipv6_results[OWLY_LINK_IPV6_INVALID],meta.ipv6_front_refused);
#endif
            }
        }
        if (result.consumed) {
            /* Any accepted AWDL unit bypasses STA; partial A-MSDU cannot be double-routed. */
            kfree_skb(skb);
            return;
        }
        /* There is intentionally NO fallback to a fake native awdl0 sink. */
    }
#endif
#endif
    /* OWLY_PHASE_G_RX_HOOK: observes signature, never owns skb. */
    #if defined(RTW89_AWDL_RX_PROBE) && RTW89_AWDL_RX_PROBE
    rtw89_awdl_probe_note((const unsigned char *)skb->data, len - FCS_LEN, (unsigned int)status->freq);
    #endif

    /* the one control frame that matters: it moves a reorder window */
    if (ieee80211_is_back_req(hdr->frame_control)) {
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        if(owly_peer_bar_rx(skb))return;
#endif
        rtw89_data_rx_bar(skb);
        return;
    }
    if (ieee80211_is_ctl(hdr->frame_control) ||
        len < sizeof(struct ieee80211_hdr_3addr) + FCS_LEN) {
        kfree_skb(skb);
        return;
    }

    if (status->flag & RX_FLAG_MACTIME_START)
        glue_rx_timing(status);

    if (ieee80211_is_beacon(hdr->frame_control) ||
        ieee80211_is_probe_resp(hdr->frame_control)) {
        /* The driver leaves the FCS on (RX_INCLUDES_FCS). */
        rtw89_glue_note_bss(skb->data, len - FCS_LEN, status->freq, status->signal);
        /* our own AP's beacons are also the sign that it is still there */
        if (ieee80211_is_beacon(hdr->frame_control))
            rtw89_mlme_rx_beacon(skb);
        else
            kfree_skb(skb);
        return;
    }

    if (ieee80211_is_data(hdr->frame_control)) {
        if (!is_multicast_ether_addr(hdr->addr1))
            glue_rx_rate(status);
        rtw89_data_rx(skb);
        return;
    }

    /* Everything else is for the station MLME, which takes the skb. */
    rtw89_mlme_rx(skb);
}

/* A received Ethernet frame from the data path. */
static void glue_deliver(const u8 *frame, size_t len)
{
    if (glue.plat.rx_frame)
        glue.plat.rx_frame(glue.plat.ctx, frame, len);
}

static void glue_tx_wake(void)
{
    if (glue.plat.tx_wake)
        glue.plat.tx_wake(glue.plat.ctx);
}

static void glue_tx_dequeued(void *ctx, struct ieee80211_txq *txq)
{
    rtw89_data_tx_dequeued(txq);
}

static void glue_link_event(void *ctx, struct ieee80211_vif *vif,
                            enum rtw89_m80211_link_event event, s32 rssi)
{
    if (event == RTW89_M80211_CONNECTION_LOSS)
        rtw89_mlme_connection_lost();
    else if (event == RTW89_M80211_BEACON_LOSS)
        rtw89_mlme_beacon_loss();
}

/*
 * Feed one received 802.11 frame (without FCS) through the same path the
 * driver uses. For the userspace smoke test, which plays the access point.
 */
static struct sk_buff *glue_test_skb(const u8 *frame, size_t len, u16 freq, s8 signal,
                                     bool decrypted)
{
    struct ieee80211_rx_status *status;
    struct sk_buff *skb;

    if (!glue.probed)
        return NULL;
    skb = dev_alloc_skb(len + FCS_LEN);
    if (!skb)
        return NULL;
    skb_put_data(skb, frame, len);
    skb_put_zero(skb, FCS_LEN);
    status = IEEE80211_SKB_RXCB(skb);
    memset(status, 0, sizeof(*status));
    status->freq = freq;
    status->signal = signal;
    if (decrypted)
        status->flag |= RX_FLAG_DECRYPTED;
    return skb;
}

void rtw89_glue_test_rx(const u8 *frame, size_t len, u16 freq, s8 signal, bool decrypted);
void rtw89_glue_test_rx(const u8 *frame, size_t len, u16 freq, s8 signal, bool decrypted)
{
    struct sk_buff *skb = glue_test_skb(frame, len, freq, signal, decrypted);

    if (skb)
        ieee80211_rx_napi(glue_hw(), NULL, skb, NULL);
}

/*
 * The same, but the frame is left where rtw89_core_rx() leaves a data frame
 * whose PPDU status report has not arrived, followed by the end of a poll.
 */
void rtw89_glue_test_rx_parked(const u8 *frame, size_t len, u16 freq, s8 signal,
                               bool decrypted);
void rtw89_glue_test_rx_parked(const u8 *frame, size_t len, u16 freq, s8 signal,
                               bool decrypted)
{
    struct sk_buff *skb = glue_test_skb(frame, len, freq, signal, decrypted);
    struct rtw89_dev *rtwdev;

    if (!skb)
        return;
    rtwdev = glue_hw()->priv;
    skb_queue_tail(&rtwdev->ppdu_sts.rx_queue[RTW89_PHY_0], skb);
    glue_napi_post_poll(0);
}

static void glue_tx_status(void *ctx, struct sk_buff *skb)
{
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    if(skb && skb->len>=81u && skb->data[0]==8u &&
       !memcmp(skb->data+16,"\x00\x25\x00\xff\x94\x73",6)) {
        const bool multicast=(skb->data[4]&1u)!=0;
        const bool done=(IEEE80211_SKB_CB(skb)->flags&IEEE80211_TX_STAT_ACK)!=0;
        spin_lock(&owly_link_lock);
        const bool local=owly_link_state.active && !memcmp(skb->data+10,owly_link_state.local,6);
        if(local && !multicast && done)++owly_link_state.tx_radio_acked;
        spin_unlock(&owly_link_lock);
        if(local) {
            static volatile unsigned long mdns_reports,other_reports;
            /* The TX builder puts IPv6 at offset 40. Read only its
             * next-header byte and the two UDP ports. */
            const bool mdns=skb->len>=88u && skb->data[46]==17u &&
                (get_unaligned_be16(skb->data+80)==5353u ||
                 get_unaligned_be16(skb->data+82)==5353u);
            const unsigned long count=__sync_add_and_fetch(
                mdns ? &mdns_reports : &other_reports,1ul);
            if(count<=16ul || !(count&(count-1ul)))
                IOLog("OWLY IPv6 TX completion: count=%lu mdns=%u multicast=%u "
                      "device_done=%u\n",count,(unsigned)mdns,(unsigned)multicast,(unsigned)done);
        }
    }
#endif
#if defined(RTW89_AWDL_CORE04F_ONE_SHOT) && RTW89_AWDL_CORE04F_ONE_SHOT
    if (skb && owly_core04f_is_probe(skb->data, skb->len))
        IOLog("OWLY core04f: TX completion callback (NOT verified over-air)\n");
#endif
    rtw89_mlme_tx_status(skb);
    kfree_skb(skb);
}

/*
 * After a scan, networks on the channels it covered that have not been heard
 * for GLUE_BSS_MAX_AGE leave the list. Connected scans cover a few channels
 * each (GLUE_SCAN_SLICE), so the others' networks stay until their turn, or
 * at most GLUE_BSS_MAX_AGE_ANY.
 */
#define GLUE_BSS_MAX_AGE (90 * HZ)
#define GLUE_BSS_MAX_AGE_ANY (10 * 60 * HZ)

static bool glue_scanned_freq(u16 freq)
{
    const struct cfg80211_scan_request *req = glue.scan_req ? &glue.scan_req->req : NULL;
    u32 i;

    for (i = 0; req && i < req->n_channels; i++)
        if (req->channels[i]->center_freq == freq)
            return true;
    return false;
}

static void glue_bss_expire(void)
{
    unsigned int i = 0;

    spin_lock(&glue.bss_lock);
    while (i < glue.n_bss) {
        unsigned long seen = glue.bss[i].last_seen;

        if (time_after(jiffies, seen + GLUE_BSS_MAX_AGE_ANY) ||
            (time_after(jiffies, seen + GLUE_BSS_MAX_AGE) &&
             glue_scanned_freq(glue.bss[i].pub.freq))) {
            glue.n_bss--;
            if (i != glue.n_bss)
                glue.bss[i] = glue.bss[glue.n_bss];
        } else {
            i++;
        }
    }
    spin_unlock(&glue.bss_lock);
}

static void glue_scan_done(void *ctx, bool aborted)
{
    glue.scanning = false;
    glue.last_scan_ms = jiffies_to_msecs(jiffies - glue.scan_started);
    if (glue.scan_connected)
        glue.scan_ms_connected += glue.last_scan_ms;
    if (!aborted)
        glue_bss_expire();
    IOLog("[rtw89] scan %s: %u network(s) heard\n", aborted ? "aborted" : "finished",
          glue.n_bss);
    /* the attempt to get the network back was waiting for this */
    if (glue.rejoining)
        glue_rejoin_queue(0);
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
    /* A VIF created during a scan stays pending. Re-evaluate on the wiphy
     * worker, never by changing channel from this completion callback.
     * The work captures no VIF/chanctx pointer and checks radio-up again. */
    if (glue.up)
        wiphy_work_queue(glue_hw()->wiphy, &owly_radio_work);
#endif
    if (glue.plat.scan_done)
        glue.plat.scan_done(glue.plat.ctx, aborted);
}

/* For the smoke test: what rtw89's core does for a chip without real channel
 * contexts (RTL8851B, RTL8852A), so the join runs that way too. */
void rtw89_glue_test_emulate_chanctx(void);
void rtw89_glue_test_emulate_chanctx(void)
{
    struct ieee80211_ops *ops = (struct ieee80211_ops *)hw_to_local(glue_hw())->ops;

    ops->add_chanctx = ieee80211_emulate_add_chanctx;
    ops->remove_chanctx = ieee80211_emulate_remove_chanctx;
    ops->change_chanctx = ieee80211_emulate_change_chanctx;
    ops->switch_vif_chanctx = ieee80211_emulate_switch_vif_chanctx;
    ops->assign_vif_chanctx = NULL;
    ops->unassign_vif_chanctx = NULL;
    /* nor beacon filtering in their firmware: no CONNECTION_MONITOR */
    __clear_bit(IEEE80211_HW_CONNECTION_MONITOR, glue_hw()->flags);
}

/*
 * For the smoke test: 802.11be capabilities on the 6 GHz band of a chip that
 * has none (the pretend RTL8852CE), as an RTL8922A's would read: 2 streams up
 * to MCS 13, no PPE thresholds. The RTL8922A itself cannot be pretended: its
 * radio does not start without firmware answers. This exercises the MLME's
 * 802.11be join, not rtw89's handling of a real 802.11be chip.
 */
void rtw89_glue_test_fake_eht(void);
void rtw89_glue_test_fake_eht(void)
{
    struct ieee80211_supported_band *sband = glue_hw()->wiphy->bands[NL80211_BAND_6GHZ];
    struct ieee80211_sband_iftype_data *data;
    int i;

    if (!sband)
        return;
    for (i = 0; i < sband->n_iftype_data; i++) {
        data = (struct ieee80211_sband_iftype_data *)&sband->iftype_data[i];
        if (!(data->types_mask & BIT(NL80211_IFTYPE_STATION)))
            continue;
        memset(&data->eht_cap, 0, sizeof(data->eht_cap));
        data->eht_cap.has_eht = true;
        data->eht_cap.eht_mcs_nss_supp.bw._80.rx_tx_mcs9_max_nss = 0x22;
        data->eht_cap.eht_mcs_nss_supp.bw._80.rx_tx_mcs11_max_nss = 0x22;
        data->eht_cap.eht_mcs_nss_supp.bw._80.rx_tx_mcs13_max_nss = 0x22;
        data->eht_cap.eht_mcs_nss_supp.bw._160 = data->eht_cap.eht_mcs_nss_supp.bw._80;
    }
}

/* For the userspace smoke test, whose pretend chip never finishes a scan. */
void rtw89_glue_test_scan_done(void);
void rtw89_glue_test_scan_done(void)
{
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
    struct ieee80211_hw *hw = glue_hw();
    struct rtw89_m80211_local *local = hw_to_local(hw);
    /* The pretend chip emits no completion event. Use the real cancel path
     * so the driver's scanning bit and glue.scanning agree before the new
     * guarded auxiliary assignment. This function is only a host-test hook. */
    wiphy_lock(hw->wiphy);
    if (glue.scanning && local->ops->cancel_hw_scan)
        local->ops->cancel_hw_scan(hw, glue.vif);
    if (glue.scanning)
        glue_scan_done(NULL, false);
    wiphy_unlock(hw->wiphy);
#else
    glue_scan_done(NULL, false);
#endif
}

/* ... and never misses a beacon. */
void rtw89_glue_test_beacon_loss(void);
void rtw89_glue_test_beacon_loss(void)
{
    if (glue.up)
        ieee80211_beacon_loss(glue.vif);
}

/* How long to wait before each attempt to get the network back, in ms. */
static const unsigned int glue_rejoin_delay[] = { 500, 1000, 2000, 4000, 8000, 15000, 30000, 60000 };

static void glue_rejoin_queue(unsigned long delay)
{
    if (glue.rejoin_wq)
        queue_delayed_work(glue.rejoin_wq, &glue.rejoin_work, delay);
}

static void glue_rejoin_schedule(void)
{
    unsigned int i = min_t(unsigned int, glue.rejoin_tries, ARRAY_SIZE(glue_rejoin_delay) - 1);

    glue_rejoin_queue(msecs_to_jiffies(glue_rejoin_delay[i]));
}

#if defined(RTW89_AWDL_VIF_STAGE) && RTW89_AWDL_VIF_STAGE
static void owly_core04d_maybe_attach(void);
#endif
#if defined(RTW89_AWDL_CORE04F_ONE_SHOT) && RTW89_AWDL_CORE04F_ONE_SHOT
static void owly_core04f_try_once(void);
#endif
/* The MLME changed state. Called with the wiphy mutex held, from whichever
 * thread caused the change. */
#if defined(OWLY_SCC_SOCIAL_RX) && OWLY_SCC_SOCIAL_RX
/* Only called from a wiphy-locked MLME callback, or wiphy-locked teardown.
 * The driver accepts the filter request and writes its RX register.
 * This is not proof firmware delivered or hardware ACKed AWDL packets.
 * Never trigger radio TX, channel changes, chanctx assignment, or scan. */
static void owly_scc_filter_set(bool should_enable, unsigned int freq)
{
#ifdef OWLY_MC_BUILT
    if (owly_mc.present) {
        should_enable = true; /* visiting AWDL: keep the AWDL filter */
        freq = owly_mc_freq(owly_mc.channel);
    }
#endif
    struct ieee80211_hw *hw = glue_hw();
    struct rtw89_m80211_local *local = hw_to_local(hw);
    unsigned int want = FIF_OTHER_BSS | FIF_ALLMULTI | FIF_BCN_PRBRESP_PROMISC;
#if defined(RTW89_MACOS) && defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    struct rtw89_dev *rtwdev = hw->priv;
    const bool ax = rtwdev->chip->chip_id == RTL8852B;
    const bool awdl_channel = ax && should_enable &&
        (freq == 2437 || freq == 5220 || freq == 5745);
    const bool mode_changed = rtwdev->hal.owly_awdl_scc_rx != awdl_channel;

    /* Apply the AWDL filter to each supported social channel. Normal station
     * admission is restored whenever the real AWDL auxiliary VIF is stopped. */
    if (ax)
        want |= FIF_PROBE_REQ;
#else
    const bool mode_changed = false;
    (void)freq;
#endif
    if (owly_scc_filter_reported == should_enable && !mode_changed) return;
    lockdep_assert_wiphy(hw->wiphy);
#if defined(RTW89_MACOS) && defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    rtwdev->hal.owly_awdl_scc_rx = awdl_channel;
#endif
    unsigned int flags = should_enable ? want : 0u;
    local->ops->configure_filter(hw, want, &flags, 0);
    owly_scc_filter_reported = (flags & want) == want;
#if defined(RTW89_MACOS) && defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    if (ax) {
        const u32 rx_fltr = rtw89_read32(rtwdev, R_AX_RX_FLTR_OPT);
        IOLog("OWLY SCC AX RX filter: requested=%u sniffer=%u uid=%u raw=0x%08x a1=%u uc_cam_drop=%u\n",
              (unsigned)awdl_channel, (unsigned)!!(rx_fltr & B_AX_SNIFFER_MODE),
              (unsigned)FIELD_GET(B_AX_UID_FILTER_MASK, rx_fltr), (unsigned)rx_fltr,
              (unsigned)!!(rx_fltr & B_AX_A_A1_MATCH),
              (unsigned)!!(rx_fltr & B_AX_A_UC_CAM_MATCH));
    }
#endif
    IOLog("OWLY SCC social RX: requested=%u reported=%u want=0x%x flags=0x%x "
          "(NO_TX)\n",
          (unsigned)should_enable, (unsigned)owly_scc_filter_reported,
          want, flags);
}
#endif
static void glue_link_notify(void)
{
    struct rtw89_mlme_status st;

    rtw89_mlme_get_status(&st);
#if defined(OWLY_SCC_SOCIAL_RX) && OWLY_SCC_SOCIAL_RX
    if (glue.up) {
        const bool allow = owly_scc_rx_should_enable(
            st.state == RTW89_MLME_CONNECTED || st.awdl_channel_owned,
            owly_scc_aux_ready, st.freq);
        IOLog("OWLY SCC social RX policy: connected=%u aux=%u ap_freq=%u allow=%u (NO_TX)\n",
              (unsigned)(st.state == RTW89_MLME_CONNECTED),
              (unsigned)owly_scc_aux_ready, (unsigned)st.freq, (unsigned)allow);
        owly_scc_filter_set(allow, st.freq);
    }
#endif
    if (st.state == RTW89_MLME_CONNECTED) {
        if (glue.want.valid) {
            if (glue.rejoining) {
                glue.rejoins++;
                IOLog("[rtw89] connected again after %u attempt(s)\n", glue.rejoin_tries);
            }
            glue.want.proven = true;
        }
        glue.rejoining = false;
        glue.rejoin_tries = 0;
    } else if (st.state == RTW89_MLME_IDLE && glue.up && glue.want.valid && glue.want.proven &&
               !glue.rejoin_off) {
        if (!glue.rejoining)
            IOLog("[rtw89] connection lost (%d): will join \"%.*s\" again\n", st.last_error,
                  glue.want.ssid_len, glue.want.ssid);
        glue.rejoining = true;
        glue.rejoin_scanned = false;
        glue_rejoin_schedule();
    }

    if (glue.plat.link_changed)
        glue.plat.link_changed(glue.plat.ctx);
/* OWLY_CORE04E_R1_ONESHOT: update primary rejoin status and notify platform
 * BEFORE the one allowed auxiliary assignment per radio-up. The wiphy
 * mutex is still held. Never enable RF TX here. */
#if defined(RTW89_AWDL_VIF_STAGE) && RTW89_AWDL_VIF_STAGE
    if (st.state == RTW89_MLME_CONNECTED)
        owly_core04d_maybe_attach();
#endif
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
    if (st.state == RTW89_MLME_CONNECTED)
        owly_radio_maybe_attach();
    else if (st.state == RTW89_MLME_IDLE && glue.up)
        wiphy_work_queue(glue_hw()->wiphy, &owly_radio_work);
#endif
#if defined(RTW89_AWDL_CORE04F_ONE_SHOT) && RTW89_AWDL_CORE04F_ONE_SHOT
    if (st.state == RTW89_MLME_CONNECTED)
        owly_core04f_try_once();
#endif
}

static int glue_start_tx_ba(void *ctx, struct ieee80211_sta *sta, u16 tid, u16 timeout)
{
    return rtw89_mlme_tx_ba_request(sta, tid, true);
}

static int glue_stop_tx_ba(void *ctx, struct ieee80211_sta *sta, u16 tid)
{
    return rtw89_mlme_tx_ba_request(sta, tid, false);
}

static const struct rtw89_m80211_glue_ops glue_m80211_ops = {
    .rx = glue_rx,
    .tx_status = glue_tx_status,
    .tx_dequeued = glue_tx_dequeued,
    .scan_done = glue_scan_done,
    .link_event = glue_link_event,
    .start_tx_ba = glue_start_tx_ba,
    .stop_tx_ba = glue_stop_tx_ba,
};

/* ------------------------------------------------------------------ */
/*  Radio up / down                                                     */
/* ------------------------------------------------------------------ */

bool rtw89_glue_is_up(void)
{
    return glue.up;
}

/* OWLY_CORE04C_VIF_STAGE_FUNCTIONS_BEGIN
 * This is a P2P CLIENT shim, not a native Apple AWDL interface.
 * All call sites hold the wiphy mutex. No chanctx, no transmit caller,
 * no channel hopping, no new macOS network interface.
 */
#if defined(RTW89_AWDL_VIF_STAGE) && RTW89_AWDL_VIF_STAGE
#if !defined(OWLY_NATIVE_PEER_DATA) || !OWLY_NATIVE_PEER_DATA
static struct ieee80211_vif *owly_core04c_vif;
#endif
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
static int owly_aux_program_cam(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
    static const u8 awdl_bssid[ETH_ALEN] = {0x00, 0x25, 0x00, 0xff, 0x94, 0x73};
    struct rtw89_dev *rtwdev = hw->priv;
    struct rtw89_vif_link *link;
    int ret;

    lockdep_assert_wiphy(hw->wiphy);
    if (rtwdev->chip->chip_id != RTL8852B)
        return 0;
    if (vif == glue.vif || !vif->p2p || vif->type != NL80211_IFTYPE_STATION)
        return -EINVAL;

    /* The stock P2P-client create path programs its own MAC but starts
     * with an empty BSSID. Update the existing auxiliary entry before the
     * VIF is published or bound to the station's channel. */
    link = vif_to_rtwvif(vif)->links[RTW89_VIF_IDLE_LINK_ID];
    if (!link || !link->addr_cam.valid || !link->bssid_cam.valid ||
        !ether_addr_equal(link->mac_addr, vif->addr))
        return -EINVAL;
    vif->bss_conf.bssid = awdl_bssid;
    ether_addr_copy(link->bssid, awdl_bssid);
    rtw89_cam_bssid_changed(rtwdev, link);
    ret = rtw89_fw_h2c_cam(rtwdev, link, NULL, NULL, RTW89_ROLE_INFO_CHANGE);
    IOLog("OWLY auxiliary AWDL CAM: port=%u addr_entry=%u bssid_entry=%u rc=%d\n",
          (unsigned)link->port, (unsigned)link->addr_cam.addr_cam_idx,
          (unsigned)link->bssid_cam.bssid_cam_idx, ret);
    return ret;
}
#endif

static int owly_core04c_vif_register(struct ieee80211_hw *hw,
                                         const u8 requested_mac[ETH_ALEN])
{
    struct rtw89_m80211_local *local = hw_to_local(hw);
    struct ieee80211_vif *vif;
    u8 mac[ETH_ALEN];
    int ret;

    lockdep_assert_wiphy(hw->wiphy);
    if (owly_core04c_vif || !glue.vif)
        return -EBUSY;
    if (!(hw->wiphy->interface_modes & BIT(NL80211_IFTYPE_P2P_CLIENT)))
        return -EOPNOTSUPP;
    if (requested_mac) {
        unsigned int nonzero = 0;
        for (unsigned int i = 0; i < ETH_ALEN; ++i) nonzero |= requested_mac[i];
        if (!nonzero || (requested_mac[0] & 1u) ||
            memcmp(requested_mac, glue.vif->addr, ETH_ALEN) == 0)
            return -EINVAL;
        memcpy(mac, requested_mac, ETH_ALEN);
    } else if (!owly_core04c_make_mac(glue.vif->addr, mac)) {
        return -EINVAL;
    }
    /* rtw89 maps STATION+p2p to RTW89_WIFI_ROLE_P2P_CLIENT.
     * DO NOT use the unsupported NL80211_IFTYPE_P2P_DEVICE. */
    vif = rtw89_m80211_vif_alloc(hw, NL80211_IFTYPE_STATION, mac);
    if (!vif)
        return -ENOMEM;
    vif->p2p = true;
    ret = local->ops->add_interface(hw, vif);
    if (ret) {
        rtw89_m80211_vif_free(vif);
        return ret;
    }
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    ret = owly_aux_program_cam(hw, vif);
    if (ret) {
        local->ops->remove_interface(hw, vif);
        rtw89_m80211_vif_free(vif);
        return ret;
    }
#endif
    rtw89_m80211_vif_set_in_driver(vif, true);
    owly_core04c_vif = vif;
#if defined(OWLY_SCC_SOCIAL_RX) && OWLY_SCC_SOCIAL_RX
    owly_scc_aux_ready = true;

    /* Re-evaluate SCC when an auxiliary VIF is registered
     * after the primary STA has already connected.
     * Called with the wiphy lock held; RX only, no TX. */
    if (glue.up) {
        struct rtw89_mlme_status st;
        rtw89_mlme_get_status(&st);

        const bool allow = owly_scc_rx_should_enable(
            st.state == RTW89_MLME_CONNECTED || st.awdl_channel_owned,
            owly_scc_aux_ready, st.freq);

        IOLog("OWLY SCC aux recheck: connected=%u freq=%u allow=%u (NO_TX)\n",
              (unsigned)(st.state == RTW89_MLME_CONNECTED),
              (unsigned)st.freq, (unsigned)allow);

        owly_scc_filter_set(allow, st.freq);
    }
#endif
    IOLog("OWLY core04c: second P2P-client vif registered; "
          "chanctx=UNASSIGNED tx=DISABLED awdl0=ABSENT\n");
    return 0;
}

static void owly_core04c_vif_unregister(struct ieee80211_hw *hw)
{
    struct ieee80211_vif *vif = owly_core04c_vif;
    struct rtw89_m80211_local *local = hw_to_local(hw);
    lockdep_assert_wiphy(hw->wiphy);
    if (!vif)
        return;
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
    /* Cancel and drain management TX before removing its VIF/context. */
#ifdef OWLY_MC_BUILT
    owly_mc_stop();
#endif
#if defined(OWLY_AWDL_SOFTWARE_SYNC) && OWLY_AWDL_SOFTWARE_SYNC
    owly_sync_pause(true);
#endif
    /* Complete unassignment while this VIF is still registered. */
    owly_radio_detach(NULL);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    rtw89_mlme_awdl_release_channel();
#endif
#endif
    owly_core04c_vif = NULL;
#if defined(OWLY_SCC_SOCIAL_RX) && OWLY_SCC_SOCIAL_RX
    owly_scc_aux_ready = false;
    owly_scc_filter_set(false, 0);
#endif
    rtw89_m80211_vif_set_in_driver(vif, false);
    local->ops->remove_interface(hw, vif);
    rtw89_m80211_vif_free(vif);
    IOLog("OWLY core04c: second P2P-client vif removed\n");
}
#endif
/* OWLY_CORE04C_VIF_STAGE_FUNCTIONS_END */

/* OWLY_BRIDGE_BACKEND_BEGIN: match macOS-requested AWDL MAC to an
 * on-demand hardware P2P-client VIF. This is a genuine add_interface()/
 * remove_interface() transaction, not an identity cookie ACK.
 * No RF TX, new chanctx, or Apple/BSD interface is created here. */
#ifndef OWLY_BACKEND_REAL_VIF
#define OWLY_BACKEND_REAL_VIF 0
#endif
#if OWLY_BACKEND_REAL_VIF
#if !defined(RTW89_AWDL_VIF_STAGE) || !RTW89_AWDL_VIF_STAGE
#error "OWLY backend bridge requires Core04C VIF stage"
#endif
#if defined(RTW89_AWDL_VIF_REGISTER) && RTW89_AWDL_VIF_REGISTER
#error "OWLY backend bridge forbids automatic VIF at radio-up"
#endif
#if defined(RTW89_AWDL_CHANCTX_ATTACH) && RTW89_AWDL_CHANCTX_ATTACH
#error "OWLY backend bridge requires channel attachment OFF"
#endif
#endif
/*
 * Whether this chip can carry AWDL at all. RTLAirLink's AWDL holds its own
 * channel context and assigns a second vif to it; rtw89 leaves
 * assign/unassign_vif_chanctx out and emulates channel contexts through
 * ->config() on chips that have none, or whose firmware lacks scan offload
 * or beacon filtering (the RTL8851B and RTL8852A always). On those AWDL is
 * reported as off and awdl0 is refused, rather than half set up.
 */
static bool glue_awdl_chip_capable(void)
{
    const struct ieee80211_ops *ops = hw_to_local(glue_hw())->ops;

    return ops->add_chanctx && ops->remove_chanctx &&
           ops->assign_vif_chanctx && ops->unassign_vif_chanctx;
}

int rtw89_glue_awdl_vif_create(const uint8_t mac[6])
{
#if OWLY_BACKEND_REAL_VIF
    struct ieee80211_hw *hw;
    int rc;
    unsigned int nonzero = 0;
    if (!mac) return -EINVAL;
    for (unsigned int i = 0; i < ETH_ALEN; ++i) nonzero |= mac[i];
    if (!nonzero || (mac[0] & 1u)) return -EINVAL;
    if (!glue.active || !glue.probed) return -ENODEV;
    if (!glue_awdl_chip_capable()) return -EOPNOTSUPP;
    mutex_lock(&glue.cmd_lock);
    if (!glue.up || !glue.vif) {
        rc = -ENETDOWN;
    } else {
        hw = glue_hw();
        wiphy_lock(hw->wiphy);
        if (owly_core04c_vif) {
            rc = memcmp(owly_core04c_vif->addr, mac, ETH_ALEN) == 0 ? 0 : -EBUSY;
        } else {
            rc = owly_core04c_vif_register(hw, mac);
        }
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
        if (!rc)
            owly_radio_maybe_attach(); /* also handles late/idempotent create */
#endif
        wiphy_unlock(hw->wiphy);
    }
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
    if (!rc)
        memcpy(glue.awdl_vif_mac, mac, ETH_ALEN);
#endif
    mutex_unlock(&glue.cmd_lock);
    return rc;
#else
    (void)mac;
    return -EOPNOTSUPP;
#endif
}

int rtw89_glue_awdl_vif_destroy(void)
{
#if OWLY_BACKEND_REAL_VIF
    struct ieee80211_hw *hw;
    if (!glue.active || !glue.probed) return 0;
    mutex_lock(&glue.cmd_lock);
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
    memset(glue.awdl_vif_mac, 0, sizeof(glue.awdl_vif_mac));
#endif
    if (glue.up && owly_core04c_vif) {
        hw = glue_hw();
        wiphy_lock(hw->wiphy);
        /* unregister unwinds an opt-in SCC channel lease before VIF removal. */
        owly_core04c_vif_unregister(hw);
        wiphy_unlock(hw->wiphy);
    }
    mutex_unlock(&glue.cmd_lock);
    return 0;
#else
    return -EOPNOTSUPP;
#endif
}

bool rtw89_glue_awdl_vif_present(void)
{
#if OWLY_BACKEND_REAL_VIF
    bool present;
    if (!glue.active || !glue.probed) return false;
    mutex_lock(&glue.cmd_lock);
    present = glue.up && owly_core04c_vif != NULL;
    mutex_unlock(&glue.cmd_lock);
    return present;
#else
    return false;
#endif
}
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
int rtw89_glue_awdl_vif_enable(void)
{
    if (!glue.active || !glue.probed) return -ENODEV;
    mutex_lock(&glue.cmd_lock);
    struct ieee80211_hw *hw=glue_hw();
    wiphy_lock(hw->wiphy);
    const bool present=glue.up && owly_core04c_vif;
    /* A real Apple VIF re-enable permits another bootstrap. SET117 and
     * SET151 still determine when the radio can transmit. */
    if (present) {
        owly_sync_state.explicitly_disabled=false;
        owly_radio_maybe_attach();
    }
    wiphy_unlock(hw->wiphy);
    mutex_unlock(&glue.cmd_lock);
    return present ? 0 : -ENETDOWN;
}
#endif
/* OWLY_BRIDGE_BACKEND_END */

#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
/* The radio and primary VIF have started. The caller still holds cmd_lock. */
static void owly_restore_awdl_vif(struct ieee80211_hw *hw)
{
    int rc;

    if (is_zero_ether_addr(glue.awdl_vif_mac))
        return;

    wiphy_lock(hw->wiphy);
    if (!owly_core04c_vif) {
        rc = owly_core04c_vif_register(hw, glue.awdl_vif_mac);
        if (!rc)
            owly_radio_maybe_attach();
        IOLog("OWLY radio SCC: auxiliary VIF restore rc=%d\n", rc);
    }
    wiphy_unlock(hw->wiphy);
}
#endif


/* OWLY_CORE04D_SHARED_CHANCTX_BEGIN
 * EXPERIMENTAL: share the connected station's existing chanctx.
 * P2P-client staging shim != Apple AWDL; AP may be 80 MHz, not AWDL 20 MHz.
 * Creating/assigning chanctx can cause a firmware channel reset or scan abort.
 * Defaults OFF; no RF transmit path, no runtime command to enable it.
 * All calls are under wiphy mutex (MLME callback/teardown/glue shutdown).
 */
#if defined(RTW89_AWDL_VIF_STAGE) && RTW89_AWDL_VIF_STAGE
#ifndef RTW89_AWDL_CHANCTX_ATTACH
#define RTW89_AWDL_CHANCTX_ATTACH 0
#endif
/* OWLY_CORE04E_GUARDED_ASSIGN: staged trial requires scoped rollback;
 * always reject unsafe build-flag combinations at compile time. */
#if defined(RTW89_AWDL_CHANCTX_ATTACH) && RTW89_AWDL_CHANCTX_ATTACH
#if !defined(RTW89_AWDL_CHANCTX_GUARD) || !RTW89_AWDL_CHANCTX_GUARD
#error "Core-04E: chanctx attach requires -DRTW89_AWDL_CHANCTX_GUARD=1"
#endif
#if !defined(RTW89_AWDL_VIF_REGISTER) || !RTW89_AWDL_VIF_REGISTER
#error "Core-04E: chanctx attach requires second VIF registration"
#endif
#if defined(RTW89_AWDL_MGMT_RF_TX) && RTW89_AWDL_MGMT_RF_TX
#if !defined(RTW89_AWDL_CORE04F_ONE_SHOT) || !RTW89_AWDL_CORE04F_ONE_SHOT
#error "Core-04E: no RF TX unless explicitly building Core-04F one-shot diagnostic"
#endif
#endif
#endif
/* OWLY_CORE04E_GUARDED_ASSIGN_BUILD_GUARD_END */
static struct ieee80211_chanctx_conf *owly_core04d_ctx;
static bool owly_core04d_assigned;
static bool owly_core04e_attach_refused;
static bool owly_core04e_r1_attach_attempted; /* per radio-up, not per reconnect */

static void owly_core04d_detach(struct ieee80211_chanctx_conf *primary)
{
    struct ieee80211_hw *hw;
    struct rtw89_m80211_local *local;
    struct ieee80211_bss_conf *conf;
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
    owly_radio_detach(primary); /* before the primary MLME frees its context */
#endif
    if (!owly_core04d_assigned || !owly_core04c_vif)
        return;
    if (primary && primary != owly_core04d_ctx) {
        IOLog("OWLY core04d: detach context mismatch, refusing free\n");
        return;
    }
    hw = glue_hw();
    lockdep_assert_wiphy(hw->wiphy);
    local = hw_to_local(hw);
    conf = &owly_core04c_vif->bss_conf;
    /* This VIF does not own the ctx; the station's MLME frees it later. */
    local->ops->unassign_vif_chanctx(hw, owly_core04c_vif, conf, owly_core04d_ctx);
    conf->chanctx_conf = NULL;
    memset(&conf->chanreq, 0, sizeof(conf->chanreq));
    owly_core04d_ctx = NULL;
    owly_core04d_assigned = false;
    IOLog("OWLY core04d: auxiliary VIF detached before AP ctx release\n");
}

static void owly_core04d_maybe_attach(void)
{
    struct ieee80211_hw *hw;
    struct rtw89_m80211_local *local;
    struct ieee80211_chanctx_conf *ctx;
    struct ieee80211_bss_conf *conf;
    int rc;
    if (!RTW89_AWDL_CHANCTX_ATTACH || !RTW89_AWDL_VIF_REGISTER ||
        !owly_core04c_vif || owly_core04d_assigned || owly_core04e_attach_refused ||
        owly_core04e_r1_attach_attempted)
        return;
    hw = glue_hw();
    lockdep_assert_wiphy(hw->wiphy);
    ctx = rtw89_mlme_awdl_shared_chanctx();
    if (!ctx)
        return;
    /* Try at most once; reconnects must never repeatedly reconfigure RF. */
    owly_core04e_r1_attach_attempted = true;
    local = hw_to_local(hw);
    conf = &owly_core04c_vif->bss_conf;
    /* No add_chanctx: borrow the precise AP context (including its width). */
    conf->chanreq.oper = ctx->def;
    rc = local->ops->assign_vif_chanctx(hw, owly_core04c_vif, conf, ctx);
    if (rc) {
        /* NOTE: some rtw89 versions mutate internal state before failing.
         * Do not enable on live hardware until that rollback is audited. */
        memset(&conf->chanreq, 0, sizeof(conf->chanreq));
        owly_core04e_attach_refused = true;
        IOLog("OWLY core04e: auxiliary assignment refused rc=%d; retry disabled until restart\n", rc);
        return;
    }
    conf->chanctx_conf = ctx;
    owly_core04d_ctx = ctx;
    owly_core04d_assigned = true;
#if defined(RTW89_AWDL_CORE04F_ONE_SHOT) && RTW89_AWDL_CORE04F_ONE_SHOT
    IOLog("OWLY core04d: sharing AP chanctx; Core04F R1 2.4GHz-only diagnostic armed\n");
#else
    IOLog("OWLY core04d: sharing AP chanctx, TX=DISABLED, AWDL=ABSENT\n");
#endif
}
#endif
/* OWLY_CORE04D_SHARED_CHANCTX_END */

/* On-demand SCC radio lifecycle. Each operation holds the wiphy mutex.
 * The borrowed context is precisely the connected AP's existing context,
 * including width. This revision never adds a channel, chooses an AWDL
 * social channel, enables GET117, or sends an Action/data frame.
 */
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
static int owly_radio_assign(void *opaque, void *owner, void *channel)
{
    struct ieee80211_hw *hw = opaque;
    struct ieee80211_vif *vif = owner;
    struct ieee80211_chanctx_conf *primary = channel;
    struct rtw89_m80211_local *local = hw_to_local(hw);
    struct ieee80211_bss_conf *conf = &vif->bss_conf;
    int rc;
    lockdep_assert_wiphy(hw->wiphy);
    if (vif != owly_core04c_vif || vif == glue.vif || !vif->p2p ||
        conf->chanctx_conf || !primary || !primary->def.chan ||
        (primary->def.chan->flags & IEEE80211_CHAN_DISABLED) ||
        !local->ops->assign_vif_chanctx || !local->ops->unassign_vif_chanctx)
        return -EINVAL;
    conf->chanreq.oper = primary->def;
    rc = local->ops->assign_vif_chanctx(hw, vif, conf, primary);
    if (rc) {
        /* RTW89_AWDL_CHANCTX_GUARD rolls back driver's software refcount/
         * role bookkeeping. RF restoration is only best effort: latch off. */
        memset(&conf->chanreq, 0, sizeof(conf->chanreq));
        return rc;
    }
    conf->chanctx_conf = primary;
    return 0;
}

static void owly_radio_unassign(void *opaque, void *owner, void *channel)
{
    struct ieee80211_hw *hw = opaque;
    struct ieee80211_vif *vif = owner;
    struct ieee80211_chanctx_conf *primary = channel;
    struct rtw89_m80211_local *local = hw_to_local(hw);
    struct ieee80211_bss_conf *conf = &vif->bss_conf;
    lockdep_assert_wiphy(hw->wiphy);
    local->ops->unassign_vif_chanctx(hw, vif, conf, primary);
    conf->chanctx_conf = NULL;
    memset(&conf->chanreq, 0, sizeof(conf->chanreq));
}

static const struct owly_radio_ops owly_radio_driver_ops = {
    .assign = owly_radio_assign,
    .unassign = owly_radio_unassign,
};

static void owly_radio_maybe_attach(void)
{
    struct ieee80211_hw *hw = glue_hw();
    struct ieee80211_chanctx_conf *primary;
    enum owly_radio_result result;
    uint32_t attempts = owly_radio_state.attempts;
    lockdep_assert_wiphy(hw->wiphy);
    if (!glue.up || !owly_core04c_vif)
        return;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    /* Same coarse idle-channel following as the referenced RTW89 port.
     * It never runs while an AP is connected/joining or a scan is active. */
    struct rtw89_mlme_status idle;
    rtw89_mlme_get_status(&idle);
    const uint64_t now=glue_now_us();
    if (idle.awdl_channel_owned && !glue.scanning &&
        !owly_sync_state.explicitly_disabled &&
        (!owly_idle_move_us || now<owly_idle_move_us || now-owly_idle_move_us>=5000000u)) {
        spin_lock(&owly_link_lock);
        const uint8_t desired=owly_link_follow_channel(&owly_link_state,now);
        spin_unlock(&owly_link_lock);
        const unsigned freq=desired==149 ? 5745 : desired==44 ? 5220 : 2437;
        struct ieee80211_channel *candidate=ieee80211_get_channel(hw->wiphy,freq);
        if (freq!=idle.freq && candidate &&
            !(candidate->flags&(IEEE80211_CHAN_DISABLED|IEEE80211_CHAN_RADAR)) &&
            (!(candidate->flags&IEEE80211_CHAN_NO_IR) ||
             rtw89_cfg80211_awdl_5g_ok(hw->wiphy,freq))) {
            owly_idle_move_us=now;
            const int rc=rtw89_mlme_awdl_hold_channel((u16)freq);
            if (rc) {
                owly_radio_state.last_error=rc; owly_radio_state.blocked=true;
                IOLog("OWLY standalone: channel follow refused rc=%d\n",rc);
            }
        }
    }
#endif
    primary = rtw89_mlme_awdl_shared_chanctx();
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    if (!primary && !glue.scanning && !owly_radio_state.blocked &&
        !owly_sync_state.explicitly_disabled) {
        struct rtw89_mlme_status st;
        rtw89_mlme_get_status(&st);
        if (st.state == RTW89_MLME_IDLE) {
            /* Channel 6 is the initial discovery channel. This creates an
             * actual driver context; it never marks the station connected. */
            const int rc = rtw89_mlme_awdl_hold_channel(2437);
            if (rc && rc != -EBUSY) {
                owly_radio_state.last_error=rc; owly_radio_state.blocked=true;
                IOLog("OWLY standalone: channel hold refused rc=%d\n", rc);
            }
            primary = rtw89_mlme_awdl_shared_chanctx();
        }
    }
#endif
    if (!primary && owly_radio_is_bound(&owly_radio_state)) return;
    result = owly_radio_bind(&owly_radio_state, owly_core04c_vif, primary,
                             !glue.scanning && primary != NULL,
                             &owly_radio_driver_ops, hw);
    if (owly_radio_state.attempts != attempts)
        IOLog("OWLY radio SCC: bind result=%u rc=%d bound=%u (NO_TX)\n",
              (unsigned)result, owly_radio_state.last_error,
              (unsigned)owly_radio_is_bound(&owly_radio_state));
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    if (owly_radio_is_bound(&owly_radio_state)) {
        struct rtw89_mlme_status st;
        rtw89_mlme_get_status(&st);
        if(st.awdl_channel_owned && !glue.scanning &&
           !owly_sync_state.explicitly_disabled) {
            const int address_rc=rtw89_mlme_awdl_set_self_addr(owly_core04c_vif->addr);
            if(address_rc) {
                owly_radio_state.last_error=address_rc;
                owly_radio_state.blocked=true;
                IOLog("OWLY standalone self-address refused rc=%d\n",address_rc);
            }
        }
        owly_scc_filter_set(owly_scc_rx_should_enable(
            st.state==RTW89_MLME_CONNECTED || st.awdl_channel_owned,
            owly_scc_aux_ready, st.freq), st.freq);
    }
#endif
#if defined(OWLY_AWDL_SOFTWARE_SYNC) && OWLY_AWDL_SOFTWARE_SYNC
    owly_sync_recheck();
#endif
}

static void owly_radio_work_run(struct wiphy *wiphy, struct wiphy_work *work)
{
    (void)work;
    lockdep_assert_wiphy(wiphy);
    if (glue.up)
        owly_radio_maybe_attach();
}

static void owly_radio_detach(struct ieee80211_chanctx_conf *primary)
{
    struct ieee80211_hw *hw = glue_hw();
    enum owly_radio_result result;
    lockdep_assert_wiphy(hw->wiphy);
#if defined(OWLY_AWDL_SOFTWARE_SYNC) && OWLY_AWDL_SOFTWARE_SYNC
    owly_sync_pause(false);
#endif
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    owly_peer_close_all(); /* before the borrowed context is freed */
#endif
    result = owly_radio_unbind(&owly_radio_state, primary,
                               &owly_radio_driver_ops, hw);
    if (result != OWLY_RADIO_OK)
        IOLog("OWLY radio SCC: detach invariant result=%u\n", (unsigned)result);
}
#endif

int rtw89_glue_awdl_radio_status(struct rtw89_glue_awdl_radio_status *out)
{
    if (!out)
        return -EINVAL;
    memset(out, 0, sizeof(*out));
    if (!glue.active || !glue.probed)
        return -ENODEV;
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
    mutex_lock(&glue.cmd_lock);
    wiphy_lock(glue_hw()->wiphy);
    out->enabled = glue_awdl_chip_capable();
    out->vif_registered = owly_core04c_vif != NULL;
    out->channel_bound = owly_radio_is_bound(&owly_radio_state);
    out->blocked = owly_radio_state.blocked;
    out->last_error = owly_radio_state.last_error;
    out->attempts = owly_radio_state.attempts;
    out->binds = owly_radio_state.binds;
    out->releases = owly_radio_state.releases;
    if (out->channel_bound) {
        struct ieee80211_chanctx_conf *primary = owly_radio_state.channel;
        out->freq = primary->def.chan->center_freq;
    }
    wiphy_unlock(glue_hw()->wiphy);
    mutex_unlock(&glue.cmd_lock);
#endif
    return 0;
}


#if defined(OWLY_AWDL_SOFTWARE_SYNC) && OWLY_AWDL_SOFTWARE_SYNC
/* The radio is not on the AWDL channel: a scan, or multichannel AWDL is
 * spending this slot with the access point. AWDL TX waits; RX can't come. */
static bool owly_awdl_away(void)
{
#ifdef OWLY_MC_BUILT
    if (owly_mc.enabled && !owly_mc.present && !owly_mc.home)
        return true;
#endif
    return glue.scanning;
}

static struct ieee80211_channel *owly_sync_bound_channel(void)
{
    struct ieee80211_chanctx_conf *primary;
    struct ieee80211_channel *ch;
    if (!glue.up || !owly_core04c_vif ||
        !owly_radio_is_bound(&owly_radio_state) || owly_radio_state.blocked)
        return NULL;
    primary=rtw89_mlme_awdl_shared_chanctx();
    if (!primary || primary!=owly_radio_state.channel ||
        owly_core04c_vif->bss_conf.chanctx_conf!=primary)
        return NULL;
#ifdef OWLY_MC_BUILT
    /* Multichannel: AWDL lives on ch 6 even though the context is the AP's.
     * owly_awdl_away() says when the radio is actually there. */
    if (owly_mc.enabled)
        return ieee80211_get_channel(glue_hw()->wiphy,owly_mc_freq(owly_mc.channel));
#endif
    ch=primary->def.chan;
    if (!ch || (ch->flags & (IEEE80211_CHAN_DISABLED | IEEE80211_CHAN_NO_IR |
                             IEEE80211_CHAN_RADAR))) return NULL;
    if (ch->center_freq!=2437 && ch->center_freq!=5220 && ch->center_freq!=5745)
        return NULL;
    return ch;
}

static void owly_sync_recheck(void)
{
    struct ieee80211_hw *hw=glue_hw();
    struct ieee80211_channel *ch;
    lockdep_assert_wiphy(hw->wiphy);
    ch=owly_sync_bound_channel();
    owly_sync_reconcile(&owly_sync_state,ch && !owly_awdl_away(),ch ? (uint8_t)ch->hw_value : 0,
                        glue_now_us());
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    spin_lock(&owly_link_lock);
    owly_link_update_locked(ch,glue_now_us());
    spin_unlock(&owly_link_lock);
#endif
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    const unsigned long delay=0;
#else
    const unsigned long delay=usecs_to_jiffies(16384);
#endif
    if (owly_sync_state.active &&
        !wiphy_delayed_work_pending(hw->wiphy,&owly_sync_work))
        wiphy_delayed_work_queue(hw->wiphy,&owly_sync_work,delay);
}

static void owly_sync_pause(bool clear)
{
    struct ieee80211_hw *hw=glue_hw();
    struct rtw89_m80211_local *local=hw_to_local(hw);
    lockdep_assert_wiphy(hw->wiphy);
    wiphy_delayed_work_cancel(hw->wiphy,&owly_sync_work);
    owly_sync_state.active=false;
    owly_sync_state.due_us=0;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    spin_lock(&owly_link_lock);
    owly_link_reconcile(&owly_link_state,false,NULL,0,glue_now_us());
    spin_unlock(&owly_link_lock);
    owly_sync_state.broadcast_mif_submitted=false;
#endif
    if (owly_core04c_vif && owly_sync_state.handed_off && local->ops->flush)
        local->ops->flush(hw,owly_core04c_vif,BIT(hw->queues)-1,false);
    if (clear) {
        owly_sync_reset(&owly_sync_state);
        __atomic_store_n(&owly_cfg_rssi_floor,-128,__ATOMIC_RELEASE);
    }
}

#ifdef OWLY_MC_BUILT
int rtw89_compat_owly_visit(struct rtw89_dev *rtwdev, struct rtw89_vif_link *sta_link,
                            const struct cfg80211_chan_def *social);

/* Associated on a channel AWDL does not use, with AWDL bound to the AP's
 * context: AWDL then runs on ch 6 in the slots owly_mc_work_run picks. */
static bool owly_mc_should_run(void)
{
    struct rtw89_mlme_status st;
    struct ieee80211_channel *social;
    if (owly_mc.off || !glue.up || !glue.vif || !owly_core04c_vif)
        return false;
    if (!owly_radio_is_bound(&owly_radio_state) || owly_radio_state.blocked)
        return false;
    rtw89_mlme_get_status(&st);
    if (st.state != RTW89_MLME_CONNECTED || st.awdl_channel_owned)
        return false;
    /* Also on a social AP channel: the AWDL devices around may be elsewhere
     * (an iPhone on Personal Hotspot sits on 6/149, not the home AP's 44). */
    social = ieee80211_get_channel(glue_hw()->wiphy, 2437);
    return social && !(social->flags & (IEEE80211_CHAN_DISABLED |
                                        IEEE80211_CHAN_NO_IR |
                                        IEEE80211_CHAN_RADAR));
}

/* A social channel we may transmit on (regulatory: not off, no radar). */
static bool owly_mc_channel_ok(uint8_t ch)
{
    struct ieee80211_channel *c;
    if (ch != 6 && ch != 44 && ch != 149)
        return false;
    c = ieee80211_get_channel(glue_hw()->wiphy, owly_mc_freq(ch));
    if (!c || (c->flags & (IEEE80211_CHAN_DISABLED | IEEE80211_CHAN_RADAR)))
        return false;
    /* No country database here: 5 GHz stays world NO_IR unless the AP is
     * on it. A known country that allows the channel lifts that for AWDL. */
    return !(c->flags & IEEE80211_CHAN_NO_IR) ||
           rtw89_cfg80211_awdl_5g_ok(glue_hw()->wiphy, c->center_freq);
}

static void owly_mc_note_switch(bool going, uint64_t took_us, int rc)
{
    if (rc)
        owly_mc.null_failures++;
    if (took_us > owly_mc.max_switch_us)
        owly_mc.max_switch_us = took_us;
    if (going)
        owly_mc.lead_us = owly_mc_lead(&owly_mc.switch_avg_us,
                                       took_us > 0xffffffffu ? 0xffffffffu : (uint32_t)took_us);
    if (took_us > 8000u)
        owly_mc.slow_switches++;
    const uint64_t n = owly_mc.visits;
    if (n <= 4 || !(n % 512) || rc || took_us > 20000u)
        IOLog("OWLY multichannel: %s ch %u took=%lluus rc=%d visits=%llu "
              "null_fail=%llu slow=%llu max=%lluus slots=0x%04x\n",
              going ? "to" : "from", (unsigned)owly_mc.channel,
              (unsigned long long)took_us, rc,
              (unsigned long long)n, (unsigned long long)owly_mc.null_failures,
              (unsigned long long)owly_mc.slow_switches,
              (unsigned long long)owly_mc.max_switch_us, (unsigned)owly_mc.slots);
}

static struct rtw89_vif_link *owly_mc_sta_link(void)
{
    return glue.vif ? rtw89_get_designated_link(vif_to_rtwvif(glue.vif)) : NULL;
}

static void owly_mc_enter(void)
{
    struct ieee80211_hw *hw = glue_hw();
    struct rtw89_vif_link *link = owly_mc_sta_link();
    struct ieee80211_channel *social =
        ieee80211_get_channel(hw->wiphy, owly_mc_freq(owly_mc.channel));
    struct cfg80211_chan_def def;
    if (owly_mc.present || !link || !social)
        return;
    const uint64_t start = glue_now_us();
    cfg80211_chandef_create(&def, social, NL80211_CHAN_NO_HT);
    const int rc = rtw89_compat_owly_visit(hw->priv, link, &def);
    owly_mc.present = true;
    owly_mc.visits++;
#if defined(OWLY_SCC_SOCIAL_RX) && OWLY_SCC_SOCIAL_RX
    owly_scc_filter_set(true, owly_mc_freq(owly_mc.channel));
#endif
    owly_mc_note_switch(true, glue_now_us() - start, rc);
}

/* Back to the AP. Safe to call in any state; wiphy lock held. */
static void owly_mc_leave(void)
{
    struct ieee80211_hw *hw = glue_hw();
    struct rtw89_vif_link *link;
    if (!owly_mc.present)
        return;
    owly_mc.present = false;
    link = owly_mc_sta_link();
    const uint64_t start = glue_now_us();
    const int rc = link ? rtw89_compat_owly_visit(hw->priv, link, NULL) : -ENOLINK;
#if defined(OWLY_SCC_SOCIAL_RX) && OWLY_SCC_SOCIAL_RX
    {
        struct rtw89_mlme_status st;
        rtw89_mlme_get_status(&st);
        owly_scc_filter_set(owly_scc_rx_should_enable(
            st.state == RTW89_MLME_CONNECTED || st.awdl_channel_owned,
            owly_scc_aux_ready, st.freq), st.freq);
    }
#endif
    owly_mc_note_switch(false, glue_now_us() - start, rc);
}

/* Before a scan, a teardown or the AWDL interface going away. */
static void owly_mc_stop(void)
{
    const bool was = owly_mc.enabled;
    owly_mc_leave();
    owly_mc.enabled = false;
    owly_mc.slots = 0;
    owly_mc.root_slots = 0;
    owly_mc.channel = 0;
    owly_mc.home = false;
    owly_sync_state.presence_slots = 0;
    if (was)
        IOLog("OWLY multichannel: off\n");
}

static void owly_mc_end_hook(void)
{
    owly_mc_stop();
}

/* Every 5 s: who we hear and whether their clock was taken. Sequence key:
 * 6 = ch 6, 4 = ch 44, 9 = ch 149, . = elsewhere. Diagnostics only. */
static void owly_mc_log_peers(void)
{
    const uint64_t now = glue_now_us();
    if (owly_mc.peer_log_us && now - owly_mc.peer_log_us < 5000000u)
        return;
    owly_mc.peer_log_us = now;
    spin_lock(&owly_link_lock);
    const struct owly_native_link *l = &owly_link_state;
    IOLog("OWLY mc: ch %u home=%d present=%d follow=%u data_ch=%u rooted=%d "
          "ok6/44/149=%d%d%d slots=0x%04x visits=%llu\n", (unsigned)owly_mc.channel,
          owly_mc.home, owly_mc.present, (unsigned)owly_mc.last_follow,
          (unsigned)owly_mc.last_data_ch, owly_mc.last_rooted, owly_mc_channel_ok(6),
          owly_mc_channel_ok(44), owly_mc_channel_ok(149), (unsigned)owly_mc.slots,
          (unsigned long long)owly_mc.visits);
    IOLog("OWLY peers: ch %u clock ok=%llu outlier=%llu reset=%llu not_root=%llu "
          "no_countdown=%llu\n", (unsigned)l->channel,
          (unsigned long long)l->clock_ok, (unsigned long long)l->clock_outlier,
          (unsigned long long)l->clock_reset, (unsigned long long)l->clock_not_root,
          (unsigned long long)l->clock_no_countdown);
    for (unsigned i = 0; i < OWLY_LINK_PEERS; i++) {
        const struct owly_link_peer *p = &l->peers[i];
        char seq[17];
        if (!p->used || now < p->last_rx_us || now - p->last_rx_us > 2000000u)
            continue;
        for (unsigned j = 0; j < 16; j++)
            seq[j] = p->channels[j] == 6 ? '6' : p->channels[j] == 44 ? '4' :
                     p->channels[j] == 149 ? '9' : '.';
        seq[16] = 0;
        IOLog("OWLY peer ..%02x:%02x master ..%02x:%02x%s clock=%u/%u rssi=%d heard=%llums seq=%s\n",
              p->mac[4], p->mac[5], p->master[4], p->master[5],
              !memcmp(p->master, p->mac, 6) ? " (self)" :
              !memcmp(p->master, l->local, 6) ? " (us)" : "",
              (unsigned)p->clock_valid, (unsigned)p->consistent, (int)p->rssi,
              (unsigned long long)((now - p->last_rx_us) / 1000u), seq);
    }
    spin_unlock(&owly_link_lock);
}

static void owly_mc_work_run(struct wiphy *wiphy, struct wiphy_work *work)
{
    (void)work;
    lockdep_assert_wiphy(wiphy);
    if (!glue.up)
        return;
    if (!owly_mc_should_run()) {
        const bool was = owly_mc.enabled;
        const uint64_t t = glue_now_us();
        if (!owly_mc.peer_log_us || t - owly_mc.peer_log_us >= 5000000u) {
            struct rtw89_mlme_status st;
            rtw89_mlme_get_status(&st);
            owly_mc.peer_log_us = t;
            IOLog("OWLY mc off: vif=%d bound=%d blocked=%d err=%d attempts=%u binds=%u "
                  "state=%d owned=%d freq=%u shared=%d scanning=%d requested=%d disabled=%d\n",
                  owly_core04c_vif != NULL, owly_radio_is_bound(&owly_radio_state),
                  owly_radio_state.blocked, owly_radio_state.last_error,
                  (unsigned)owly_radio_state.attempts, (unsigned)owly_radio_state.binds,
                  (int)st.state, st.awdl_channel_owned, (unsigned)st.freq,
                  rtw89_mlme_awdl_shared_chanctx() != NULL, glue.scanning,
                  owly_sync_state.requested, owly_sync_state.explicitly_disabled);
        }
        owly_mc_stop();
        if (was)
            owly_sync_recheck();
        wiphy_delayed_work_queue(wiphy, &owly_mc_work, msecs_to_jiffies(250));
        return;
    }
    if (!owly_mc.enabled) {
        struct rtw89_mlme_status st;
        rtw89_mlme_get_status(&st);
        owly_mc.enabled = true;
        if (!owly_mc.channel)
            owly_mc.channel = st.freq == 5745 ? 149 : st.freq == 5220 ? 44 : 6;
        owly_mc.home = owly_mc_freq(owly_mc.channel) == st.freq;
        owly_mc.root_us = glue_now_us(); /* 10 s to hear a root here first */
        IOLog("OWLY multichannel: on, AP on %u MHz, AWDL visits ch %u\n",
              (unsigned)st.freq, (unsigned)owly_mc.channel);
        owly_sync_recheck(); /* the bound channel is now ch 6 */
    }
    owly_mc_log_peers();
    if (glue.scanning) {
        /* AWDL stays bound across a scan, as in single-channel mode. */
        owly_mc_leave();
        wiphy_delayed_work_queue(wiphy, &owly_mc_work, msecs_to_jiffies(50));
        return;
    }
    const bool wanted = owly_sync_state.requested && !owly_sync_state.explicitly_disabled;
    uint16_t seq, social_slots = 0;
    uint32_t phase, until;
    unsigned peers = 0;
    bool busy;
    const uint64_t now = glue_now_us();
    spin_lock(&owly_link_lock);
    const bool rooted = owly_link_clock(&owly_link_state, now, &seq, &phase,
                                        &social_slots, &peers);
    /* Where to be: the root's main channel, else the peers' own. */
    const uint8_t data_ch = owly_link_data_channel(&owly_link_state, now);
    const uint8_t follow = data_ch ? data_ch :
                           rooted ? owly_link_follow_channel(&owly_link_state, now) :
                                    owly_link_peer_channel(&owly_link_state, now);
    owly_mc.last_follow = follow;
    owly_mc.last_data_ch = data_ch;
    owly_mc.last_rooted = rooted;
    busy = owly_link_data_busy(&owly_link_state, now);
    const uint64_t data_rx = owly_link_state.data_rx_admitted;
    spin_unlock(&owly_link_lock);
    /* A peer sending us data (a TLS handshake, a transfer) needs the
     * slots as much as our own queue does. */
    if (data_rx != owly_mc.data_rx_seen) {
        owly_mc.data_rx_seen = data_rx;
        owly_mc.data_rx_us = now;
    }
    if (owly_mc.data_rx_us && now - owly_mc.data_rx_us < 2000000u)
        busy = true;
    const bool heard = rooted || peers;
    /* Go where the followed root's domain spends most of its slots (Apple
     * devices on another network mostly sit on 149). Moving drops the link
     * state, so move at most every 5 s, and fall back to discovery on ch 6
     * only after 10 s without hearing a root on the chosen channel. */
    if (heard)
        owly_mc.root_us = now;
    uint8_t want_ch = owly_mc.channel;
    if (follow && follow != owly_mc.channel)
        want_ch = follow;
    else if (!heard && owly_mc.channel != 6 && now - owly_mc.root_us > 10000000u)
        want_ch = 6;
    if (want_ch != owly_mc.channel && owly_mc_channel_ok(want_ch) &&
        (!owly_mc.moved_us || now - owly_mc.moved_us >= 5000000u)) {
        IOLog("OWLY multichannel: ch %u -> ch %u (%s)\n", (unsigned)owly_mc.channel,
              (unsigned)want_ch, rooted ? "root's main channel" :
              heard ? "peers' main channel" : "nobody heard: discovery");
        owly_mc_leave();
        owly_mc.channel = want_ch;
        owly_mc.moved_us = now;
        owly_mc.root_us = now; /* a grace period to hear the root there */
        owly_mc.root_slots = 0;
        owly_sync_recheck(); /* rebinds AWDL to the new channel */
        wiphy_delayed_work_queue(wiphy, &owly_mc_work, usecs_to_jiffies(1000));
        return;
    }
    {
        struct rtw89_mlme_status st;
        rtw89_mlme_get_status(&st);
        const bool home = owly_mc_freq(owly_mc.channel) == st.freq;
        if (home != owly_mc.home) {
            if (home)
                owly_mc_leave(); /* the AP's channel is the AWDL channel */
            owly_mc.home = home;
            owly_sync_recheck();
        }
    }
    if (owly_mc.home) {
        /* Single channel, as before multichannel: AWDL all the time. */
        owly_mc.slots = 0;
        owly_sync_state.presence_slots = 0;
        wiphy_delayed_work_queue(wiphy, &owly_mc_work, msecs_to_jiffies(250));
        return;
    }
    /* The root is heard only during our visits: keep its slots through a
     * short gap instead of resetting the plan every time it goes quiet. */
    if (rooted && social_slots)
        owly_mc.root_slots = social_slots;
    else if (!rooted && owly_mc.root_slots && now - owly_mc.root_us <= 3000000u)
        social_slots = owly_mc.root_slots;
    const uint16_t slots = owly_mc_pick_slots(social_slots, peers, busy);
    if (slots != owly_mc.slots &&
        (!owly_mc.slot_log_us || now - owly_mc.slot_log_us >= 5000000u)) {
        owly_mc.slot_log_us = now;
        IOLog("OWLY multichannel: ch %u slots 0x%04x (root's slots here 0x%04x, %u peer(s)%s)\n",
              (unsigned)owly_mc.channel, (unsigned)slots, (unsigned)social_slots, peers,
              busy ? ", data" : "");
    }
    owly_mc.slots = slots;
    owly_sync_state.presence_slots = slots;
    const unsigned slot = owly_mc_slot(seq, phase, &until);
    const uint32_t lead = owly_mc.lead_us ? owly_mc.lead_us : OWLY_MC_LEAD_US;
    const bool want = wanted && owly_mc_want_social(slots, slot, until, lead);
    if (want != owly_mc.present) {
        if (want)
            owly_mc_enter();
        else
            owly_mc_leave();
        owly_sync_recheck();
    }
    uint64_t delay = wanted ? owly_mc_next_check_us(until, lead) : 250000u;
    const uint64_t spent = glue_now_us() - now;
    delay = delay > spent + 1000u ? delay - spent : 1000u;
    wiphy_delayed_work_queue(wiphy, &owly_mc_work, usecs_to_jiffies((unsigned)delay));
}

/* Re-evaluate soon: sync enabled, link state changed. */
static void owly_mc_kick(void)
{
    if (glue.up && !owly_mc.off)
        wiphy_delayed_work_queue(glue_hw()->wiphy, &owly_mc_work, 0);
}
#endif

static int owly_sync_submit(struct ieee80211_channel *ch,const uint8_t *p,size_t n,bool data)
{
    struct ieee80211_hw *hw=glue_hw();
    struct ieee80211_supported_band *band;
    struct ieee80211_tx_info *info;
    struct sk_buff *skb;
    unsigned int rate;
    lockdep_assert_wiphy(hw->wiphy);
    if(!ch || owly_awdl_away())return -EBUSY;
    band=hw->wiphy->bands[ch->band];
    if (!band || !owly_core04c_vif || n<24 || n>OWLY_SYNC_FRAME_MAX)
        return -EOPNOTSUPP;
#if !defined(OWLY_NATIVE_PEER_DATA) || !OWLY_NATIVE_PEER_DATA
    struct rtw89_m80211_local *local=hw_to_local(hw);
    if (!local->ops->tx)
        return -EOPNOTSUPP;
#else
    struct rtw89_dev *rtwdev=hw->priv;
    struct rtw89_vif *vif=vif_to_rtwvif(owly_core04c_vif);
    if (!vif->dlink_pool.next || !vif->dlink_pool.prev || list_empty(&vif->dlink_pool))
        return -ENOLINK;
#endif
    for (rate=0;rate<band->n_bitrates;rate++)
        if (band->bitrates[rate].bitrate==60) break;
    if (rate==band->n_bitrates) return -EOPNOTSUPP;
    skb=dev_alloc_skb(hw->extra_tx_headroom+n);
    if (!skb) return -ENOMEM;
    skb_reserve(skb,hw->extra_tx_headroom);
    memcpy(skb_put(skb,(unsigned int)n),p,n);
#if defined(RTW89_MACOS) && defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    if(!owly_radio_assign_sequence(&owly_radio_tx_sequence,skb->data,n)) {
        kfree_skb(skb);return -EINVAL;
    }
    static unsigned long sequence_samples;
    const unsigned long sample=++sequence_samples;
    if(sample<=8ul || !(sample&(sample-1ul)))
        IOLog("OWLY radio TX sequence: count=%lu kind=%s wifi_seq=%u ch=%u bytes=%lu\n",
            sample,data ? "data" : "action",(unsigned)(get_unaligned_le16(skb->data+22)>>4),
            (unsigned)ch->hw_value,(unsigned long)n);
#endif
    info=IEEE80211_SKB_CB(skb); memset(info,0,sizeof(*info));
    const bool unicast=!(p[4]&1u);
    info->flags=IEEE80211_TX_INTFL_DONT_ENCRYPT | IEEE80211_TX_CTL_NO_ACK |
                IEEE80211_TX_CTL_INJECTED;
    if(data) info->flags|=IEEE80211_TX_CTL_REQ_TX_STATUS;
    if(unicast) info->flags&=~IEEE80211_TX_CTL_NO_ACK;
    info->control.vif=owly_core04c_vif;
    info->control.rates[0].idx=(s8)rate;
    info->control.rates[0].count=unicast ? 3 : 1;
    info->band=ch->band;
    /* Match mac80211 selection for this fully formed frame: management
     * uses VO/7, non-QoS data uses BE/0. Never invent a QoS TID for data
     * whose supplied 802.11 header has no QoS control field. */
    const unsigned int ac=data ? IEEE80211_AC_BE : IEEE80211_AC_VO;
    info->hw_queue=owly_core04c_vif->hw_queue[ac];
    skb->priority=data ? 0 : 7; skb_set_queue_mapping(skb,ac);
    /* The injected descriptor uses a fixed legacy 6 Mbps rate on the
     * already-bound channel. The native queue needs the actual PCIe result. */
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    int qsel;
    int rc=rtw89_core_tx_write(rtwdev,owly_core04c_vif,
                                unicast ? owly_peer_tx_station(p+4) : NULL,skb,&qsel);
    if (rc) {
        ieee80211_free_txskb(hw,skb);
        return rc;
    }
#if defined(RTW89_MACOS)
    if(data && unicast) {
        size_t size;const uint8_t *ip=owly_observe_frame_ip(p,n,&size);
        owly_unicast_note(0,ip,size,0,false); /* DMA submission, not peer receipt */
    }
#endif
    rtw89_core_tx_kick_off(rtwdev,qsel);
#else
    struct ieee80211_tx_control control={.sta=NULL};
    local->ops->tx(hw,&control,skb);
#endif
    return 0;
}

static void owly_sync_work_run(struct wiphy *wiphy,struct wiphy_work *work)
{
    struct ieee80211_channel *ch;
    size_t length=0;
    int rc;
    (void)work;
    lockdep_assert_wiphy(wiphy);
    ch=owly_sync_bound_channel();
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    spin_lock(&owly_link_lock);
#endif
    uint64_t now=glue_now_us();
    owly_sync_reconcile(&owly_sync_state,ch && !owly_awdl_away(),
                        ch ? (uint8_t)ch->hw_value : 0,now);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    /* Use one sample under the same lock for reconciliation and snapshot.
     * A later timestamp followed by an older one would expire the TX queue. */
    owly_link_update_locked(ch,now);
    spin_unlock(&owly_link_lock);
    owly_peer_tick(ch,now);
    /* Re-sample: peer/BA H2Cs can cross an AW boundary. */
    now=glue_now_us();
    owly_sync_reconcile(&owly_sync_state,ch && !owly_awdl_away(),ch ? (uint8_t)ch->hw_value : 0,now);
    spin_lock(&owly_link_lock);
    owly_link_update_locked(ch,now);
    (void)owly_link_window(&owly_link_state,now,&owly_sync_state.peer_clock);
    owly_sync_state.have_master_election=owly_link_root_election(
        &owly_link_state,now,owly_sync_state.master_election);
    owly_sync_state.shared_slots=owly_link_shared_slots(&owly_link_state,now);
    owly_sync_state.hold_for_peer=!owly_link_action_tx_ready(&owly_link_state,now);
    if (owly_sync_state.pending_mi.length) {
        const uint8_t *destination=owly_sync_state.pending_mi_destination;
        owly_sync_state.pending_mi_ready=(destination[0]&1u) ?
            !owly_sync_state.hold_for_peer :
            owly_link_unicast_action_tx_ready(&owly_link_state,destination,now);
    }
    spin_unlock(&owly_link_lock);
#endif
    if (!owly_sync_state.active) return;
    rc=owly_sync_frame(&owly_sync_state,now,owly_sync_txbuf,
                       sizeof(owly_sync_txbuf),&length);
    if (rc==1) {
        rc=owly_sync_submit(ch,owly_sync_txbuf,length,false);
        owly_sync_result(&owly_sync_state,rc);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        if (owly_sync_state.last_native_mi) {
            const uint64_t count=owly_sync_state.native_mi_handed_off;
            if (count<=4 || rc || !(count%64))
                IOLog("OWLY native MI: handoff=%llu unicast=%u ch=%u bytes=%u rc=%d "
                      "remote_master_ch=%u shared_slots=0x%04x\n",
                      (unsigned long long)count,(unsigned)((owly_sync_txbuf[4]&1u)==0),
                      (unsigned)owly_sync_state.channel,(unsigned)length,rc,
                      owly_sync_state.peer_clock.remote ?
                          (unsigned)owly_sync_state.peer_clock.master_channel : 0u,
                      (unsigned)owly_sync_state.shared_slots);
        }
#endif
        if (owly_sync_state.handed_off<=4 || rc || !(owly_sync_state.handed_off%64))
            IOLog("OWLY software AWDL: action handoff=%llu failed=%llu ch=%u bytes=%u rc=%d (NOT RF confirmation)\n",
                  (unsigned long long)owly_sync_state.handed_off,
                  (unsigned long long)owly_sync_state.failed,
                  (unsigned)owly_sync_state.channel,(unsigned)length,rc);
    }
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    /* Each frame still needs its own valid transmit window. A broadcast
     * MIF for another peer must not hold an otherwise ready reply. */
    for(unsigned int i=0;i<4 && owly_sync_state.active;i++) {
        unsigned int offset;
        uint64_t generation;
        spin_lock(&owly_link_lock);
        rc=owly_link_next_tx(&owly_link_state,glue_now_us(),
                             owly_sync_state.broadcast_mif_submitted,owly_link_txbuf,
                             sizeof(owly_link_txbuf),&length,&offset,&generation);
        spin_unlock(&owly_link_lock);
        if(rc!=1)break;
        rc=owly_sync_submit(ch,owly_link_txbuf,length,true);
        spin_lock(&owly_link_lock);
        owly_link_tx_result(&owly_link_state,offset,generation,rc);
        spin_unlock(&owly_link_lock);
        if(rc)break;
    }
#endif
    if (owly_sync_state.active) {
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        spin_lock(&owly_link_lock);
        const bool queued=owly_link_state.count!=0;
        spin_unlock(&owly_link_lock);
        const unsigned poll_delay=owly_awdl_poll_delay_us(glue_now_us(),
            owly_sync_state.due_us,owly_sync_state.mif_due_us,
            queued,owly_sync_state.pending_mi.length!=0,
            owly_sync_state.hold_for_peer,owly_sync_state.peer_clock.until_next_tu);
#else
        const unsigned poll_delay=16384;
#endif
        wiphy_delayed_work_queue(wiphy,&owly_sync_work,usecs_to_jiffies(poll_delay));
    }
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    /* Channel changes belong to separate serialized wiphy work, never RX
     * or the selected TX transaction. Bound the policy to four checks/s. */
    const uint64_t policy_now=glue_now_us();
    if (policy_now<owly_idle_policy_us || policy_now-owly_idle_policy_us>=250000u) {
        owly_idle_policy_us=policy_now;
        wiphy_work_queue(wiphy,&owly_radio_work);
    }
#endif
}
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
static void owly_link_update_locked(struct ieee80211_channel *ch,uint64_t now)
{
    if(owly_sync_state.explicitly_disabled)ch=NULL;
    owly_link_reconcile(&owly_link_state,ch!=NULL,
        ch && owly_core04c_vif ? owly_core04c_vif->addr : NULL,
        ch ? (uint8_t)ch->hw_value : 0,now);
    owly_link_state.sync_enabled=ch && owly_sync_configured(&owly_sync_state);
    owly_link_state.starting=ch && !owly_sync_state.blocked && !owly_link_state.sync_enabled;
    owly_link_set_tx_paused(&owly_link_state,ch && owly_awdl_away(),now);
    if(owly_link_state.sync_enabled && (owly_sync_state.native.committed&OWLY_CFG_SYNC) &&
       owly_sync_state.native.sync.state)
        owly_link_prefer(&owly_link_state,owly_sync_state.native.sync.master);
}
static bool owly_scan_protect_locked(bool *data_busy)
{
    struct ieee80211_channel *ch=owly_sync_bound_channel();
    struct owly_link_window window={0};
    bool busy=false;
    if(data_busy)*data_busy=false;
    if(!ch || !owly_sync_configured(&owly_sync_state))return false;
    const uint64_t now=glue_now_us();
    spin_lock(&owly_link_lock);
    owly_link_update_locked(ch,now);
    (void)owly_link_window(&owly_link_state,now,&window);
    busy=owly_link_data_busy(&owly_link_state,now);
    spin_unlock(&owly_link_lock);
    if(data_busy)*data_busy=busy;
    return busy || window.peers!=0;
}
int rtw89_glue_native_window(struct owly_link_window *out)
{
    struct ieee80211_channel *ch;
    if(!out)return -EINVAL;
    memset(out,0,sizeof(*out));
    if(!glue.active || !glue.probed)return -ENODEV;
    mutex_lock(&glue.cmd_lock);wiphy_lock(glue_hw()->wiphy);
    /* A bound frontend stays attached during the scan. Its snapshot has
     * no RF window until the scan releases the channel. */
    ch=owly_sync_bound_channel();
    spin_lock(&owly_link_lock);
    const uint64_t now=glue_now_us();
    owly_link_update_locked(ch,now);
    (void)owly_link_window(&owly_link_state,now,out);
    const int rc=owly_sync_state.explicitly_disabled ? -ECANCELED : ch ? 0 : -ENETDOWN;
    spin_unlock(&owly_link_lock);
    wiphy_unlock(glue_hw()->wiphy);mutex_unlock(&glue.cmd_lock);
    return rc;
}
int rtw89_glue_native_output(const uint8_t *eth,size_t n)
{
    struct ieee80211_channel *ch;int rc;
    if(!glue.active || !glue.probed)return -ENODEV;
    mutex_lock(&glue.cmd_lock);wiphy_lock(glue_hw()->wiphy);
    ch=owly_sync_bound_channel();
    spin_lock(&owly_link_lock);
    const uint64_t now=glue_now_us();
    owly_link_update_locked(ch,now);
    rc=owly_link_enqueue(&owly_link_state,eth,n,now);
    spin_unlock(&owly_link_lock);
    if(!rc && !owly_sync_state.template_len)
        memcpy(owly_sync_state.mac,owly_core04c_vif->addr,ETH_ALEN);
    if(!rc && owly_sync_note_tx(&owly_sync_state,eth,n)) {
        /* Publish a newly learned local host at the next opportunity. A
         * native ARPA record still takes precedence when building the MI. */
        if(owly_sync_state.mif_due_us>now)
            owly_sync_state.mif_due_us=now;
        IOLog("OWLY local host: learned own mDNS SRV/AAAA identity; MIF ARPA enabled\n");
    }
    /* queue(...,0) cancels the idle timer and wakes the real wiphy worker. */
    if(!rc && owly_sync_state.active)
        wiphy_delayed_work_queue(glue_hw()->wiphy,&owly_sync_work,0);
    wiphy_unlock(glue_hw()->wiphy);mutex_unlock(&glue.cmd_lock);
    return rc;
}
#endif
#endif

bool rtw89_glue_awdl_scan_protect(bool *data_busy)
{
    if(data_busy)*data_busy=false;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    if(!glue.active || !glue.probed)return false;
    mutex_lock(&glue.cmd_lock);wiphy_lock(glue_hw()->wiphy);
    const bool protect=owly_scan_protect_locked(data_busy);
    wiphy_unlock(glue_hw()->wiphy);mutex_unlock(&glue.cmd_lock);
    return protect;
#else
    return false;
#endif
}
#include "owly_awdl_ht.h"
int rtw89_glue_awdl_ht_capability(void *output,size_t capacity)
{
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    /* Native configure queries capabilities before SET117/151. Require a
     * probed radio, not an active AW or a discovered peer. Use the common
     * subset of both supported social bands so the IE stays valid on SCC
     * channel changes and does not depend on an AP association.
     */
    if (!output || capacity<OWLY_AWDL_HT_REPLY_BYTES) return -EINVAL;
    if (!glue.active || !glue.probed) return -ENODEV;
    mutex_lock(&glue.cmd_lock);wiphy_lock(glue_hw()->wiphy);
    bool supported=false,valid=true;uint8_t mcs=255,density=0;
    for (unsigned i=NL80211_BAND_2GHZ;i<=NL80211_BAND_5GHZ;i++) {
        const struct ieee80211_supported_band *band=glue_hw()->wiphy->bands[i];
        if (!band) continue;
        supported=true;
        if (!band->ht_cap.ht_supported) {valid=false;break;}
        mcs &= band->ht_cap.mcs.rx_mask[0];
        if (band->ht_cap.ampdu_density>density) density=band->ht_cap.ampdu_density;
    }
    const int rc=supported && valid && owly_awdl_build_ht(output,capacity,mcs,density) ?
        0:-EOPNOTSUPP;
    wiphy_unlock(glue_hw()->wiphy);mutex_unlock(&glue.cmd_lock);
    return rc;
#else
    (void)output;(void)capacity;return -EOPNOTSUPP;
#endif
}
int rtw89_glue_awdl_config(bool set,unsigned number,void *data)
{
#if defined(OWLY_AWDL_SOFTWARE_SYNC) && OWLY_AWDL_SOFTWARE_SYNC
    int rc;
    struct ieee80211_channel *ch;
    uint32_t prior_period;
    const bool stopping=set && number==134 && data && ((struct owly_cfg_sync *)data)->state==0;
    if (!glue.active || !glue.probed) return -ENODEV;
    mutex_lock(&glue.cmd_lock); wiphy_lock(glue_hw()->wiphy);
    /* These are software configuration writes. A temporary off-channel
     * scan does not invalidate a real SCC bind or require a fresh peer. */
    ch=owly_sync_bound_channel();
    prior_period=owly_sync_state.native.psf_period_ms;
    if (!ch && !stopping) rc=-ENETDOWN;
    else rc=owly_config_request(&owly_sync_state.native,set,number,data,
                                owly_core04c_vif ? owly_core04c_vif->addr : NULL,
                                ch ? (uint8_t)ch->hw_value : 0);
    if (!rc && set) {
        if (owly_core04c_vif) memcpy(owly_sync_state.mac,owly_core04c_vif->addr,6);
        if (number==135)
            __atomic_store_n(&owly_cfg_rssi_floor,owly_sync_state.native.peer_rssi,__ATOMIC_RELEASE);
        if (number==134 && !owly_sync_state.native.sync.state) {
            owly_sync_request(&owly_sync_state,false);
            owly_sync_pause(false);
        } else {
            if (number==116 && owly_sync_state.active &&
                prior_period!=owly_sync_state.native.psf_period_ms)
                owly_sync_state.due_us=glue_now_us();
            owly_sync_recheck();
        }
    }
    wiphy_unlock(glue_hw()->wiphy); mutex_unlock(&glue.cmd_lock);
    return rc;
#else
    (void)set; (void)number; (void)data; return -EOPNOTSUPP;
#endif
}

int rtw89_glue_awdl_sync_template(const uint8_t *bytes,size_t length)
{
#if defined(OWLY_AWDL_SOFTWARE_SYNC) && OWLY_AWDL_SOFTWARE_SYNC
    int rc;
    if (!glue.active || !glue.probed) return -ENODEV;
    mutex_lock(&glue.cmd_lock); wiphy_lock(glue_hw()->wiphy);
    if (!owly_core04c_vif || !glue.up) rc=-ENETDOWN;
    else {
        rc=owly_sync_template(&owly_sync_state,bytes,length,owly_core04c_vif->addr);
        if (rc) rc=-EINVAL;
        if (!rc) {
            if (!length) owly_sync_pause(false);
            else owly_sync_recheck();
        }
    }
    wiphy_unlock(glue_hw()->wiphy); mutex_unlock(&glue.cmd_lock);
    return rc;
#else
    (void)bytes; (void)length; return -EOPNOTSUPP;
#endif
}

#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
int rtw89_glue_awdl_mi(bool automatic,const uint8_t destination[6],
                       const uint8_t *bytes,size_t length)
{
    if (!glue.active || !glue.probed) return -ENODEV;
    struct wiphy *wiphy=glue_hw()->wiphy;
    mutex_lock(&glue.cmd_lock);
    wiphy_lock(wiphy);
    const struct ieee80211_channel *ch=owly_sync_bound_channel();
    int rc=-ENETDOWN;
    if (ch || (automatic && glue.up && owly_core04c_vif)) {
        rc=owly_sync_mi(&owly_sync_state,automatic,destination,bytes,length,
                        owly_core04c_vif->addr,ch ? (uint8_t)ch->hw_value : 0,glue_now_us());
        if (rc==OWLY_MI_BUSY) rc=-ENOBUFS;
        else if (rc) rc=-EINVAL;
        else owly_sync_recheck();
    }
    wiphy_unlock(wiphy);
    mutex_unlock(&glue.cmd_lock);
    return rc;
}
#endif

static int owly_set_sync_enabled(bool enabled,bool vif_disabled)
{
    (void)vif_disabled;
#if defined(OWLY_AWDL_SOFTWARE_SYNC) && OWLY_AWDL_SOFTWARE_SYNC
    int rc=0;
    if (!glue.active || !glue.probed) return enabled ? -ENODEV : 0;
    mutex_lock(&glue.cmd_lock); wiphy_lock(glue_hw()->wiphy);
    if (enabled && (!owly_core04c_vif || !glue.up)) rc=-ENETDOWN;
    else {
        owly_sync_request(&owly_sync_state,enabled);
        if (!enabled) {
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
            if (vif_disabled)
                memset(&owly_sync_state.auto_mi,0,sizeof(owly_sync_state.auto_mi));
#endif
            owly_sync_pause(false);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
            if (vif_disabled) rtw89_mlme_awdl_release_channel();
#endif
        } else {
            owly_radio_maybe_attach();
            owly_sync_recheck();
#ifdef OWLY_MC_BUILT
            owly_mc_kick();
#endif
        }
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
        IOLog("OWLY AWDL sync request: enabled=%u vif_disabled=%u broadcast_bytes=%lu\n",
              (unsigned)enabled,(unsigned)vif_disabled,(unsigned long)owly_sync_state.auto_mi.length);
#endif
    }
    wiphy_unlock(glue_hw()->wiphy); mutex_unlock(&glue.cmd_lock);
    return rc;
#else
    (void)enabled; return -EOPNOTSUPP;
#endif
}

int rtw89_glue_awdl_sync_enable(bool enabled)
{
    return owly_set_sync_enabled(enabled,false);
}

#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
int rtw89_glue_awdl_vif_disable(void)
{
    return owly_set_sync_enabled(false,true);
}
#endif

int rtw89_glue_awdl_sync_status(struct rtw89_glue_awdl_sync_status *out)
{
    if (!out) return -EINVAL;
    memset(out,0,sizeof(*out));
#if defined(OWLY_AWDL_SOFTWARE_SYNC) && OWLY_AWDL_SOFTWARE_SYNC
    if (!glue.active || !glue.probed) return -ENODEV;
    mutex_lock(&glue.cmd_lock); wiphy_lock(glue_hw()->wiphy);
    const struct ieee80211_channel *ch=owly_sync_bound_channel();
    out->built=true; out->requested=owly_sync_state.requested;
    out->enabled=ch && owly_sync_configured(&owly_sync_state);
    out->scan_paused=out->enabled && glue.scanning;
    out->active=out->enabled && !out->scan_paused && owly_sync_state.active;
    out->blocked=owly_sync_state.blocked;
    out->has_template=owly_sync_state.template_len!=0;
    out->channel=ch ? (uint8_t)ch->hw_value : 0; out->staged=owly_sync_state.staged;
    out->handed_off=owly_sync_state.handed_off; out->failed=owly_sync_state.failed;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    out->native_mi_handed_off=owly_sync_state.native_mi_handed_off;
#endif
    out->skipped=owly_sync_state.skipped;
    out->config_mask=owly_sync_state.native.committed;
    out->master_channel=owly_sync_state.native.master_channel;
    out->sync_role=owly_sync_state.native.sync.state;
    out->psf_period_ms=owly_sync_state.native.psf_period_ms ? owly_sync_state.native.psf_period_ms : 110;
    out->election_id=owly_sync_state.native.election_id;
    out->peer_rssi=(owly_sync_state.native.committed&OWLY_CFG_RSSI) ? owly_sync_state.native.peer_rssi : -128;
    out->rejected_rssi=__atomic_load_n(&owly_cfg_rssi_drops,__ATOMIC_RELAXED);
#ifdef OWLY_MC_BUILT
    out->mc_enabled=owly_mc.enabled; out->mc_present=owly_mc.present;
    out->mc_slots=owly_mc.slots; out->mc_visits=owly_mc.visits;
    out->mc_null_failures=owly_mc.null_failures; out->mc_max_switch_us=owly_mc.max_switch_us;
#endif
    wiphy_unlock(glue_hw()->wiphy); mutex_unlock(&glue.cmd_lock);
#endif
    return 0;
}

bool rtw89_glue_awdl_service_ready(void)
{
#if defined(OWLY_AWDL_SOFTWARE_SYNC) && OWLY_AWDL_SOFTWARE_SYNC
    bool ready, scanning;
    if (!glue.active || !glue.probed) return false;
    mutex_lock(&glue.cmd_lock);
    wiphy_lock(glue_hw()->wiphy);
    /* SET120 prepares the service on a real binding. The separate radio
     * scheduler pauses TX while a connected scan is in progress. */
    ready = owly_sync_bound_channel() != NULL;
    scanning = ready && glue.scanning;
    wiphy_unlock(glue_hw()->wiphy);
    mutex_unlock(&glue.cmd_lock);
    if (scanning)
        IOLog("OWLY AWDL service: preserved bound interface for SET120 during scan\n");
    return ready;
#else
    return false;
#endif
}

/* OWLY_CORE04F_TX_ONCE_BEGIN:
 * At most ONE attempted handoff per boot (even across radio resets).
 * ONLY when attached to an eligible primary 2.4GHz channel (1-11).
 * Does not schedule off-channel work, retry, or send protocol-valid PSF.
 * All callers hold wiphy mutex. Handoff != RF proof.
 */
#if defined(RTW89_AWDL_CORE04F_ONE_SHOT) && RTW89_AWDL_CORE04F_ONE_SHOT
static bool owly_core04f_attempted;
static void owly_core04f_try_once(void)
{
    struct ieee80211_chanctx_conf *primary;
    struct ieee80211_channel *chan;
    struct ieee80211_hw *hw;
    unsigned char pkt[OWLY_CORE04F_PROBE_LEN];
    int ret;

    if (owly_core04f_attempted || !glue.up || glue.scanning ||
        !owly_core04d_assigned || !owly_core04c_vif || !owly_core04d_ctx)
        return;
    hw = glue_hw();
    lockdep_assert_wiphy(hw->wiphy);
    primary = rtw89_mlme_awdl_shared_chanctx();
    if (!primary || primary != owly_core04d_ctx ||
        owly_core04c_vif->bss_conf.chanctx_conf != primary)
        return;
    chan = primary->def.chan;
    if (!chan) {
        IOLog("OWLY core04f R1: no TX; channel context has no control channel\n");
        return;
    }
    /* Respect the current wiphy flags. World-domain NO_IR on 5GHz is never
     * overridden. Also deny 2.4GHz channels 12-14 and any invalid channel.
     * The 2.4GHz AP must be the primary connected station's existing channel.
     */
    if (!owly_core04f_r1_chan_eligible(chan->center_freq,
                                      chan->band == NL80211_BAND_2GHZ,
                                      chan->flags,
                                      IEEE80211_CHAN_DISABLED | IEEE80211_CHAN_NO_IR)) {
        IOLog("OWLY core04f R1: no TX; freq=%u MHz band=%u flags=0x%x NO_IR=%u DISABLED=%u (requires eligible 2.4GHz AP)\n",
              (unsigned)chan->center_freq, (unsigned)chan->band, (unsigned)chan->flags,
              !!(chan->flags & IEEE80211_CHAN_NO_IR),
              !!(chan->flags & IEEE80211_CHAN_DISABLED));
        return;
    }
    if (!owly_core04f_build_probe(pkt, sizeof(pkt), owly_core04c_vif->addr))
        return;
    owly_core04f_attempted = true; /* latch BEFORE handing buffer to driver */
    IOLog("OWLY core04f R1: attempting ONE 40-byte diagnostic action frame %u MHz; no TLVs\n",
          (unsigned)chan->center_freq);
    ret = rtw89_mlme_awdl_submit_action(owly_core04c_vif, chan, pkt, sizeof(pkt));
    IOLog("OWLY core04f: mgmt bridge returned %d (0 = handoff, NOT RF confirmation)\n", ret);
}
#endif
/* OWLY_CORE04F_TX_ONCE_END */

static int glue_up_locked(void);

int rtw89_glue_up(void)
{
    int ret;

    if (!glue.probed)
        return -ENODEV;
    mutex_lock(&glue.cmd_lock);
    ret = glue_up_locked();
    mutex_unlock(&glue.cmd_lock);
    return ret;
}

static int glue_up_locked(void)
{
    struct rtw89_m80211_local *local;
    struct ieee80211_hw *hw;
    unsigned int filter = 0;
    int ret;

    if (glue.up)
        return 0;

#if defined(RTW89_MACOS) && defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    /* Reset before start() enables RX and before wiphy TX is available. */
    memset(&owly_radio_rx_clock,0,sizeof(owly_radio_rx_clock));
    memset(&owly_radio_tx_sequence,0,sizeof(owly_radio_tx_sequence));
#endif

    hw = glue_hw();
    local = hw_to_local(hw);
    rtw89_m80211_set_glue(hw, &glue_m80211_ops, NULL);

    glue.vif = rtw89_m80211_vif_alloc(hw, NL80211_IFTYPE_STATION,
                                      glue.have_mac ? glue.mac : hw->wiphy->perm_addr);
    if (!glue.vif)
        return -ENOMEM;

    /* The driver enables the chip's interrupt mask inside start(). */
    if (glue.plat.irq_enable)
        glue.plat.irq_enable(glue.plat.ctx, true);

    /* mac80211 calls every driver op with the wiphy mutex held. */
    wiphy_lock(hw->wiphy);
    ret = local->ops->start(hw);
    if (ret)
        goto err_unlock;

    ret = local->ops->add_interface(hw, glue.vif);
    if (ret) {
        local->ops->stop(hw, false);
        goto err_unlock;
    }
    rtw89_m80211_vif_set_in_driver(glue.vif, true);
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
    /* Prior down/remove must have released every borrowed reference. */
    if (owly_radio_reset(&owly_radio_state) != OWLY_RADIO_OK) {
        ret = -EBUSY;
        rtw89_m80211_vif_set_in_driver(glue.vif, false);
        local->ops->remove_interface(hw, glue.vif);
        local->ops->stop(hw, false);
        goto err_unlock;
    }
    owly_idle_move_us=owly_idle_policy_us=0;
#endif
    /* OWLY_PHASE_P_OTHER_BSS_BEGIN
     * EXPERIMENTAL: explicitly request mac80211 to relax Address-1 matching.
     * Default OFF, leaving the original station RX filter untouched.
     * This changes hardware RX filter policy when enabled; it may affect
     * throughput, power management, and association. NOT an AirDrop fix. */
#if defined(RTW89_AWDL_RX_OTHER_BSS_TRIAL) && RTW89_AWDL_RX_OTHER_BSS_TRIAL
    filter = FIF_OTHER_BSS;
    local->ops->configure_filter(hw, FIF_OTHER_BSS, &filter, 0);
    IOLog("OWLY Phase P: FIF_OTHER_BSS trial requested (NOT proof register state)\n");
#else
    local->ops->configure_filter(hw, 0, &filter, 0);
#endif
    /* OWLY_PHASE_P_OTHER_BSS_END */
#if defined(RTW89_AWDL_VIF_STAGE) && RTW89_AWDL_VIF_STAGE
    /* New radio-up is a fresh trial, but attachment still requires a VIF
     * and connected primary context. A previously refused attach stays latched. */
    owly_core04e_r1_attach_attempted = false;
#endif
    rtw89_mlme_start(hw, glue.vif, glue_link_notify);
#if defined(RTW89_AWDL_VIF_STAGE) && RTW89_AWDL_VIF_STAGE
    rtw89_mlme_awdl_set_release_hook(owly_core04d_detach);
#endif
#ifdef OWLY_MC_BUILT
    rtw89_mlme_set_offchan_hook(owly_mc_end_hook);
#endif
#if defined(RTW89_AWDL_VIF_STAGE) && RTW89_AWDL_VIF_STAGE
    if (RTW89_AWDL_VIF_REGISTER) {
        int stage_rc = owly_core04c_vif_register(hw, NULL);
        if (stage_rc)
            IOLog("OWLY core04c: second VIF refused rc=%d; primary Wi-Fi preserved\n",
                  stage_rc);
    }
#endif
    wiphy_unlock(hw->wiphy);

    INIT_DELAYED_WORK(&glue.ppdu_flush_work, glue_ppdu_flush_work);
    glue.ppdu_flush = true;
    glue.up = true;
    rtw88_napi_post_poll = glue_napi_post_poll;
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
    owly_restore_awdl_vif(hw);
#endif
#ifdef OWLY_MC_BUILT
    owly_mc_kick();
#endif
    return 0;

err_unlock:
    wiphy_unlock(hw->wiphy);
    if (glue.plat.irq_enable)
        glue.plat.irq_enable(glue.plat.ctx, false);
    rtw89_m80211_vif_free(glue.vif);
    glue.vif = NULL;
    return ret;
}

static void glue_forget_network(void)
{
    glue.want.valid = false;
    glue.rejoining = false;
    memset(glue.want.pmk, 0, sizeof(glue.want.pmk));
    memset(glue.want.password, 0, sizeof(glue.want.password));
    glue.want.password_len = 0;
}

static void glue_down_locked(void);

void rtw89_glue_down(void)
{
    if (!glue.active)
        return;
    /* before the lock: the work takes it too */
    glue_forget_network();
    cancel_delayed_work_sync(&glue.rejoin_work);

    mutex_lock(&glue.cmd_lock);
    glue_down_locked();
    mutex_unlock(&glue.cmd_lock);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    owly_peer_drain_rx(); /* callbacks can re-enter cmd/wiphy */
#endif
}

static void glue_down_locked(void)
{
    struct rtw89_m80211_local *local;
    struct ieee80211_hw *hw;

    if (!glue.up)
        return;
    glue.up = false;
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    owly_peer_clear_delivery(); /* never wait while cmd_lock is held */
#endif
    rtw88_napi_post_poll = NULL;
    cancel_delayed_work_sync(&glue.ppdu_flush_work);

    hw = glue_hw();
    local = hw_to_local(hw);

    wiphy_lock(hw->wiphy);
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
    wiphy_work_cancel(hw->wiphy, &owly_radio_work);
#endif
#ifdef OWLY_MC_BUILT
    wiphy_delayed_work_cancel(hw->wiphy, &owly_mc_work);
    owly_mc_stop(); /* back on the AP's channel before anything stops */
#endif
#if defined(OWLY_SCC_SOCIAL_RX) && OWLY_SCC_SOCIAL_RX
    owly_scc_filter_set(false, 0); /* unwind before interface/radio stop */
#endif
    if (glue.scanning && local->ops->cancel_hw_scan)
        local->ops->cancel_hw_scan(hw, glue.vif);
#if defined(RTW89_AWDL_VIF_STAGE) && RTW89_AWDL_VIF_STAGE
    owly_core04d_detach(NULL);
#endif
    rtw89_mlme_stop();
#if defined(RTW89_AWDL_VIF_STAGE) && RTW89_AWDL_VIF_STAGE
    rtw89_mlme_awdl_set_release_hook(NULL);
#endif
#ifdef OWLY_MC_BUILT
    rtw89_mlme_set_offchan_hook(NULL);
#endif
#if defined(RTW89_AWDL_VIF_STAGE) && RTW89_AWDL_VIF_STAGE
    owly_core04c_vif_unregister(hw);
#endif
    rtw89_m80211_vif_set_in_driver(glue.vif, false);
    local->ops->remove_interface(hw, glue.vif);
    local->ops->stop(hw, false);
    wiphy_unlock(hw->wiphy);
    glue.scanning = false;

    if (glue.plat.irq_enable)
        glue.plat.irq_enable(glue.plat.ctx, false);

    rtw89_m80211_vif_free(glue.vif);
    glue.vif = NULL;
    /* the driver is stopped: nothing can still be using what was freed */
    rtw89_m80211_reap(hw, true);
}

int rtw89_glue_set_mac(const uint8_t mac[6])
{
    int ret = 0;

    if (!glue.probed)
        return -ENODEV;
    if (is_multicast_ether_addr(mac) || is_zero_ether_addr(mac))
        return -EINVAL;

    glue_forget_network();
    cancel_delayed_work_sync(&glue.rejoin_work);
    mutex_lock(&glue.cmd_lock);
    if (!glue.have_mac || !ether_addr_equal(glue.mac, mac)) {
        bool was_up = glue.up;

        /* the interface gets its address when it is added */
        glue_down_locked();
        memcpy(glue.mac, mac, ETH_ALEN);
        glue.have_mac = true;
        if (was_up)
            ret = glue_up_locked();
    }
    mutex_unlock(&glue.cmd_lock);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Scan                                                                */
/* ------------------------------------------------------------------ */

/* Probe request IEs per band: supported rates only for now. */
static const u8 glue_ies_2ghz[] = {
    WLAN_EID_SUPP_RATES, 8, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
    WLAN_EID_EXT_SUPP_RATES, 4, 0x30, 0x48, 0x60, 0x6c,
};
static const u8 glue_ies_5ghz[] = {
    WLAN_EID_SUPP_RATES, 8, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
};

bool rtw89_glue_scanning(void)
{
    return glue.scanning;
}

static int glue_scan_locked(const u8 *name, size_t name_len,
                            const u16 *want_freqs, size_t n_want);

int rtw89_glue_scan(void)
{
    int ret;

    if (!glue.active)
        return -ENETDOWN;
    mutex_lock(&glue.cmd_lock);
    ret = glue_scan_locked(NULL, 0, NULL, 0);
    mutex_unlock(&glue.cmd_lock);
    return ret;
}

int rtw89_glue_scan_for(const uint8_t *ssid, size_t ssid_len)
{
    int ret;

    if (!glue.active)
        return -ENETDOWN;
    if (!ssid_len || ssid_len > IEEE80211_MAX_SSID_LEN)
        return -EINVAL;
    mutex_lock(&glue.cmd_lock);
    ret = glue_scan_locked(ssid, ssid_len, NULL, 0);
    mutex_unlock(&glue.cmd_lock);
    return ret;
}

/*
 * A scan macOS asked for by name, by channel, or both.  Unlike the plain
 * scan this is never answered from what was heard earlier and never sliced:
 * it is asked for when something is expected to have just appeared.
 */
int rtw89_glue_scan_directed(const uint8_t *ssid, size_t ssid_len,
                             const uint16_t *freqs, size_t n_freqs)
{
    int ret;

    if (!glue.active)
        return -ENETDOWN;
    if (ssid_len > IEEE80211_MAX_SSID_LEN)
        return -EINVAL;
    mutex_lock(&glue.cmd_lock);
    ret = glue_scan_locked(ssid_len ? ssid : NULL, ssid_len, freqs, n_freqs);
    mutex_unlock(&glue.cmd_lock);
    return ret;
}

static int glue_scan_locked(const u8 *name, size_t name_len,
                            const u16 *want_freqs, size_t n_want)
{
    struct rtw89_m80211_local *local;
    struct ieee80211_scan_request *sreq;
    struct ieee80211_supported_band *sband;
    struct cfg80211_scan_request *req;
    struct cfg80211_ssid *ssid;
    struct ieee80211_hw *hw;
    unsigned int n_channels = 0;
    unsigned int next_slice;
    u8 *ies;
    int band, i, ret;
    bool awdl_scan=false;

    if (!glue.up)
        return -ENETDOWN;
    if (glue.scanning)
        return -EBUSY;

    hw = glue_hw();
    local = hw_to_local(hw);
#if defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
    wiphy_lock(hw->wiphy);
    awdl_scan=owly_scan_protect_locked(NULL);
    wiphy_unlock(hw->wiphy);
#endif

    for (band = 0; band < NUM_NL80211_BANDS; band++)
        if (hw->wiphy->bands[band])
            n_channels += hw->wiphy->bands[band]->n_channels;

    /* One allocation: request, channel pointers, the wildcard SSID and maybe
     * a named one, the IEs. */
    sreq = kzalloc(sizeof(*sreq) + n_channels * sizeof(sreq->req.channels[0]) +
                   2 * sizeof(*ssid) + sizeof(glue_ies_2ghz) + sizeof(glue_ies_5ghz),
                   GFP_KERNEL);
    if (!sreq)
        return -ENOMEM;
    req = &sreq->req;
    ssid = (void *)&req->channels[n_channels];
    ies = (u8 *)(ssid + 2);

    /*
     * Connected, a scan covers the next GLUE_SCAN_SLICE channels only: all of
     * them took about 5.5 s off the network's channel, and macOS asks every
     * 30 s, which on a weak 5 GHz link was seconds of no traffic each time. A
     * slice is about a second; the whole list comes round every few minutes,
     * as a Mac's own background scans do. Not connected, or looking for one
     * network by name, all of them. A configured AWDL peer uses four-channel
     * slices even without an AP.
     */
    {
        bool slice = (glue.vif->cfg.assoc && !name && !n_want) || awdl_scan;
        const unsigned limit=awdl_scan ? OWLY_NATIVE_SCAN_CHANNELS : GLUE_SCAN_SLICE;
        unsigned int k = 0, taken = 0, from = slice ? glue.scan_slice_pos : 0;

        for (band = 0; band < NUM_NL80211_BANDS; band++) {
            sband = hw->wiphy->bands[band];
            for (i = 0; sband && i < sband->n_channels; i++) {
                if (!glue_scan_channel(&sband->channels[i]))
                    continue;
                /* Asked for particular channels, only those: macOS knows
                 * where the hotspot it just switched on is, and a scan of
                 * one channel costs the link a fraction of a full sweep. */
                if (n_want) {
                    size_t w;
                    bool wanted = false;

                    for (w = 0; w < n_want; w++)
                        if (want_freqs[w] == sband->channels[i].center_freq)
                            wanted = true;
                    if (!wanted)
                        continue;
                }
                if (k++ < from)
                    continue;
                if (slice && taken == limit)
                    continue;
                req->channels[req->n_channels++] = &sband->channels[i];
                taken++;
            }
        }
        /* k is now the number of channels: wrap round (once the scan has
         * started, below) */
        next_slice = slice && from + taken < k ? from + taken : 0;
        if (!req->n_channels) {
            kfree(sreq);
            return -EINVAL;
        }
    }

    req->ssids = ssid;          /* zero length: the wildcard SSID */
    req->n_ssids = 1;
    if (name) {
        /* and the network asked for by name: a phone's hotspot that has
         * only just come up answers that soonest */
        memcpy(ssid[1].ssid, name, name_len);
        ssid[1].ssid_len = (u8)name_len;
        req->n_ssids = 2;
    }
    req->wiphy = hw->wiphy;
    req->scan_start = jiffies;
    ether_addr_copy(req->mac_addr, glue.vif->addr);
    eth_broadcast_addr(req->bssid);

    memcpy(ies, glue_ies_2ghz, sizeof(glue_ies_2ghz));
    memcpy(ies + sizeof(glue_ies_2ghz), glue_ies_5ghz, sizeof(glue_ies_5ghz));
    req->ie = ies;
    req->ie_len = sizeof(glue_ies_2ghz) + sizeof(glue_ies_5ghz);
    sreq->ies.ies[NL80211_BAND_2GHZ] = ies;
    sreq->ies.len[NL80211_BAND_2GHZ] = sizeof(glue_ies_2ghz);
    sreq->ies.ies[NL80211_BAND_5GHZ] = ies + sizeof(glue_ies_2ghz);
    sreq->ies.len[NL80211_BAND_5GHZ] = sizeof(glue_ies_5ghz);

    wiphy_lock(hw->wiphy);
#ifdef OWLY_MC_BUILT
    owly_mc_leave(); /* the scan starts from the AP's channel */
#endif
    /* The previous request is no longer referenced once a new scan starts. */
    kfree(glue.scan_req);
    glue.scan_req = sreq;
    glue.scanning = true;
    glue.scan_started = jiffies;
    glue.scan_connected = glue.vif->cfg.assoc;
    glue.last_scan_channels = req->n_channels;
    ret = local->ops->hw_scan(hw, glue.vif, sreq);
    if (ret) {
        glue.scanning = false;
    } else {
#if defined(OWLY_AWDL_SOFTWARE_SYNC) && OWLY_AWDL_SOFTWARE_SYNC
        owly_sync_recheck();
#endif
        glue.scan_slice_pos = next_slice;
        if (glue.scan_connected)
            glue.scans_connected++;
        /*
         * The list is kept through the scan, not started afresh: macOS asks
         * to join right after starting one, and an emptied list made a
         * network on a channel not yet scanned "not found". What was not
         * heard for a while goes when a scan ends (glue_bss_expire()).
         */
        spin_lock(&glue.bss_lock);
        glue.scan_gen++;
        spin_unlock(&glue.bss_lock);
    }
    wiphy_unlock(hw->wiphy);

    if (ret > 0)    /* "do a software scan instead": the firmware lacks scan offload */
        ret = -EOPNOTSUPP;
    if (!ret)
        IOLog("[rtw89] scan started on %u channel(s)\n", req->n_channels);
    return ret;
}

unsigned int rtw89_glue_scan_results(struct rtw89_glue_bss *out, unsigned int max)
{
    unsigned int n;

    if (!glue.active)
        return 0;

    spin_lock(&glue.bss_lock);
    n = min(glue.n_bss, max);
    for (unsigned int i = 0; i < n; i++)
        out[i] = glue.bss[i].pub;
    spin_unlock(&glue.bss_lock);
    return n;
}

static void glue_copy_entry(const struct rtw89_glue_bss_entry *e, struct rtw89_glue_bss *out,
                            uint8_t *ies, size_t ies_max, size_t *ies_len, uint16_t *beacon_int)
{
    size_t n = min_t(size_t, e->ies_len, ies_max);

    if (out)
        *out = e->pub;
    if (ies && n)
        memcpy(ies, e->ies, n);
    if (ies_len)
        *ies_len = ies ? n : 0;
    if (beacon_int)
        *beacon_int = e->beacon_int;
}

bool rtw89_glue_scan_entry(unsigned int index, struct rtw89_glue_bss *out, uint8_t *ies,
                           size_t ies_max, size_t *ies_len, uint16_t *beacon_int)
{
    bool found = false;

    if (!glue.active)
        return false;
    spin_lock(&glue.bss_lock);
    if (index < glue.n_bss) {
        glue_copy_entry(&glue.bss[index], out, ies, ies_max, ies_len, beacon_int);
        found = true;
    }
    spin_unlock(&glue.bss_lock);
    return found;
}

bool rtw89_glue_find_bss(const uint8_t bssid[6], struct rtw89_glue_bss *out, uint8_t *ies,
                         size_t ies_max, size_t *ies_len, uint16_t *beacon_int)
{
    bool found = false;
    unsigned int i;

    if (!glue.active)
        return false;
    spin_lock(&glue.bss_lock);
    for (i = 0; i < glue.n_bss && !found; i++) {
        if (ether_addr_equal(glue.bss[i].pub.bssid, bssid)) {
            glue_copy_entry(&glue.bss[i], out, ies, ies_max, ies_len, beacon_int);
            found = true;
        }
    }
    spin_unlock(&glue.bss_lock);
    return found;
}

unsigned int rtw89_glue_channels(struct rtw89_glue_channel *out, unsigned int max)
{
    struct ieee80211_supported_band *sband;
    unsigned int n = 0;
    int band, i;

    if (!glue.probed)
        return 0;
    for (band = 0; band < NUM_NL80211_BANDS; band++) {
        sband = glue_hw()->wiphy->bands[band];
        for (i = 0; sband && i < sband->n_channels && n < max; i++) {
            const struct ieee80211_channel *chan = &sband->channels[i];

            if (!glue_scan_channel(chan))
                continue;
            out[n].freq = (u16)chan->center_freq;
            out[n].channel = (u8)chan->hw_value;
            out[n].passive = !!(chan->flags & IEEE80211_CHAN_NO_IR);
            out[n].radar = !!(chan->flags & IEEE80211_CHAN_RADAR);
            n++;
        }
    }
    return n;
}

/* ------------------------------------------------------------------ */
/*  Join / leave                                                        */
/* ------------------------------------------------------------------ */

/* WPA2-PSK: the pairwise master key from a passphrase (IEEE 802.11 J.4.1), or
 * given directly as 64 hex digits. */
static int glue_derive_pmk(const u8 *ssid, size_t ssid_len,
                           const char *passphrase, size_t len, u8 pmk[32])
{
    size_t i;

    if (len == 64) {
        for (i = 0; i < 64; i++) {
            char c = passphrase[i];
            u8 v;

            if (c >= '0' && c <= '9')
                v = c - '0';
            else if (c >= 'a' && c <= 'f')
                v = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F')
                v = c - 'A' + 10;
            else
                return -EACCES;
            pmk[i / 2] = (i & 1) ? (pmk[i / 2] | v) : (u8)(v << 4);
        }
        return 0;
    }
    if (len < 8 || len > 63)
        return -EACCES;

    rtw89_pbkdf2_sha1((const u8 *)passphrase, len, ssid, ssid_len, 4096, pmk, 32);
    return 0;
}

int rtw89_glue_derive_pmk(const uint8_t *ssid, size_t ssid_len, const char *passphrase,
                          size_t passphrase_len, uint8_t pmk[32])
{
    if (!ssid_len || ssid_len > IEEE80211_MAX_SSID_LEN)
        return -EINVAL;
    return glue_derive_pmk(ssid, ssid_len, passphrase, passphrase_len, pmk);
}

/* Join the strongest access point of the last scan that has this name. */
/* When set, the next glue_join_locked() is for an outside supplicant. */
static const u8 *glue_ext_rsn_ie;
static size_t glue_ext_rsn_len;
static bool glue_ext;

/* See glue_join_locked(): a 5 or 6 GHz access point of the network is
 * preferred to a 2.4 GHz one when its signal is at least this good, and no
 * more than this much weaker. */
#define GLUE_PREFER_5G_MIN      (-70)   /* dBm */
#define GLUE_PREFER_5G_BONUS    15      /* dB */

/* Whether the key for one access point of a network works with another:
 * open with open, 802.1X with 802.1X, and a password with WPA2-PSK, or with
 * WPA3 (SAE) when the password itself is there (@sae). */
static bool glue_same_key(const struct rtw89_glue_bss_entry *a,
                          const struct rtw89_glue_bss_entry *b, bool sae)
{
    const u8 personal = RTW89_GLUE_SEC_WPA2_PSK | (sae ? RTW89_GLUE_SEC_WPA3_SAE : 0);
    u8 sa = a->pub.security, sb = b->pub.security;

    if (!sa || !sb)
        return !sa && !sb;
    if (sa & personal)
        return sb & personal;
    if (sa & RTW89_GLUE_SEC_ENTERPRISE)
        return sb & RTW89_GLUE_SEC_ENTERPRISE;
    return false;
}

static int glue_join_locked(const u8 *ssid, size_t ssid_len, const u8 *bssid, const u8 *pmk,
                            const u8 *password, size_t password_len)
{
    static u8 ies[RTW89_GLUE_MAX_IES];  /* under cmd_lock */
    struct rtw89_glue_bss_entry *best = NULL;
    struct rtw89_mlme_bss bss = {};
    struct ieee80211_hw *hw;
    unsigned int i;
    int ret;

    spin_lock(&glue.bss_lock);
    for (i = 0; i < glue.n_bss; i++) {
        struct rtw89_glue_bss_entry *e = &glue.bss[i];

        if (e->pub.ssid_len != ssid_len || memcmp(e->pub.ssid, ssid, ssid_len) ||
            !e->ies_len)
            continue;
        if (bssid && !ether_addr_equal(e->pub.bssid, bssid))
            continue;
        if (!best || e->pub.signal > best->pub.signal)
            best = e;
    }
    /*
     * The same network on 5 or 6 GHz when its signal is good, as Windows and
     * wpa_supplicant choose: on 2.4 GHz the link is 20 MHz wide, a quarter of
     * an 80 MHz channel. An RTL8852AE tester got 287 Mb/s on 2.4 GHz at
     * -30 dBm where Windows took the same router's 5 GHz side at -37 dBm and
     * 1201 Mb/s. airportd asks for an access point by its signal alone, so
     * its choice of a 2.4 GHz one is overridden too, but only for one of the
     * same network the same key works with.
     */
    memset(glue.asked_bssid, 0, ETH_ALEN);
    /*
     * Only when the caller left the access point open.  Asked for one by
     * address, it gets that one: swapping in a different radio of the same
     * name is the right guess when macOS picked by signal alone, and simply
     * the wrong network when macOS named a target -- a phone's hotspot, say,
     * whose other band is a different device entirely.  Reported as joining
     * 5745 MHz when macOS asked for channel 6 (issue #7).
     */
    if (best && !bssid && best->pub.freq < 5000) {
        struct rtw89_glue_bss_entry *alt = NULL;

        for (i = 0; i < glue.n_bss; i++) {
            struct rtw89_glue_bss_entry *e = &glue.bss[i];

            if (e->pub.ssid_len != ssid_len || memcmp(e->pub.ssid, ssid, ssid_len) ||
                !e->ies_len || e->pub.freq < 5000 || e->pub.signal < GLUE_PREFER_5G_MIN ||
                e->pub.signal + GLUE_PREFER_5G_BONUS <= best->pub.signal ||
                !glue_same_key(best, e, password_len > 0))
                continue;
            if (!alt || e->pub.signal > alt->pub.signal)
                alt = e;
        }
        if (alt) {
            IOLog("[rtw89] the network on %u MHz (%d dBm) rather than %u MHz (%d dBm)\n",
                  alt->pub.freq, alt->pub.signal, best->pub.freq, best->pub.signal);
            if (bssid)
                memcpy(glue.asked_bssid, bssid, ETH_ALEN);
            best = alt;
        }
    }
    if (best) {
        memcpy(bss.bssid, best->pub.bssid, ETH_ALEN);
        memcpy(bss.ssid, ssid, ssid_len);
        bss.ssid_len = (u8)ssid_len;
        bss.freq = best->pub.freq;
        bss.capability = best->pub.capability;
        bss.beacon_int = best->beacon_int;
        memcpy(ies, best->ies, best->ies_len);
        bss.ies = ies;
        bss.ies_len = best->ies_len;
    }
    spin_unlock(&glue.bss_lock);
    if (!best)
        return -ENOENT;

    hw = glue_hw();
    /*
     * Not in the middle of a scan: the firmware is hopping over 39 channels
     * and the AP's answer to the authentication request is missed. macOS
     * often asks to join while its own scan runs; on chips whose channel is
     * set through ->config() (emulated channel contexts: RTL8852A, RTL8851B)
     * every such join failed. mac80211 never authenticates during a scan
     * either. Cancel it and give it a moment to stop.
     */
    if (glue.scanning) {
        struct rtw89_m80211_local *local = hw_to_local(hw);

        wiphy_lock(hw->wiphy);
        if (glue.scanning && local->ops->cancel_hw_scan)
            local->ops->cancel_hw_scan(hw, glue.vif);
        wiphy_unlock(hw->wiphy);
        for (i = 0; i < 50 && glue.scanning; i++)
            msleep(20);
        if (glue.scanning)
            IOLog("[rtw89] the scan did not stop for the join; joining anyway\n");
    }
    wiphy_lock(hw->wiphy);
    if (glue_ext)
        ret = rtw89_mlme_connect_ext(&bss, glue_ext_rsn_ie, glue_ext_rsn_len);
    else
        ret = rtw89_mlme_connect(&bss, pmk, password, password_len);
    wiphy_unlock(hw->wiphy);
    return ret;
}

static int glue_join_request(const u8 *ssid, size_t ssid_len, const u8 *bssid, const u8 *pmk,
                             const u8 *password, size_t password_len)
{
    typeof(glue.want) old;
    int ret;

    mutex_lock(&glue.cmd_lock);
    if (!glue.up) {
        ret = -ENETDOWN;
        goto out;
    }
    /* a new request ends the attempts to get the previous network back */
    if (glue.rejoining) {
        struct ieee80211_hw *hw = glue_hw();

        glue_forget_network();
        cancel_delayed_work(&glue.rejoin_work);
        wiphy_lock(hw->wiphy);
        rtw89_mlme_disconnect(WLAN_REASON_DEAUTH_LEAVING);
        wiphy_unlock(hw->wiphy);
    }

    /* What to come back to, in place before the join can succeed. If the
     * join cannot even start, what was there before stays. */
    old = glue.want;
    memset(&glue.want, 0, sizeof(glue.want));
    memcpy(glue.want.ssid, ssid, ssid_len);
    glue.want.ssid_len = (u8)ssid_len;
    glue.want.have_pmk = pmk != NULL;
    if (pmk)
        memcpy(glue.want.pmk, pmk, sizeof(glue.want.pmk));
    if (password_len)
        memcpy(glue.want.password, password, password_len);
    glue.want.password_len = (u8)password_len;
    glue.want.valid = true;

    ret = glue_join_locked(ssid, ssid_len, bssid, pmk, password, password_len);
    if (ret)
        glue.want = old;
    else
        glue.rejoin_tries = 0;
    memset(&old, 0, sizeof(old));
out:
    mutex_unlock(&glue.cmd_lock);
    return ret;
}

int rtw89_glue_join(const uint8_t *ssid, size_t ssid_len,
                    const char *passphrase, size_t passphrase_len)
{
    bool have_pmk = false;
    u8 pmk[32];
    int ret;

    if (!glue.up)
        return -ENETDOWN;
    if (!ssid_len || ssid_len > IEEE80211_MAX_SSID_LEN)
        return -EINVAL;
    if (passphrase && passphrase_len) {
        ret = glue_derive_pmk(ssid, ssid_len, passphrase, passphrase_len, pmk);
        if (ret)
            return ret;
        have_pmk = true;
    }
    ret = glue_join_request(ssid, ssid_len, NULL, have_pmk ? pmk : NULL,
                            (const u8 *)passphrase,
                            passphrase_len <= RTW89_GLUE_MAX_PASSWORD ? passphrase_len : 0);
    memset(pmk, 0, sizeof(pmk));
    return ret;
}

int rtw89_glue_join_ext(const uint8_t *ssid, size_t ssid_len, const uint8_t *bssid,
                        const uint8_t *rsn_ie, size_t rsn_len)
{
    int ret;

    if (!glue.up)
        return -ENETDOWN;
    if (!ssid_len || ssid_len > IEEE80211_MAX_SSID_LEN)
        return -EINVAL;
    /* not remembered for coming back: the sign-in is not ours to repeat */
    mutex_lock(&glue.cmd_lock);
    glue_forget_network();
    cancel_delayed_work(&glue.rejoin_work);
    glue_ext = true;
    glue_ext_rsn_ie = rsn_ie;
    glue_ext_rsn_len = rsn_len;
    ret = glue.up ? glue_join_locked(ssid, ssid_len, bssid, NULL, NULL, 0) : -ENETDOWN;
    glue_ext = false;
    glue_ext_rsn_ie = NULL;
    mutex_unlock(&glue.cmd_lock);
    return ret;
}

size_t rtw89_glue_assoc_rsn_ie(uint8_t *buf, size_t max)
{
    return glue.up ? rtw89_mlme_assoc_rsn_ie(buf, max) : 0;
}

int rtw89_glue_set_key(bool pairwise, int index, const uint8_t *key, size_t len, uint64_t rsc)
{
    struct ieee80211_hw *hw;
    int ret;

    if (!glue.up)
        return -ENETDOWN;
    hw = glue_hw();
    wiphy_lock(hw->wiphy);
    ret = rtw89_mlme_set_key(pairwise, index, key, len, rsc);
    wiphy_unlock(hw->wiphy);
    return ret;
}

int rtw89_glue_set_pmk(const uint8_t *pmk, size_t len)
{
    struct ieee80211_hw *hw;
    int ret;

    if (!glue.up)
        return -ENETDOWN;
    hw = glue_hw();
    wiphy_lock(hw->wiphy);
    ret = rtw89_mlme_set_pmk(pmk, len);
    wiphy_unlock(hw->wiphy);
    return ret;
}

int rtw89_glue_join_pmk(const uint8_t *ssid, size_t ssid_len, const uint8_t *bssid,
                        const uint8_t *pmk)
{
    if (!glue.up)
        return -ENETDOWN;
    if (!ssid_len || ssid_len > IEEE80211_MAX_SSID_LEN)
        return -EINVAL;
    return glue_join_request(ssid, ssid_len, bssid, pmk, NULL, 0);
}

int rtw89_glue_join_password(const uint8_t *ssid, size_t ssid_len, const uint8_t *bssid,
                             const char *password, size_t password_len)
{
    bool have_pmk;
    u8 pmk[32];
    int ret;

    if (!glue.up)
        return -ENETDOWN;
    if (!ssid_len || ssid_len > IEEE80211_MAX_SSID_LEN || !password_len ||
        password_len > RTW89_GLUE_MAX_PASSWORD)
        return -EINVAL;
    /* not every SAE password is a WPA2 passphrase: then WPA3 alone */
    have_pmk = !glue_derive_pmk(ssid, ssid_len, password, password_len, pmk);
    ret = glue_join_request(ssid, ssid_len, bssid, have_pmk ? pmk : NULL,
                            (const u8 *)password, password_len);
    memset(pmk, 0, sizeof(pmk));
    return ret;
}

void rtw89_glue_leave(void)
{
    struct ieee80211_hw *hw;

    if (!glue.up)
        return;
    mutex_lock(&glue.cmd_lock);
    if (glue.up) {
        /* leaving is for good */
        glue_forget_network();
        cancel_delayed_work(&glue.rejoin_work);
        hw = glue_hw();
        wiphy_lock(hw->wiphy);
        rtw89_mlme_disconnect(WLAN_REASON_DEAUTH_LEAVING);
        wiphy_unlock(hw->wiphy);
    }
    mutex_unlock(&glue.cmd_lock);
}

/*
 * One step of getting the network back after the connection was lost: a
 * scan (the AP may have moved), then a join; glue_link_notify() and
 * glue_scan_done() queue the next step.
 */
static void glue_rejoin_work(struct work_struct *work)
{
    struct rtw89_mlme_status st;
    int ret;

    mutex_lock(&glue.cmd_lock);
    if (!glue.up || !glue.want.valid || !glue.rejoining || glue.rejoin_off)
        goto out;
    rtw89_mlme_get_status(&st);
    if (st.state != RTW89_MLME_IDLE)
        goto out;       /* an attempt is under way; its end brings us back */

    if (glue.scanning) {
        /* its results will do; look again when it is over, or after a while
         * if it never is */
        glue.rejoin_scanned = true;
        if (time_before(jiffies, glue.scan_started + 15 * HZ)) {
            glue_rejoin_queue(HZ);
            goto out;
        }
    } else if (!glue.rejoin_scanned) {
        glue.rejoin_scanned = true;
        if (!glue_scan_locked(NULL, 0, NULL, 0))
            goto out;
        /* no scan to be had: try with what was heard before */
    }

    glue.rejoin_scanned = false;
    glue.rejoin_tries++;
    ret = glue_join_locked(glue.want.ssid, glue.want.ssid_len, NULL,
                           glue.want.have_pmk ? glue.want.pmk : NULL,
                           glue.want.password, glue.want.password_len);
    if (ret) {
        IOLog("[rtw89] attempt %u to join \"%.*s\" again failed: %d\n", glue.rejoin_tries,
              glue.want.ssid_len, glue.want.ssid, ret);
        glue_rejoin_schedule();
    }
out:
    mutex_unlock(&glue.cmd_lock);
}

void rtw89_glue_probe_ap(void)
{
    if (glue.up)
        rtw89_mlme_beacon_loss();
}

void rtw89_glue_drop(void)
{
    if (glue.up)
        rtw89_mlme_connection_lost();
}

/*
 * Whether the self address still disagrees with what @freq asks for, so that
 * the work is queued for the address alone once the channel has settled.
 */

/* From rtw89_awdl.c as well, with the frame already in 802.3 form. */

void rtw89_glue_set_rejoin(bool on)
{
    if (!glue.active)
        return;
    glue.rejoin_off = !on;
    if (!on) {
        glue.rejoining = false;
        cancel_delayed_work(&glue.rejoin_work);
    }
}

void rtw89_glue_link(struct rtw89_glue_link *link)
{
    struct rtw89_mlme_status st;

    struct rtw89_data_stats stats;

    memset(link, 0, sizeof(*link));
    if (!glue.probed)
        return;
    rtw89_data_get_stats(&stats);
    link->tx_frames = stats.tx_frames;
    link->tx_dropped = stats.tx_dropped;
    link->rx_frames = stats.rx_frames;
    link->rx_dropped = stats.rx_dropped;
    link->rx_undecrypted = stats.rx_undecrypted;
    link->rx_replay = stats.rx_replay;
    link->rx_dup = stats.rx_dup;
    link->rx_reorder_timeout = stats.rx_reorder_timeout;
    link->rx_late = glue.rx_late;
    link->rx_late_irq = glue.rx_late_irq;
    link->rx_late_max_ms = glue.rx_late_max;
    link->rx_ppdu_flushed = glue.ppdu_flushed;
    link->ppdu_flush = glue.ppdu_flush;
    link->ax = rtw89_mlme_get_he();
    link->rejoin = !glue.rejoin_off;
    link->rejoins = glue.rejoins;
    {
        struct rtw89_dev *rtwdev = glue_hw()->priv;

        if (rtwdev->regulatory.regd)
            memcpy(link->country, rtwdev->regulatory.regd->alpha2, 2);
        if (glue.up && glue.vif && glue.vif->cfg.assoc) {
            const struct rtw89_chan *chan = rtw89_chan_get(rtwdev, RTW89_CHANCTX_0);

            link->txpwr_limit[0] = rtw89_phy_read_txpwr_limit(rtwdev, chan->band_type,
                RTW89_CHANNEL_WIDTH_20, RTW89_1TX, RTW89_RS_MCS, RTW89_NONBF,
                chan->primary_channel);
            link->txpwr_limit[1] = rtw89_phy_read_txpwr_limit(rtwdev, chan->band_type,
                RTW89_CHANNEL_WIDTH_20, RTW89_2TX, RTW89_RS_MCS, RTW89_NONBF,
                chan->primary_channel);
        }
    }
    if (!glue.up)
        return;

    rtw89_mlme_get_status(&st);
    link->rejoining = glue.rejoining;
    link->rejoin_tries = glue.rejoin_tries;
    link->beacons = st.beacons;
    link->beacon_losses = st.beacon_losses;
    link->beacon_updates = st.beacon_updates;
    link->scans_connected = glue.scans_connected;
    link->scan_ms_connected = glue.scan_ms_connected;
    link->last_scan_ms = glue.last_scan_ms;
    link->last_scan_channels = glue.last_scan_channels;
    link->probe_acks = st.probe_acks;
    if (st.state == RTW89_MLME_CONNECTED) {
        struct rate_info ri;

        if (st.tx_rate_valid)
            glue_rate_describe(&st.tx_rate, &link->tx_rate);
        if (glue_rate_info(glue.rx_rate, &ri))
            glue_rate_describe(&ri, &link->rx_rate);
    }
    switch (st.state) {
    case RTW89_MLME_AUTHENTICATING:
    case RTW89_MLME_ASSOCIATING:
        link->state = RTW89_GLUE_LINK_JOINING;
        break;
    case RTW89_MLME_ASSOCIATED:
        link->state = RTW89_GLUE_LINK_ASSOCIATED;
        break;
    case RTW89_MLME_CONNECTED:
        link->state = RTW89_GLUE_LINK_CONNECTED;
        break;
    default:
        link->state = RTW89_GLUE_LINK_DOWN;
        break;
    }
    memcpy(link->bssid, st.bssid, ETH_ALEN);
    memcpy(link->asked_bssid, glue.asked_bssid, ETH_ALEN);
    memcpy(link->ssid, st.ssid, sizeof(link->ssid));
    link->freq = st.freq;
    link->aid = st.aid;
    link->authorized = st.state == RTW89_MLME_CONNECTED && rtw89_mlme_authorized();
    if (st.state != RTW89_MLME_IDLE) {
        struct rtw89_glue_bss bss;

        if (rtw89_glue_find_bss(st.bssid, &bss, NULL, 0, NULL, NULL))
            link->signal = bss.signal;
    }
    link->width = st.width;
    link->center_freq = st.center_freq;
    link->mode = st.mode;
    link->nss = st.nss;
    link->last_error = st.last_error;
    link->eapol_rx = st.eapol_rx;
    link->tx_ba = st.tx_ba;
    link->rx_ba = st.rx_ba;
}

/* ------------------------------------------------------------------ */
/*  Data                                                                */
/* ------------------------------------------------------------------ */

void *rtw89_glue_tx_alloc(size_t len, uint8_t **frame)
{
    struct sk_buff *skb;

    if (!glue.probed)
        return NULL;
    skb = rtw89_data_tx_alloc(len);
    if (skb)
        *frame = skb->data;
    return skb;
}

int rtw89_glue_tx(void *handle)
{
    return rtw89_data_tx(handle);
}

unsigned int rtw89_glue_tx_room(void)
{
    return rtw89_data_tx_room();
}

void rtw89_glue_tx_cancel(void *handle)
{
    kfree_skb(handle);
}
