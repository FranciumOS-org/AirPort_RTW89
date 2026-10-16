// SPDX-License-Identifier: GPL-2.0
/*
 * Watching AWDL go by. See rtw89_awdl.h for why.
 *
 * An AWDL sync frame is a vendor-specific action frame: the usual 24-byte
 * management header with Apple's AWDL address as the BSSID, then
 *
 *     category 0x7f  OUI 00:17:f2  type 0x08  version  subtype  reserved
 *     phy_tx_time (le32)  target_tx_time (le32)   then TLVs
 *
 * Subtype 0 is a periodic sync frame (PSF) and 3 a master indication frame
 * (MIF). The two timestamps are what the timeline is built from: target_tx_time
 * is when the sender meant to transmit, phy_tx_time when the radio actually
 * did, both in microseconds of the sender's own clock.
 *
 * TLV 4 carries the synchronisation parameters -- the availability window
 * length and period, and where in the sequence the sender currently is --
 * which is the schedule a driver has to match to be heard.
 */
#include "rtw89_awdl.h"

#include <linux/ieee80211.h>
#include <linux/skbuff.h>
#include <net/mac80211.h>

#define awdl_log(fmt, ...) IOLog("[rtw89 awdl] " fmt "\n", ##__VA_ARGS__)

/* 00:25:00:ff:94:73, the address every AWDL frame is addressed to */
static const u8 kAwdlBssid[ETH_ALEN] = { 0x00, 0x25, 0x00, 0xff, 0x94, 0x73 };
static const u8 kAppleOui[3] = { 0x00, 0x17, 0xf2 };

#define AWDL_TYPE           0x08
#define AWDL_SUBTYPE_PSF    0
#define AWDL_SUBTYPE_MIF    3
#define AWDL_TLV_SYNC_PARAMS 4

/* category + OUI + type + version + subtype + reserved + the two timestamps */
#define AWDL_FIXED_LEN      (1 + 3 + 1 + 1 + 1 + 1 + 4 + 4)

static bool gWatching;
static u32 gLastTargetTx;   /* to show the period between sync frames */
/* Only the first few of each kind, so a busy room cannot fill the log ring. */
static unsigned int gSeen[4];
#define AWDL_LOG_LIMIT 12

void rtw89_awdl_watch(bool on)
{
    if (on == gWatching)
        return;
    gWatching = on;
    if (on) {
        memset(gSeen, 0, sizeof(gSeen));
        gLastTargetTx = 0;
    }
    awdl_log("watching %s", on ? "on" : "off");
}

bool rtw89_awdl_watching(void)
{
    return gWatching;
}

/*
 * The synchronisation parameters TLV: the schedule itself. The layout below
 * is OWL's awdl_sync_params_tlv, checked field by field against frames from
 * an iPhone on 2026-10-16 -- master channel 6 and next AW channel 44 are
 * AWDL's social channels, the master address was the sender's own, and the
 * periods came out as round numbers of TU. (An earlier version guessed these
 * offsets and printed nonsense; the bytes are still logged beside the decode
 * so a wrong reading stays visible.)
 */
struct awdl_sync_params {
    u8  next_aw_channel;
    __le16 tx_down_counter;
    u8  master_channel;
    u8  guard_time;
    __le16 aw_period;
    __le16 af_period;
    __le16 flags;
    __le16 aw_ext_length;
    __le16 aw_common_length;
    __le16 remaining_aw_length;
    u8  min_ext;
    u8  max_ext_multicast;
    u8  max_ext_unicast;
    u8  max_ext_af;
    u8  master_addr[ETH_ALEN];
} __packed;

static void awdl_log_sync_params(const u8 *v, size_t len)
{
    const struct awdl_sync_params *p = (const void *)v;

    if (len < sizeof(*p))
        return;
    /* A TU is 1024 us, so an AW period of 16 TU is 16.384 ms. */
    awdl_log("    sync: AW period %u TU, common length %u TU, extension %u TU, "
             "%u TU left; AF period %u TU",
             le16_to_cpu(p->aw_period), le16_to_cpu(p->aw_common_length),
             le16_to_cpu(p->aw_ext_length), le16_to_cpu(p->remaining_aw_length),
             le16_to_cpu(p->af_period));
    awdl_log("    sync: master channel %u, next AW on channel %u, master "
             "%02x:%02x:%02x:%02x:%02x:%02x, flags 0x%04x, counter %u",
             p->master_channel, p->next_aw_channel,
             p->master_addr[0], p->master_addr[1], p->master_addr[2],
             p->master_addr[3], p->master_addr[4], p->master_addr[5],
             le16_to_cpu(p->flags), le16_to_cpu(p->tx_down_counter));
}

static void awdl_log_hex(const char *what, const u8 *v, size_t len)
{
    char line[3 * 24 + 1];
    size_t i, n = len > 24 ? 24 : len;

    for (i = 0; i < n; i++)
        snprintf(line + 3 * i, sizeof(line) - 3 * i, "%02x ", v[i]);
    line[n ? 3 * n - 1 : 0] = '\0';
    awdl_log("    %s (%u bytes): %s%s", what, (unsigned int)len, line,
             len > n ? " ..." : "");
}

bool rtw89_awdl_rx(struct sk_buff *skb, size_t len)
{
    const struct ieee80211_mgmt *mgmt = (const void *)skb->data;
    const struct ieee80211_rx_status *status = IEEE80211_SKB_RXCB(skb);
    const u8 *body, *end, *tlv;
    u8 subtype, version;
    u32 phy_tx, target_tx;
    unsigned int slot;

    if (len < sizeof(struct ieee80211_hdr_3addr) + AWDL_FIXED_LEN)
        return false;
    if (!ieee80211_is_action(mgmt->frame_control))
        return false;
    if (!ether_addr_equal(mgmt->bssid, kAwdlBssid))
        return false;

    body = (const u8 *)mgmt + sizeof(struct ieee80211_hdr_3addr);
    end = (const u8 *)skb->data + len;
    if (body[0] != WLAN_CATEGORY_VENDOR_SPECIFIC ||
        memcmp(body + 1, kAppleOui, sizeof(kAppleOui)) != 0 || body[4] != AWDL_TYPE)
        return false;

    /* It is AWDL from here on, whether or not we are watching. */
    if (!gWatching)
        return true;

    version = body[5];
    subtype = body[6];
    phy_tx = (u32)(body[8] | (body[9] << 8) | (body[10] << 16) | ((u32)body[11] << 24));
    target_tx = (u32)(body[12] | (body[13] << 8) | (body[14] << 16) | ((u32)body[15] << 24));

    slot = subtype < ARRAY_SIZE(gSeen) ? subtype : ARRAY_SIZE(gSeen) - 1;
    if (gSeen[slot]++ >= AWDL_LOG_LIMIT)
        return true;

    awdl_log("%s from %02x:%02x:%02x:%02x:%02x:%02x, %d dBm, %u MHz, v%u",
             subtype == AWDL_SUBTYPE_PSF ? "PSF" :
             subtype == AWDL_SUBTYPE_MIF ? "MIF" : "sync frame",
             mgmt->sa[0], mgmt->sa[1], mgmt->sa[2], mgmt->sa[3], mgmt->sa[4], mgmt->sa[5],
             (int)status->signal, (unsigned int)status->freq, (unsigned int)version);
    /* target vs phy is the sender's own transmit jitter: the budget we would
     * have to stay inside to be heard in the same window. */
    /* target vs phy is the sender's own jitter; the gap between frames is the
     * period we would have to keep up with. */
    awdl_log("    target tx %u us, phy tx %u us, late by %d us; our clock %u us%s",
             (unsigned int)target_tx, (unsigned int)phy_tx,
             (int)(phy_tx - target_tx), (unsigned int)status->mactime,
             gLastTargetTx ? "" : " (first)");
    if (gLastTargetTx)
        awdl_log("    %u us since the last sync frame seen", (unsigned int)(target_tx - gLastTargetTx));
    gLastTargetTx = target_tx;

    for (tlv = body + AWDL_FIXED_LEN; tlv + 3 <= end; ) {
        u8 type = tlv[0];
        size_t tlen = (size_t)(tlv[1] | (tlv[2] << 8));

        if (tlv + 3 + tlen > end)
            break;
        if (type == AWDL_TLV_SYNC_PARAMS) {
            awdl_log_sync_params(tlv + 3, tlen);
            awdl_log_hex("sync params", tlv + 3, tlen);
        }
        else
            awdl_log("    TLV type %u, %u bytes", (unsigned int)type, (unsigned int)tlen);
        tlv += 3 + tlen;
    }
    return true;
}
