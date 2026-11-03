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
#include "rtw89_glue.h"
#include "rtw89_net80211.h"

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
/* Election parameters v2, which names the master and carries its metric.
 * The family builds ours naming this machine, which contradicts the
 * synchronisation parameters once a real master is being followed. */
#define AWDL_TLV_ELECTION_V2 24
/* The peer's host name, which IO80211 cannot parse without panicking */
#define AWDL_TLV_ARPA        0x10

/* category + OUI + type + version + subtype + reserved + the two timestamps */
#define AWDL_FIXED_LEN      (1 + 3 + 1 + 1 + 1 + 1 + 4 + 4)

static bool gWatching;
static bool gDelivering;
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

void rtw89_awdl_deliver(bool on)
{
    if (on == gDelivering)
        return;
    gDelivering = on;
    awdl_log("handing frames to IO80211: %s", on ? "on" : "off");
}

bool rtw89_awdl_delivering(void)
{
    return gDelivering;
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

/*
 * In full, 24 to a line.  The synchronisation parameters are the one TLV we
 * have to send as well as read, and the part past the fixed fields decoded
 * above -- the channel sequence -- has no layout here yet, so the bytes
 * themselves are the record to build it from.
 */
static void awdl_log_hex(const char *what, const u8 *v, size_t len)
{
    char line[3 * 24 + 1];
    size_t off;

    awdl_log("    %s (%u bytes):", what, (unsigned int)len);
    for (off = 0; off < len; off += 24) {
        size_t i, m = len - off < 24 ? len - off : 24;

        for (i = 0; i < m; i++)
            snprintf(line + 3 * i, sizeof(line) - 3 * i, "%02x ", v[off + i]);
        line[3 * m - 1] = '\0';
        awdl_log("      %04x  %s", (unsigned int)off, line);
    }
}

/* What has come back the other way; see rtw89_awdl_rx(). */
static struct { u32 data_seen; u32 offered; u32 matched; u32 apple; u32 arpa; } gRx;

/*
 * The master's timeline, which is the thing we were missing.
 *
 * Everything else works: a peer is heard steadily, its frames reach the
 * family, our own frames go out on schedule with no window missed, and
 * packets pass in both directions. What has never happened is the iPhone
 * seeing this machine at all, and the reason is that we kept our own time.
 * The clock started whenever awdl0 came up and the sync frames we sent named
 * ourselves as master, so our availability windows and the peer's coincided
 * only by luck -- which is what two packets in a minute looks like.
 *
 * AWDL is a timeline, so being on it means adopting someone else's. A sync
 * frame says how much of the current window is left (remaining_aw_length, in
 * TU) and which window it is (the sequence number), so a frame heard at a
 * known local time says exactly when the master's next window starts on our
 * own clock. That is recorded here and used both to phase the clock and to
 * fill in the frames we send.
 *
 * Election is not decoded yet, so the tie-break is the lowest address, which
 * is at least deterministic and cannot oscillate between two peers. Adopting
 * the wrong master costs synchronisation with the right one; adopting none,
 * as until now, costs everything.
 */
#define AWDL_MASTER_STALE_US  3000000   /* forget a master unheard this long */

static struct {
    bool have;
    u8   addr[ETH_ALEN];
    u8   channel;           /* the master's own channel */
    u16  aw_period;         /* TU, 16 on every frame seen so far */
    u16  aw_seq;            /* the window number that starts at next_aw_us */
    u64  next_aw_us;        /* our clock, when that window begins */
    u64  seen_us;
    u32  frames;
    /*
     * The master half of its election parameters v2 TLV: the master address,
     * the synchronisation master address, and the metric and counter that go
     * with them -- the first 20 bytes of that TLV. A follower repeats these
     * unchanged and keeps only its own self metric and counter.
     */
    bool have_election;
    u8   election[20];
} gMaster;

static u64 awdl_now_us(void)
{
    return ktime_get_boottime_ns() / 1000;
}

static void awdl_note_master(const u8 *sa, const u8 *v, size_t len, u64 rx_us)
{
    const struct awdl_sync_params *p = (const void *)v;
    u16 remaining, period;

    /* 31 bytes: the fixed struct, plus the presence mode and the window
     * sequence number that follow it at offsets 27..30. */
    if (len < 31)
        return;
    period = le16_to_cpu(p->aw_period);
    remaining = le16_to_cpu(p->remaining_aw_length);
    if (!period || remaining > period)
        return;             /* not a schedule we can read */

    /* Only the master's own frames carry its timeline; a peer repeating it
     * would be a second-hand copy with its own delay in it. */
    if (!ether_addr_equal(p->master_addr, sa))
        return;
    if (gMaster.have && !ether_addr_equal(gMaster.addr, sa)) {
        if (awdl_now_us() - gMaster.seen_us < AWDL_MASTER_STALE_US &&
            memcmp(sa, gMaster.addr, ETH_ALEN) > 0)
            return;         /* we already follow one at least as good */
    }
    if (!gMaster.have || !ether_addr_equal(gMaster.addr, sa))
        awdl_log("following the AWDL master %02x:%02x:%02x:%02x:%02x:%02x on "
                 "channel %u, windows of %u TU",
                 sa[0], sa[1], sa[2], sa[3], sa[4], sa[5],
                 p->master_channel, (unsigned int)period);
    gMaster.have = true;
    memcpy(gMaster.addr, sa, ETH_ALEN);
    gMaster.channel = p->master_channel;
    gMaster.aw_period = period;
    /* What is left of the window this frame went out in tells us where the
     * next one begins; the frame's own window is that sequence number. */
    gMaster.next_aw_us = rx_us + (u64)remaining * 1024;
    /* The window this frame belongs to is at offset 29, the same place we
     * write ours; the one starting at next_aw_us is the one after it. */
    gMaster.aw_seq = (u16)((v[29] | ((u16)v[30] << 8)) + 1);
    gMaster.seen_us = awdl_now_us();
    gMaster.frames++;
}

bool rtw89_awdl_master_election(u8 out[20])
{
    if (!gMaster.have || !gMaster.have_election)
        return false;
    if (awdl_now_us() - gMaster.seen_us > AWDL_MASTER_STALE_US)
        return false;
    if (out)
        memcpy(out, gMaster.election, sizeof(gMaster.election));
    return true;
}

u8 rtw89_awdl_master_channel(void)
{
    if (!gMaster.have || awdl_now_us() - gMaster.seen_us > AWDL_MASTER_STALE_US)
        return 0;
    return gMaster.channel;
}

bool rtw89_awdl_master_timeline(u8 addr[ETH_ALEN], u64 *next_aw_us, u16 *aw_seq,
                                u16 *aw_period_tu)
{
    if (!gMaster.have)
        return false;
    if (awdl_now_us() - gMaster.seen_us > AWDL_MASTER_STALE_US) {
        gMaster.have = false;
        awdl_log("the AWDL master has gone quiet; keeping our own time again");
        return false;
    }
    if (addr)
        memcpy(addr, gMaster.addr, ETH_ALEN);
    if (next_aw_us)
        *next_aw_us = gMaster.next_aw_us;
    if (aw_seq)
        *aw_seq = gMaster.aw_seq;
    if (aw_period_tu)
        *aw_period_tu = gMaster.aw_period;
    return true;
}

bool rtw89_awdl_rx(struct sk_buff *skb, size_t len)
{
    const struct ieee80211_mgmt *mgmt = (const void *)skb->data;
    const struct ieee80211_rx_status *status = IEEE80211_SKB_RXCB(skb);
    const u8 *body, *end, *tlv;
    u8 subtype, version;
    u32 phy_tx, target_tx;
    unsigned int slot;

    if (len < sizeof(struct ieee80211_hdr_3addr))
        return false;
    /*
     * How much the card hears, in two numbers. A boot where the engine was
     * running and transmitting perfectly received nothing at all, and from
     * the log alone there was no telling whether the radio heard nothing or
     * heard plenty and this function rejected it.
     */
    if (++gRx.offered % 512 == 0)
        awdl_log("%u frame(s) offered to the AWDL path, %u on the AWDL BSSID",
                 (unsigned int)gRx.offered, (unsigned int)gRx.matched);
    /*
     * What the frames actually are, because two guesses at why so few match
     * -- the channel, then the receive filter bits -- were both wrong, and
     * 91648 frames reaching here with 2 on the AWDL BSSID says either no
     * peer is transmitting AWDL near us or this comparison is looking in the
     * wrong place. A sample of the addresses settles it either way.
     */
    if (gRx.offered % 4096 == 0) {
        const u8 *a3 = mgmt->bssid;
        const u8 *a2 = mgmt->sa;
        u16 fc = le16_to_cpu(mgmt->frame_control);

        awdl_log("    a sample frame: fc 0x%04x (%s), %u MHz, "
                 "bssid %02x:%02x:%02x:%02x:%02x:%02x, "
                 "from %02x:%02x:%02x:%02x:%02x:%02x",
                 (unsigned int)fc,
                 ieee80211_is_mgmt(mgmt->frame_control) ? "management" :
                 ieee80211_is_data(mgmt->frame_control) ? "data" : "other",
                 (unsigned int)status->freq,
                 a3[0], a3[1], a3[2], a3[3], a3[4], a3[5],
                 a2[0], a2[1], a2[2], a2[3], a2[4], a2[5]);
    }
    /* Anything from an Apple radio, whatever its BSSID: the AWDL OUI as a
     * sender is the other way to recognise one of these. */
    if (memcmp(mgmt->sa, kAppleOui, 3) == 0 && gRx.apple++ < 8)
        awdl_log("    an Apple sender on %u MHz, bssid "
                 "%02x:%02x:%02x:%02x:%02x:%02x, fc 0x%04x",
                 (unsigned int)status->freq,
                 mgmt->bssid[0], mgmt->bssid[1], mgmt->bssid[2],
                 mgmt->bssid[3], mgmt->bssid[4], mgmt->bssid[5],
                 (unsigned int)le16_to_cpu(mgmt->frame_control));
    if (!ether_addr_equal(mgmt->bssid, kAwdlBssid))
        return false;
    gRx.matched++;
    /*
     * A data frame on the AWDL BSSID, which is what a transfer is made of.
     * Only action frames were recognised here before, so these fell through
     * to mac80211, which has no station for this BSSID and dropped them:
     * awdl0 received nothing at all while the sync frames flowed both ways.
     *
     * The payload past the 24-byte header is already what the stack above
     * expects -- Apple's SNAP header and AWDL data header, as our own
     * transmit side learned -- so all that is missing is the 802.3 header
     * the interface works in, built from the addresses the 802.11 header
     * carries.
     */
    if (ieee80211_is_data(mgmt->frame_control)) {
        const u8 *body = (const u8 *)mgmt + sizeof(struct ieee80211_hdr_3addr);
        size_t payload = len - sizeof(struct ieee80211_hdr_3addr);
        u8 eth[ETH_HLEN + 2048];

        if (!payload || payload > sizeof(eth) - ETH_HLEN)
            return false;
        memcpy(eth, mgmt->da, ETH_ALEN);
        memcpy(eth + ETH_ALEN, mgmt->sa, ETH_ALEN);
        eth[12] = (u8)(payload >> 8);
        eth[13] = (u8)payload;
        memcpy(eth + ETH_HLEN, body, payload);
        if (!gRx.data_seen++)
            awdl_log("the first data frame from a peer: %u bytes on air, %u to "
                     "awdl0, from %02x:%02x:%02x:%02x:%02x:%02x",
                     (unsigned int)len, (unsigned int)(payload + ETH_HLEN),
                     mgmt->sa[0], mgmt->sa[1], mgmt->sa[2],
                     mgmt->sa[3], mgmt->sa[4], mgmt->sa[5]);
        rtw89_glue_awdl_data(eth, payload + ETH_HLEN);
        return true;
    }
    if (len < sizeof(struct ieee80211_hdr_3addr) + AWDL_FIXED_LEN)
        return false;
    if (!ieee80211_is_action(mgmt->frame_control))
        return false;

    body = (const u8 *)mgmt + sizeof(struct ieee80211_hdr_3addr);
    end = (const u8 *)skb->data + len;
    if (body[0] != WLAN_CATEGORY_VENDOR_SPECIFIC ||
        memcmp(body + 1, kAppleOui, sizeof(kAppleOui)) != 0 || body[4] != AWDL_TYPE)
        return false;

    /*
     * The master's schedule, read whether or not we are logging: following
     * the timeline is not a diagnostic any more, and gWatching used to gate
     * the only code that looked at these TLVs.
     */
    {
        const u8 *t = body + AWDL_FIXED_LEN;
        u64 arrived;

        /*
         * The chip's own arrival time, not ours. Timing the window from the
         * moment the driver got round to the frame gave corrections scattered
         * across the whole 16 ms window, which was the receive processing
         * delay and nothing about AWDL. Without a hardware stamp there is
         * nothing worth recording, so the frame is left alone.
         */
        if ((status->flag & RX_FLAG_MACTIME_START) &&
            rtw89_glue_rx_local_us(status->mactime, &arrived)) {
            const u8 *election = NULL;
            size_t election_len = 0;

            while (t + 3 <= end) {
                size_t tl = (size_t)(t[1] | (t[2] << 8));

                if (t + 3 + tl > end)
                    break;
                if (t[0] == AWDL_TLV_SYNC_PARAMS)
                    awdl_note_master(mgmt->sa, t + 3, tl, arrived);
                else if (t[0] == AWDL_TLV_ELECTION_V2) {
                    election = t + 3;
                    election_len = tl;
                }
                t += 3 + tl;
            }
            /* Only from the master we settled on, and only after the sync
             * parameters above have had their say about who that is. */
            if (election && election_len >= sizeof(gMaster.election) &&
                gMaster.have && ether_addr_equal(gMaster.addr, mgmt->sa)) {
                memcpy(gMaster.election, election, sizeof(gMaster.election));
                if (!gMaster.have_election)
                    awdl_log("    and its election parameters, which we repeat "
                             "rather than claiming to be master ourselves");
                gMaster.have_election = true;
            }
        }
    }

    /* It is AWDL from here on, whether or not we are watching. */
    /*
     * The action frame body, not the 802.11 frame, and with the RSSI.
     *
     * IO80211AWDLPeerManager::isValidAF() reads mbuf_data()[1..5] and wants
     * 00 17 f2 08 00 there -- the vendor OUI, type and version of the action
     * frame itself -- and getTlvPtrForType() walks the TLVs from
     * mbuf_data() + 16, the fixed AWDL action header. Handing over the whole
     * 802.11 frame put the frame control where the OUI belongs, so every
     * frame handed over since this path was written failed that check and was
     * thrown away ("BAD OUI in AF"). Nothing past it ever ran, which is why
     * the family has never built an IO80211AWDLPeer for the phone.
     *
     * The RSSI is the other half. determinePeerReachability() reads it from
     * apple80211_act_frm_hdr at 0x2c and treats zero as unreachable, which
     * makes addAWDLPeer() give up ("Unable to create peer"); the threshold
     * at 0x6e84 is -70 dBm by default, so the figure has to be a real one.
     */
    if (gDelivering) {
        /*
         * Everything but the peer's host name.
         *
         * IO80211ServiceRequestDescriptor::initWithArpaTLV() takes the ARPA
         * TLV -- type 0x10, which a phone sends and we do not -- accepts a
         * length of up to 260 bytes, and expands it with uncompressAwdl()
         * into a single 512-byte global with guard bytes after it and no cap
         * on the output. When the expansion runs past the end the guard check
         * panics the machine: "bufout overflow! awdlUncompressData 1740",
         * three boots in a row at about thirty seconds, as soon as the phone
         * was heard. Nothing we can put on the wire avoids it, because the
         * TLV is the phone's and the buffer is Apple's.
         *
         * So it is left out of the copy the family is given. What it carries
         * is the peer's .local host name; peers, elections and the timeline
         * are all in other TLVs, and those still go through untouched.
         */
        u8 filtered[1024];
        size_t body_len = (size_t)(end - body);

        if (body_len >= AWDL_FIXED_LEN && body_len <= sizeof(filtered)) {
            const u8 *t = body + AWDL_FIXED_LEN;
            size_t out = AWDL_FIXED_LEN;
            bool stripped = false;

            memcpy(filtered, body, AWDL_FIXED_LEN);
            while (t + 3 <= end) {
                size_t tl = (size_t)(t[1] | (t[2] << 8));

                if (t + 3 + tl > end)
                    break;
                if (t[0] == AWDL_TLV_ARPA)
                    stripped = true;
                else {
                    memcpy(filtered + out, t, 3 + tl);
                    out += 3 + tl;
                }
                t += 3 + tl;
            }
            if (stripped && !gRx.arpa++)
                awdl_log("the peer's host name TLV is left out of what IO80211 "
                         "is given: its own decompressor overruns a fixed "
                         "buffer and panics on it");
            rtw89_glue_awdl_frame(filtered, out, mgmt->sa,
                                  ieee80211_frequency_to_channel(status->freq),
                                  status->signal);
        }
    }
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

/* ------------------------------------------------------------------ */
/*  Transmitting: building a sync frame                                 */
/* ------------------------------------------------------------------ */

/*
 * What IO80211's AWDL engine last gave us.  Broadcom's firmware buffer for
 * this is 0x724 bytes, which is the size Apple expects to be able to send;
 * the templates seen so far are nearer 110.
 */
#define AWDL_TEMPLATE_MAX   0x724

static u8 gTemplate[AWDL_TEMPLATE_MAX];
static size_t gTemplateLen;
static u8 gTemplateMac[ETH_ALEN];
static bool gTemplateMacSet;

void rtw89_awdl_set_template(const u8 *tlvs, size_t len, const u8 *mac)
{
    if (!tlvs || !len) {
        if (gTemplateLen)
            awdl_log("the sync frame template was forgotten");
        gTemplateLen = 0;
        return;
    }
    if (len > sizeof(gTemplate)) {
        awdl_log("a sync frame template of %u bytes is longer than the %u we keep",
                 (unsigned int)len, (unsigned int)sizeof(gTemplate));
        return;
    }
    memcpy(gTemplate, tlvs, len);
    gTemplateLen = len;
    if (mac) {
        memcpy(gTemplateMac, mac, ETH_ALEN);
        gTemplateMacSet = true;
    }
    awdl_log("keeping a %u byte sync frame template%s", (unsigned int)len,
             gTemplateMacSet ? "" : " (no address for it yet)");
    /*
     * What is in it, which has never been looked at.
     *
     * The template is appended to every frame we send, verbatim, and the
     * family built it while it believed this machine was the master. Our own
     * synchronisation parameters now name the peer as master, so if the
     * election TLV in here still names us the frame contradicts itself and no
     * peer would adopt us -- which is exactly the symptom: the timeline is
     * followed to within a millisecond, the channel is the master's own, 454
     * frames go out with no window missed, and the iPhone does not list this
     * machine at all.
     *
     * The TLV types are listed so the election one can be found, and the
     * bytes with them, because the layouts here are read off captures rather
     * than known.
     */
    {
        const u8 *t = gTemplate;
        const u8 *e = gTemplate + gTemplateLen;

        while (t + 3 <= e) {
            size_t tl = (size_t)(t[1] | (t[2] << 8));

            if (t + 3 + tl > e) {
                awdl_log("    a TLV of type %u claims %u bytes with %u left",
                         t[0], (unsigned int)tl, (unsigned int)(e - t - 3));
                break;
            }
            awdl_log("    template TLV type %u, %u bytes", t[0], (unsigned int)tl);
            awdl_log_hex("      its bytes", t + 3, tl < 40 ? tl : 40);
            t += 3 + tl;
        }
    }
}

size_t rtw89_awdl_get_template(const u8 **tlvs, const u8 **mac)
{
    if (!gTemplateLen || !gTemplateMacSet)
        return 0;
    if (tlvs)
        *tlvs = gTemplate;
    if (mac)
        *mac = gTemplateMac;
    return gTemplateLen;
}

/* The TLV header the decoder above walks: type, then the length little endian. */
#define AWDL_TLV_HDR_LEN    3

size_t rtw89_awdl_sync_frame_len(size_t sync_params_len, size_t tlv_len)
{
    return sizeof(struct ieee80211_hdr_3addr) + AWDL_FIXED_LEN +
           AWDL_TLV_HDR_LEN + sync_params_len + tlv_len;
}

size_t rtw89_awdl_build_sync_frame(u8 *buf, size_t size,
                                   const struct rtw89_awdl_frame_params *p)
{
    struct ieee80211_hdr_3addr *hdr;
    u8 *body, *tlv;
    size_t need;

    if (!buf || !p || !p->src || !p->sync_params || !p->sync_params_len)
        return 0;
    if (p->tlv_len && !p->tlvs)
        return 0;
    /* the length goes in a 16-bit field */
    if (p->sync_params_len > 0xffff)
        return 0;
    need = rtw89_awdl_sync_frame_len(p->sync_params_len, p->tlv_len);
    if (need > size)
        return 0;

    memset(buf, 0, need);

    /*
     * Every AWDL frame is addressed to Apple's AWDL address, as both the
     * receiver and the BSSID; the sender is the AWDL interface's own address,
     * which is not the station's.
     */
    hdr = (struct ieee80211_hdr_3addr *)buf;
    hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION);
    hdr->duration_id = 0;
    memcpy(hdr->addr1, kAwdlBssid, ETH_ALEN);
    memcpy(hdr->addr2, p->src, ETH_ALEN);
    memcpy(hdr->addr3, kAwdlBssid, ETH_ALEN);
    hdr->seq_ctrl = cpu_to_le16((u16)(p->seq << 4));

    body = buf + sizeof(*hdr);
    body[0] = WLAN_CATEGORY_VENDOR_SPECIFIC;
    memcpy(body + 1, kAppleOui, sizeof(kAppleOui));
    body[4] = AWDL_TYPE;
    body[5] = p->version;
    body[6] = p->subtype;
    body[7] = 0;                /* reserved */
    body[8]  = (u8)p->phy_tx_time;
    body[9]  = (u8)(p->phy_tx_time >> 8);
    body[10] = (u8)(p->phy_tx_time >> 16);
    body[11] = (u8)(p->phy_tx_time >> 24);
    body[12] = (u8)p->target_tx_time;
    body[13] = (u8)(p->target_tx_time >> 8);
    body[14] = (u8)(p->target_tx_time >> 16);
    body[15] = (u8)(p->target_tx_time >> 24);

    /* the schedule first, then the family's static TLVs as they were given */
    tlv = body + AWDL_FIXED_LEN;
    tlv[0] = AWDL_TLV_SYNC_PARAMS;
    tlv[1] = (u8)p->sync_params_len;
    tlv[2] = (u8)(p->sync_params_len >> 8);
    memcpy(tlv + AWDL_TLV_HDR_LEN, p->sync_params, p->sync_params_len);
    tlv += AWDL_TLV_HDR_LEN + p->sync_params_len;
    if (p->tlv_len)
        memcpy(tlv, p->tlvs, p->tlv_len);

    return need;
}

/*
 * Our own schedule, in the layout real devices use.  Values that are not the
 * schedule are what every capture carried, which is the only ground there is
 * for them; a value this file invents would be a value no receiver expects.
 *
 *   off 0..26   struct awdl_sync_params, as decoded above
 *   off 27      presence mode              4 in every capture
 *   off 28      reserved                   0
 *   off 29..30  availability window number, counts up one per window
 *   off 31..32  AP beacon alignment delta  0 in every capture
 *   off 33..38  channel sequence header: count, encoding, duplicates, step,
 *               then the fill channel
 *   off 39..70  16 slots of two bytes, the sequence itself
 *   off 71..72  unidentified, and the only bytes here that are guessed at,
 *               so they go out zero rather than wrong
 *
 * The schedule we send says we are on our one channel in every slot, which is
 * true: the driver does not hop.  A device that does puts its other channels
 * in the other slots.
 */
#define AWDL_SYNC_AW_PERIOD     16      /* TU */
#define AWDL_SYNC_AF_PERIOD     110     /* TU */
#define AWDL_SYNC_FLAGS         0x1000
#define AWDL_SYNC_EXT_LENGTH    16      /* TU */
#define AWDL_SYNC_COMMON_LENGTH 16      /* TU */
#define AWDL_SYNC_MIN_EXT       3
#define AWDL_SYNC_PRESENCE_MODE 4
#define AWDL_SYNC_SLOTS         16
#define AWDL_SYNC_STEP_COUNT    3
/* The first byte of a channel slot: 0x2b beside channel 6 in every capture.
 * It encodes the band and width; only the one we were given is known good. */
#define AWDL_SLOT_FLAGS_2GHZ    0x2b

static void awdl_put_le16(u8 *p, u16 v)
{
    p[0] = (u8)v;
    p[1] = (u8)(v >> 8);
}

size_t rtw89_awdl_build_sync_params(u8 *buf, size_t size,
                                    const struct rtw89_awdl_schedule *s)
{
    unsigned int i;
    u8 *seq;

    if (!buf || !s || !s->master || size < RTW89_AWDL_SYNC_PARAMS_LEN)
        return 0;

    memset(buf, 0, RTW89_AWDL_SYNC_PARAMS_LEN);
    buf[0] = s->channel;                        /* next AW channel */
    awdl_put_le16(buf + 1, s->tx_down_counter);
    buf[3] = s->channel;                        /* master channel */
    buf[4] = 0;                                 /* guard time */
    awdl_put_le16(buf + 5, AWDL_SYNC_AW_PERIOD);
    awdl_put_le16(buf + 7, AWDL_SYNC_AF_PERIOD);
    awdl_put_le16(buf + 9, AWDL_SYNC_FLAGS);
    awdl_put_le16(buf + 11, AWDL_SYNC_EXT_LENGTH);
    awdl_put_le16(buf + 13, AWDL_SYNC_COMMON_LENGTH);
    awdl_put_le16(buf + 15, s->remaining_aw);
    buf[17] = AWDL_SYNC_MIN_EXT;
    buf[18] = AWDL_SYNC_MIN_EXT;                /* multicast */
    buf[19] = AWDL_SYNC_MIN_EXT;                /* unicast */
    buf[20] = AWDL_SYNC_MIN_EXT;                /* action frames */
    memcpy(buf + 21, s->master, ETH_ALEN);

    buf[27] = AWDL_SYNC_PRESENCE_MODE;
    buf[28] = 0;
    awdl_put_le16(buf + 29, s->aw_seq);
    awdl_put_le16(buf + 31, 0);                 /* AP beacon alignment delta */

    buf[33] = AWDL_SYNC_SLOTS - 1;              /* count, one less than slots */
    buf[34] = 1;                                /* encoding */
    buf[35] = 0;                                /* duplicate count */
    buf[36] = AWDL_SYNC_STEP_COUNT;
    buf[37] = 0xff;                             /* fill channel */
    buf[38] = 0xff;

    seq = buf + 39;
    for (i = 0; i < AWDL_SYNC_SLOTS; i++) {
        seq[2 * i] = AWDL_SLOT_FLAGS_2GHZ;
        seq[2 * i + 1] = s->channel;
    }
    /* 71..72 left zero: see above */
    return RTW89_AWDL_SYNC_PARAMS_LEN;
}

/* ------------------------------------------------------------------ */
/*  The transmit loop                                                   */
/* ------------------------------------------------------------------ */

/*
 * One sync frame every action frame period.  The schedule says 110 TU and a
 * window is 16 TU, so a frame goes out every seventh window -- close to the
 * 112 ms the captures show between an iPhone's frames, and a whole number of
 * windows so the frame always lands at a window boundary.
 */
#define AWDL_AW_PER_AF      7
/* 802.11 sequence numbers are 12 bits. */
#define AWDL_SEQ_MASK       0x0fff

static struct {
    bool on;
    u8   channel;
    u16  aw_seq;
    u16  seq;
    u32  windows;
    u32  sent;
    u32  failed;
    u32  data_sent;
    u32  data_failed;
    int  last_err;              /* the last refusal, so a change is noticed */
    u32  waiting;               /* windows passed before the radio was ready */
    bool ready_said;
    u8   master[ETH_ALEN];      /* the master we follow, when we follow one */
} gTx;

void rtw89_awdl_tx_start(u8 channel)
{
    if (gTx.on)
        return;
    memset(&gTx, 0, sizeof(gTx));
    gTx.on = true;
    gTx.channel = channel;
    awdl_log("transmitting on channel %u, a sync frame every %u windows",
             (unsigned int)channel, (unsigned int)AWDL_AW_PER_AF);
}

void rtw89_awdl_tx_stop(void)
{
    if (!gTx.on)
        return;
    gTx.on = false;
    awdl_log("transmit stopped: %u frame(s) sent, %u not", gTx.sent, gTx.failed);
}

bool rtw89_awdl_transmitting(void)
{
    return gTx.on;
}

u32 rtw89_awdl_tx_waiting(void)
{
    return gTx.waiting;
}

void rtw89_awdl_tx_counts(u32 *sent, u32 *failed)
{
    if (sent)
        *sent = gTx.sent;
    if (failed)
        *failed = gTx.failed;
}

void rtw89_awdl_tick(u32 now_us)
{
    u8 sync_params[RTW89_AWDL_SYNC_PARAMS_LEN];
    u8 frame[RTW89_AWDL_SYNC_PARAMS_LEN + AWDL_TEMPLATE_MAX + 128];
    u8 tlv_patched[AWDL_TEMPLATE_MAX];
    struct rtw89_awdl_schedule sched;
    struct rtw89_awdl_frame_params p;
    const u8 *tlvs = NULL, *mac = NULL;
    size_t tlv_len, len;
    int err;

    if (!gTx.on)
        return;
    /*
     * The window number counts every window, whether or not we send in it --
     * including the ones spent waiting for the radio, so the timeline does
     * not shift once it is ready.
     */
    gTx.aw_seq++;
    if (gTx.windows++ % AWDL_AW_PER_AF)
        return;
    /*
     * Only the windows that would have carried a frame count as waiting, and
     * the window number advances through the wait either way, so the timeline
     * does not shift when the radio becomes ready.
     */
    if (!rtw89_mlme_awdl_tx_ready()) {
        gTx.waiting++;
        return;
    }
    if (gTx.waiting && !gTx.ready_said) {
        gTx.ready_said = true;
        awdl_log("the radio can carry frames now, after %u window(s) of waiting",
                 (unsigned int)gTx.waiting);
    }

    /* Nothing to send until IO80211's engine has given us its half. */
    tlv_len = rtw89_awdl_get_template(&tlvs, &mac);
    if (!tlv_len)
        return;

    memset(&sched, 0, sizeof(sched));
    sched.channel = gTx.channel;
    sched.tx_down_counter = 0;      /* we do not hop, so the channel never changes */
    sched.master = mac;             /* ours until a master is heard */
    sched.aw_seq = gTx.aw_seq;
    sched.remaining_aw = AWDL_SYNC_AW_PERIOD;
    /*
     * A master's window numbering and our own place in it, when one is being
     * followed. Naming ourselves master in every frame while a real device
     * was already the master is why this machine was never adopted as a peer:
     * two masters on one channel have no common timeline to be on.
     *
     * The remainder is measured against the master's own window boundary
     * rather than claimed as a whole window, so a peer can tell where in the
     * window this frame was sent.
     */
    {
        u8 maddr[ETH_ALEN];
        u64 next_aw;
        u16 mseq, mperiod;

        if (rtw89_awdl_master_timeline(maddr, &next_aw, &mseq, &mperiod)) {
            u64 now = awdl_now_us();
            u64 period_us = (u64)mperiod * 1024;
            u64 elapsed, into;

            memcpy(gTx.master, maddr, ETH_ALEN);
            sched.master = gTx.master;
            if (now >= next_aw) {
                elapsed = now - next_aw;
                into = elapsed % period_us;
                sched.aw_seq = (u16)(mseq + elapsed / period_us);
            } else {
                /* before that window begins: still in the one before it */
                into = period_us - ((next_aw - now) % period_us);
                sched.aw_seq = (u16)(mseq - 1);
            }
            sched.remaining_aw = (u16)((period_us - into) / 1024);
            gTx.aw_seq = sched.aw_seq;
        }
    }
    if (!rtw89_awdl_build_sync_params(sync_params, sizeof(sync_params), &sched))
        return;

    memset(&p, 0, sizeof(p));
    p.src = mac;
    p.version = 0x10;
    p.subtype = AWDL_SUBTYPE_PSF;
    p.seq = gTx.seq++ & AWDL_SEQ_MASK;
    /*
     * target_tx_time is when this window was due and phy_tx_time when the
     * radio actually sends.  We cannot know the latter before the fact, so
     * both are the window's time: that reports zero jitter, which is a
     * harmless lie to a receiver -- Apple's own frames are 400 us out -- and
     * an honest one would need the chip's transmit timestamp back.
     */
    p.target_tx_time = now_us;
    p.phy_tx_time = now_us;
    p.sync_params = sync_params;
    p.sync_params_len = sizeof(sync_params);
    p.tlvs = tlvs;
    p.tlv_len = tlv_len;
    /*
     * The election parameters, made to agree with the schedule.
     *
     * The family builds the template believing this machine is the master:
     * its election parameters v2 TLV carried our own address twice with a
     * metric of 0x41. Our synchronisation parameters name the peer we follow,
     * so every frame we sent said one thing in one TLV and the opposite in
     * another, and no peer would adopt a master that cannot agree with
     * itself -- which is what the iPhone never listing this machine looked
     * like, with the timeline followed to within a millisecond and 454 frames
     * going out on the master's own channel.
     *
     * A follower repeats the master's half of that TLV unchanged and keeps
     * only its own self metric and counter, so that is what is done: the
     * master's first 20 bytes as it sent them, our own tail untouched. The
     * template itself is left alone; the copy is what goes on air.
     */
    {
        u8 election[20];

        if (tlv_len <= sizeof(tlv_patched) &&
            rtw89_awdl_master_election(election)) {
            u8 *t = tlv_patched;
            const u8 *e;

            memcpy(tlv_patched, tlvs, tlv_len);
            e = tlv_patched + tlv_len;
            while (t + 3 <= e) {
                size_t tl = (size_t)(t[1] | (t[2] << 8));

                if (t + 3 + tl > e)
                    break;
                if (t[0] == AWDL_TLV_ELECTION_V2 && tl >= sizeof(election)) {
                    memcpy(t + 3, election, sizeof(election));
                    p.tlvs = tlv_patched;
                    break;
                }
                t += 3 + tl;
            }
        }
    }

    len = rtw89_awdl_build_sync_frame(frame, sizeof(frame), &p);
    if (!len)
        return;

    /*
     * Tell the family which window this is, on the master's numbering, so it
     * can keep its own timeline. Reported once per action frame window rather
     * than once per window: it is the progression the family tracks, and
     * eight a second is enough of it.
     */
    {
        u8 maddr[ETH_ALEN];

        if (rtw89_awdl_master_timeline(maddr, NULL, NULL, NULL))
            rtw89_glue_awdl_window(sched.aw_seq, maddr);
    }

    err = rtw89_mlme_tx_awdl(frame, len);
    if (err) {
        /*
         * The errno, and again whenever it changes or every 64th refusal.
         * One run sent 63 sync frames and failed 452, and the single line
         * printed at the first failure said nothing about the 451 after it --
         * which matters, because -ENETDOWN from the transmit guard and
         * -ENOMEM from the frame pool want opposite fixes, and an iPhone that
         * never sees this machine is the symptom of either.
         */
        if (!gTx.failed++ || err != gTx.last_err || gTx.failed % 64 == 0)
            awdl_log("a sync frame could not be sent: %d (%u sent, %u not)",
                     err, (unsigned int)gTx.sent, (unsigned int)gTx.failed);
        gTx.last_err = err;
        return;
    }
    if (gTx.sent++ < 4 || !(gTx.sent % 64))
        awdl_log("sync frame %u sent, %u bytes, window %u", gTx.sent,
                 (unsigned int)len, (unsigned int)gTx.aw_seq);
}

/* ------------------------------------------------------------------ */
/*  Data frames                                                         */
/* ------------------------------------------------------------------ */

/*
 * What a transfer travels in. The sync frames above only make peers aware of
 * each other; AirDrop stops at "Waiting..." until the mDNS and the TCP that
 * follow it can actually move, and those arrive from the family on awdl0.
 *
 * What arrives is not the plain Ethernet frame this code first assumed. A
 * frame from this machine, logged byte for byte, reads:
 *
 *   33 33 00 00 00 16  ea e5 39 33 01 2b  00 5c
 *   aa aa 03  00 17 f2  08 00  03 04 00 00 00 00  86 dd  ...
 *
 * The two bytes where an EtherType belongs are 0x005c -- 92, this frame's
 * length less its 14-byte header -- so it is an 802.3 length field, and what
 * follows it is already Apple's own SNAP header (OUI 00:17:f2) and the AWDL
 * data header carrying the real EtherType. The family builds all of that
 * itself. So the only thing missing is the 802.11 header: drop the 14-byte
 * 802.3 header, whose addresses the 802.11 header carries anyway, and put the
 * rest on air untouched. Wrapping it a second time, as this did before, left
 * a peer with two SNAP headers and nothing it would read.
 */

static u16 gDataSeq;

size_t rtw89_awdl_build_data_frame(u8 *buf, size_t size, const u8 *src,
                                   const u8 *eth, size_t eth_len, u16 seq)
{
    struct ieee80211_hdr_3addr *hdr;
    size_t payload, need;

    if (!buf || !src || !eth || eth_len < ETH_HLEN)
        return 0;
    payload = eth_len - ETH_HLEN;
    need = sizeof(*hdr) + payload;
    if (need > size)
        return 0;

    memset(buf, 0, sizeof(*hdr));
    hdr = (struct ieee80211_hdr_3addr *)buf;
    hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA);
    hdr->duration_id = 0;
    /* where the frame was going, which for mDNS is a multicast group */
    memcpy(hdr->addr1, eth, ETH_ALEN);
    memcpy(hdr->addr2, src, ETH_ALEN);
    memcpy(hdr->addr3, kAwdlBssid, ETH_ALEN);
    hdr->seq_ctrl = cpu_to_le16((u16)(seq << 4));

    /* the payload as the family built it: SNAP, AWDL header and all */
    memcpy(buf + sizeof(*hdr), eth + ETH_HLEN, payload);
    return need;
}

int rtw89_awdl_data_tx(const u8 *eth, size_t eth_len)
{
    u8 frame[sizeof(struct ieee80211_hdr_3addr) + 2048];
    const u8 *mac = NULL;
    size_t len;
    int err;

    /*
     * Every refusal counts as a failure and says why once.
     *
     * awdl0 handed down 38 packets and the report read "data frames 0 sent,
     * 0 not": these three returns happen before anything is counted, so a
     * path that refuses every packet looked exactly like a path nothing ever
     * reached. Which of them it is matters -- no schedule, no template and a
     * bad length are three different bugs.
     */
    if (!gTx.on) {
        if (!gTx.data_failed++)
            awdl_log("a packet from awdl0 was dropped: no schedule is running");
        return -ENETDOWN;
    }
    if (!rtw89_awdl_get_template(NULL, &mac) || !mac) {
        if (!gTx.data_failed++)
            awdl_log("a packet from awdl0 was dropped: no sync frame template, "
                     "so we have no AWDL address to send from");
        return -ENETDOWN;
    }
    if (eth_len < ETH_HLEN || eth_len > 2048 + ETH_HLEN) {
        if (!gTx.data_failed++)
            awdl_log("a packet from awdl0 was dropped: %u bytes is not a frame "
                     "we can carry", (unsigned int)eth_len);
        return -EINVAL;
    }

    len = rtw89_awdl_build_data_frame(frame, sizeof(frame), mac, eth, eth_len,
                                      gDataSeq++ & AWDL_SEQ_MASK);
    if (!len) {
        if (!gTx.data_failed++)
            awdl_log("a packet from awdl0 was dropped: it would not build into "
                     "a frame");
        return -EINVAL;
    }
    if (!gTx.data_sent && !gTx.data_failed) {
        awdl_log("the first data frame: %u bytes from awdl0 in %u on air, to "
                 "%02x:%02x:%02x:%02x:%02x:%02x, 802.3 length %u",
                 (unsigned int)eth_len, (unsigned int)len,
                 eth[0], eth[1], eth[2], eth[3], eth[4], eth[5],
                 (unsigned int)((eth[12] << 8) | eth[13]));
        awdl_log_hex("as the family built it", eth, eth_len < 48 ? eth_len : 48);
    }
    err = rtw89_mlme_tx_awdl(frame, len);
    if (err) {
        if (!gTx.data_failed++)
            awdl_log("the first data frame could not be sent: %d", err);
    } else {
        gTx.data_sent++;
    }
    return err;
}

void rtw89_awdl_data_counts(u32 *sent, u32 *failed)
{
    if (sent)
        *sent = gTx.data_sent;
    if (failed)
        *failed = gTx.data_failed;
}
