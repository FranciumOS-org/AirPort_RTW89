/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Watching AWDL go by: the receive half of the AirDrop work. Apple devices
 * send AWDL sync frames on the social channels (6, 44, 149) all the time, so
 * before the driver tries to join that timeline it can measure it.
 *
 * Nothing here transmits and nothing here answers macOS; it only reads frames
 * the chip already gives us, and only while rtw89_awdl_watch() is on.
 */
#ifndef RTW89_AWDL_H
#define RTW89_AWDL_H

#include <linux/types.h>

struct sk_buff;

/* True if @skb is an AWDL action frame; it is logged and left alone. */
bool rtw89_awdl_rx(struct sk_buff *skb, size_t len);

/* Hand received AWDL action frames to IO80211's AWDL engine as well as logging
 * them. Off until the driver has a virtual interface to give them to. */
void rtw89_awdl_deliver(bool on);
bool rtw89_awdl_delivering(void);

/* Turn the watch on or off, and report. */
void rtw89_awdl_watch(bool on);
bool rtw89_awdl_watching(void);

/*
 * Building a sync frame to transmit.
 *
 * IO80211's AWDL engine hands the driver a "sync frame template" which is not
 * a frame: it is the static TLVs only (service parameters, election
 * parameters, data path state, version), with no 802.11 header, no action
 * frame header and no timestamps.  Broadcom passes that blob to its firmware
 * and the firmware builds the frame; having no such firmware, we build it.
 *
 * The synchronisation parameters are passed in rather than composed here: the
 * TLV real devices send is longer than the fixed part this file decodes, the
 * tail being the channel sequence, and that layout is not yet read off a
 * capture.  Handing the payload in keeps the invention out of the frame.
 */
struct rtw89_awdl_frame_params {
    const u8 *src;              /* our AWDL address, the sender */
    u8  version;                /* as seen on air, 0x10 */
    u8  subtype;                /* 0 PSF, 3 MIF */
    u16 seq;                    /* 802.11 sequence number */
    u32 phy_tx_time;            /* us, when the radio transmitted */
    u32 target_tx_time;         /* us, when we meant it to */
    const u8 *sync_params;      /* the synchronisation parameters TLV payload */
    size_t sync_params_len;
    const u8 *tlvs;             /* the family's template, appended verbatim */
    size_t tlv_len;
};

/*
 * Keep the template IO80211 built, and the address it built it for, for the
 * transmit loop to use.  @len of 0 forgets it.  The bytes are copied.
 */
void rtw89_awdl_set_template(const u8 *tlvs, size_t len, const u8 *mac);

/* The template, or 0 with *tlvs untouched if there is none yet. */
size_t rtw89_awdl_get_template(const u8 **tlvs, const u8 **mac);

/*
 * The synchronisation parameters we send: our own availability window
 * schedule.  73 bytes, the length real devices send.
 *
 * The fixed half (offsets 0..26) is struct awdl_sync_params, decoded against
 * real frames.  The rest was read off five captures from one iPhone on
 * 2026-10-18 by diffing them: everything was identical except the transmit
 * down counter, the window remainder, the sequence number and the last two
 * bytes, which is what let the fields below be told apart from padding.
 * The last two bytes are still unidentified and go out zero.
 */
struct rtw89_awdl_schedule {
    u8  channel;            /* the social channel we sit on */
    u16 tx_down_counter;    /* availability windows until the channel changes */
    u16 remaining_aw;       /* TU left in the window this frame goes out in */
    u16 aw_seq;             /* availability window number, +1 each window */
    const u8 *master;       /* the master's address: ours until elected out */
};

/* Writes the 73 byte payload into @buf; returns its length, or 0 if it does
 * not fit.  RTW89_AWDL_SYNC_PARAMS_LEN bytes are needed. */
#define RTW89_AWDL_SYNC_PARAMS_LEN  73
size_t rtw89_awdl_build_sync_params(u8 *buf, size_t size,
                                    const struct rtw89_awdl_schedule *s);

/* How many bytes rtw89_awdl_build_sync_frame() would write. */
size_t rtw89_awdl_sync_frame_len(size_t sync_params_len, size_t tlv_len);

/* Writes the frame into @buf, returning its length, or 0 if it does not fit
 * or the parameters are incomplete. */
size_t rtw89_awdl_build_sync_frame(u8 *buf, size_t size,
                                   const struct rtw89_awdl_frame_params *p);

/*
 * The transmit loop.  rtw89_awdl_tx_start() takes the channel we sit on;
 * after it, one call to rtw89_awdl_tick() per availability window, with the
 * time that window was due, drives the schedule and sends a sync frame every
 * action frame period.  @now_us is the window's own time, not the time the
 * call happens to arrive, so a late wake-up still stamps the frame with the
 * window it belongs to.
 */
void rtw89_awdl_tx_start(u8 channel);
void rtw89_awdl_tx_stop(void);
bool rtw89_awdl_transmitting(void);
void rtw89_awdl_tick(u32 now_us);

/* How many frames went out, and how many could not. */
void rtw89_awdl_tx_counts(u32 *sent, u32 *failed);

/*
 * Data frames: what a transfer travels in, once peers know about each other.
 * @eth is a whole Ethernet frame as the family handed it to awdl0.
 */
size_t rtw89_awdl_build_data_frame(u8 *buf, size_t size, const u8 *src,
                                   const u8 *eth, size_t eth_len, u16 seq);
int rtw89_awdl_data_tx(const u8 *eth, size_t eth_len);
void rtw89_awdl_data_counts(u32 *sent, u32 *failed);

#endif /* RTW89_AWDL_H */
