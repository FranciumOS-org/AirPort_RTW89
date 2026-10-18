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

/* How many bytes rtw89_awdl_build_sync_frame() would write. */
size_t rtw89_awdl_sync_frame_len(size_t sync_params_len, size_t tlv_len);

/* Writes the frame into @buf, returning its length, or 0 if it does not fit
 * or the parameters are incomplete. */
size_t rtw89_awdl_build_sync_frame(u8 *buf, size_t size,
                                   const struct rtw89_awdl_frame_params *p);

#endif /* RTW89_AWDL_H */
