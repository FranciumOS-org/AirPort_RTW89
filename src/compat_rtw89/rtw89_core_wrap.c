// SPDX-License-Identifier: GPL-2.0
/*
 * The driver's core.c plus one function that needs access to its
 * static helpers. This file is compiled in place of third_party/rtw89/core.c.
 *
 * Why: rtw89_core_rx() parks every received data frame on ppdu_sts.rx_queue
 * until the chip's status report for the same transmission (PPDU) arrives, so
 * that the signal measurements can be attached to it; if no report comes, the
 * frame is passed on when the next transmission is received. On the RTL8852BE
 * in this machine the report does not come for most data frames (measured:
 * four in ten frames of a download, nearly all sparse ones), and the next
 * thing received was then the access point's beacon, up to 102 ms later.
 * rtw89_glue.c therefore calls rtw89_compat_flush_ppdu_rx() a couple of
 * milliseconds after a poll that left frames parked.
 */
#include "core.c"

#if defined(RTW89_MACOS) && defined(OWLY_NATIVE_PEER_DATA) && OWLY_NATIVE_PEER_DATA
#include "owly_awdl_self_addr.inc"
#include "owly_unicast_observe.h"
void rtw89_compat_awdl_rx_note(const struct rtw89_rx_desc_info *d,const struct sk_buff *skb)
{
    static volatile unsigned long samples;
    if(!d || !skb || !owly_observe_unicast_frame(skb->data,skb->len))return;
    const unsigned long count=__sync_add_and_fetch(&samples,1ul);
    if(count>8ul && (count&(count-1ul)))return;
    IOLog("OWLY unicast RX hardware: count=%lu crc=%u icv=%u cam_valid=%u cam=%u a1=%u macid=%u bytes=%u\n",
          count,(unsigned)d->crc32_err,(unsigned)d->icv_err,(unsigned)d->addr_cam_valid,
          (unsigned)d->addr_cam_id,(unsigned)d->addr1_match,(unsigned)d->mac_id,(unsigned)skb->len);
}
#endif

/* Pass on whatever is still waiting for a PPDU status report. Must run on the
 * thread that calls rtw89_core_rx(). Returns the number of frames. */
unsigned int rtw89_compat_flush_ppdu_rx(struct rtw89_dev *rtwdev);
unsigned int rtw89_compat_flush_ppdu_rx(struct rtw89_dev *rtwdev)
{
    /* what the driver's own flush is given, minus a frame to take it from:
     * band 0, and nothing known about the transmission that ends the wait */
    struct rtw89_rx_desc_info desc_info = {};
    unsigned int n = skb_queue_len(&rtwdev->ppdu_sts.rx_queue[RTW89_PHY_0]);

    if (n)
        rtw89_core_flush_ppdu_rx_queue(rtwdev, &desc_info);
    return n;
}

/*
 * Change the address the chip answers to, so it acknowledges AWDL.
 *
 * An iPhone that has decided to talk to us addresses its frames to awdl0's own
 * MAC, which is not the station's. The chip receives them -- receive is
 * promiscuous while AWDL runs -- but nothing acknowledges them, because A1
 * matching and the hardware's acknowledgement both come from the self address
 * in the port's address CAM (rtw89_cam_fill_addr_cam_info() takes it from
 * rtwvif_link->mac_addr). Measured: 1216 frames from the phone addressed to
 * our AWDL address, 1155 of them retries, while everything we sent it was
 * acknowledged. It hears us, it wants us, and it never gets an answer.
 *
 * The driver already reprograms that address for a scan with a random MAC --
 * rtw89_core_scan_start() copies the new one in and sends the CAM update --
 * so this is the same two steps without the scan's own business (RF
 * calibration, coexistence, EDCCA), which has nothing to do with an address.
 *
 * One address at a time, which is why this is only safe with no network
 * joined: an association needs the station address to be the one acknowledged.
 * Holding both at once needs a second port, and this is the experiment that
 * says whether that work is worth doing.
 *
 * Returns 1 when the address was changed, 0 when it was already that one, or a
 * negative errno. The caller keeps no state of its own: asking again costs
 * nothing, which is what makes a join putting the station's address back
 * behind the glue's back harmless.
 */
