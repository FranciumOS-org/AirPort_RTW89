// SPDX-License-Identifier: GPL-2.0
/*
 * The driver's core.c, unmodified, plus one function that needs access to its
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

/*
 * Whether an AWDL frame may be handed to rtw89_ops_tx() for this vif.
 *
 * rtw89_core_tx_write() finds the link with rtw89_get_designated_link(), which
 * is list_first_entry_or_null() over rtwvif->dlink_pool. On a vif whose link
 * pool has never been set up, or has just been torn down, that list head is
 * zeroed: head->next is NULL, which is not equal to head, so the list does not
 * look empty, and container_of(NULL, struct rtw89_vif_link, dlink_schd) comes
 * back as a pointer eight bytes below zero. It survives the driver's own
 * `if (!rtwvif_link)` check and is dereferenced one line later. That is the
 * panic at rtw89_core_tx_write_link+0x2e with CR2 0xfffffffffffffff8, hit by
 * the availability-window clock still firing while the radio was going down.
 *
 * Checking the list head itself is what the driver cannot do for us here, so
 * the AWDL path asks first. Ordinary traffic never reaches this: it is sent
 * with a station, which takes the other branch.
 */
bool rtw89_compat_vif_can_tx(struct ieee80211_vif *vif);
bool rtw89_compat_vif_can_tx(struct ieee80211_vif *vif)
{
    struct rtw89_vif *rtwvif;

    if (!vif)
        return false;
    rtwvif = vif_to_rtwvif(vif);
    if (!rtwvif)
        return false;
    if (!rtwvif->dlink_pool.next || !rtwvif->dlink_pool.prev)
        return false;
    if (list_empty(&rtwvif->dlink_pool))
        return false;
    return rtw89_get_designated_link(rtwvif) != NULL;
}

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
int rtw89_compat_set_self_addr(struct ieee80211_vif *vif, const u8 *addr);
int rtw89_compat_set_self_addr(struct ieee80211_vif *vif, const u8 *addr)
{
    struct rtw89_vif_link *rtwvif_link;
    struct rtw89_vif *rtwvif;
    struct rtw89_dev *rtwdev;
    int ret;

    if (!vif || !addr)
        return -EINVAL;
    if (!rtw89_compat_vif_can_tx(vif))
        return -ENETDOWN;
    rtwvif = vif_to_rtwvif(vif);
    rtwdev = rtwvif->rtwdev;
    rtwvif_link = rtw89_get_designated_link(rtwvif);
    if (!rtwdev || !rtwvif_link)
        return -ENETDOWN;
    if (ether_addr_equal(rtwvif_link->mac_addr, addr))
        return 0;               /* already there: nothing was changed */
    ether_addr_copy(rtwvif_link->mac_addr, addr);
    ret = rtw89_fw_h2c_cam(rtwdev, rtwvif_link, NULL, addr,
                           RTW89_ROLE_INFO_CHANGE);
    return ret ? ret : 1;       /* 1: it was changed, so a caller can say so */
}
