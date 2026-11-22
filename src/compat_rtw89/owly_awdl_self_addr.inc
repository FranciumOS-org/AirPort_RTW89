/* SPDX-License-Identifier: GPL-2.0 */
/* Based on FranciumOS-org/AirPort_RTW89 rtw89_compat_set_self_addr().
 * Only the idle MLME coordinator calls this. Keep the associated station's
 * hardware identity intact. Firmware errors roll back software and retry the
 * previous CAM; a forced restore also revalidates uncertain firmware state. */
int rtw89_compat_awdl_self_addr(struct ieee80211_vif *vif,const u8 *addr,bool force);
int rtw89_compat_awdl_self_addr(struct ieee80211_vif *vif,const u8 *addr,bool force)
{
    struct rtw89_vif *rtwvif;
    struct rtw89_vif_link *link;
    struct rtw89_dev *rtwdev;
    u8 previous[ETH_ALEN];
    int ret, rollback;
    if(!vif || !addr || is_zero_ether_addr(addr) || is_multicast_ether_addr(addr))
        return -EINVAL;
    rtwvif=vif_to_rtwvif(vif);
    if(!rtwvif || !rtwvif->rtwdev || !rtwvif->dlink_pool.next ||
       !rtwvif->dlink_pool.prev || list_empty(&rtwvif->dlink_pool))return -ENETDOWN;
    rtwdev=rtwvif->rtwdev;
    lockdep_assert_wiphy(rtwdev->hw->wiphy);
    link=rtw89_get_designated_link(rtwvif);
    if(!link || !link->addr_cam.valid)return -ENETDOWN;
    /* RTL8852BT is the same CAM and firmware interface as the RTL8852B, and
     * like it reports support_chanctx_num 2, which is what the AWDL channel
     * context needs. Taking a station's own address back on leaving AWDL is
     * exactly the same CAM write there. */
    if(rtwdev->chip->chip_id!=RTL8852B && rtwdev->chip->chip_id!=RTL8852BT)
        return -EOPNOTSUPP;
    if(vif->p2p || vif->type!=NL80211_IFTYPE_STATION || vif->cfg.assoc ||
       link->net_type!=RTW89_NET_TYPE_NO_LINK || rtwdev->scanning)return -EBUSY;
    if(!force && ether_addr_equal(link->mac_addr,addr))return 0;
    ether_addr_copy(previous,link->mac_addr);
    ether_addr_copy(link->mac_addr,addr);
    ret=rtw89_fw_h2c_cam(rtwdev,link,NULL,addr,RTW89_ROLE_INFO_CHANGE);
    if(!ret)return 1;
    ether_addr_copy(link->mac_addr,previous);
    rollback=rtw89_fw_h2c_cam(rtwdev,link,NULL,previous,RTW89_ROLE_INFO_CHANGE);
    if(rollback)rtw89_err(rtwdev,"AWDL self-address CAM rollback failed: %d\n",rollback);
    return ret;
}
