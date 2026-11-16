// SPDX-License-Identifier: GPL-2.0
/*
 * core.c (through its wrapper) with rtw89_chip_info_setup() replaced, for the second smoke-test
 * binary (hosttest_fakechip).
 *
 * The real function powers the chip on, downloads firmware and reads the
 * efuse, which nothing in userspace can answer. This version keeps every step
 * that is pure software (waiting for and parsing the real firmware image, chip
 * data and RFE parameter setup) and fills in by hand what the hardware would
 * have reported. Probe then runs on through IRQ setup and rtw89_core_register()
 * and the test can remove a fully probed device, which the dead-device run
 * never reaches.
 */
#define rtw89_chip_info_setup rtw89_real_chip_info_setup
#define rtw89_core_start rtw89_real_core_start
#define rtw89_core_stop rtw89_real_core_stop
#include "rtw89_core_wrap.c"
#undef rtw89_chip_info_setup
#undef rtw89_core_start
#undef rtw89_core_stop

#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
#include "rtw89_net80211.h"

/* OWLY_FAKE_CONNECTED_SCAN_MODEL_BEGIN */

/* HOST TEST ONLY: this translation unit is linked instead of core_wrap.o
 * in hosttest_fakechip, never in the real kext. The pretend device consumes
 * TX rings but emits no firmware packet-offload acknowledgement, so a real
 * connected hw_scan fails before it can exercise scan/VIF interleaving.
 * Model only that firmware boundary. Real glue request building/completion,
 * wiphy worker, VIF and channel assign/unassign operations remain in use.
 * Do not set rtwdev->scanning or claim firmware/RF scan coverage.
 */
static struct ieee80211_ops owly_fake_radio_ops;
static const struct ieee80211_ops *owly_fake_original_ops;
static struct ieee80211_vif *owly_fake_scan_vif;

static int owly_fake_connected_scan(struct ieee80211_hw *hw,
                                     struct ieee80211_vif *vif,
                                     struct ieee80211_scan_request *req)
{
    lockdep_assert_wiphy(hw->wiphy);
    if (!vif || !req || !req->req.n_channels)
        return -EINVAL;
    /* Preserve existing disconnected-scan coverage; only this new
     * connected interleaving test uses a modeled offload boundary. */
    if (!vif->cfg.assoc)
        return owly_fake_original_ops->hw_scan(hw, vif, req);
    if (owly_fake_scan_vif)
        return -EBUSY;
    owly_fake_scan_vif = vif;
    IOLog("== AWDL SCC scan fixture: start (simulated firmware boundary)\n");
    return 0;
}

static void owly_fake_cancel_scan(struct ieee80211_hw *hw,
                                  struct ieee80211_vif *vif)
{
    struct cfg80211_scan_info info = { .aborted = true };
    lockdep_assert_wiphy(hw->wiphy);
    if (owly_fake_scan_vif == vif) {
        owly_fake_scan_vif = NULL; /* clear before completion can queue work */
        IOLog("== AWDL SCC scan fixture: complete (simulated firmware boundary)\n");
        ieee80211_scan_completed(hw, &info);
        return;
    }
    owly_fake_original_ops->cancel_hw_scan(hw, vif);
}

static void owly_fake_install_scan_model(struct ieee80211_hw *hw)
{
    struct rtw89_m80211_local *local = hw_to_local(hw);
    lockdep_assert_wiphy(hw->wiphy);
    if (local->ops != &owly_fake_radio_ops) {
        owly_fake_original_ops = local->ops;
        owly_fake_radio_ops = *local->ops;
        owly_fake_radio_ops.hw_scan = owly_fake_connected_scan;
        owly_fake_radio_ops.cancel_hw_scan = owly_fake_cancel_scan;
        local->ops = &owly_fake_radio_ops;
    }
    owly_fake_scan_vif = NULL;
}
/* OWLY_FAKE_CONNECTED_SCAN_MODEL_END */
#endif

/*
 * Starting the radio is hardware from top to bottom (MAC/BB/RF init, firmware
 * download, calibration). Pretend it worked, so the test can go on to add an
 * interface, build a scan request and take it all down again; the commands
 * the driver then sends go into a firmware-command ring nobody drains.
 */
int rtw89_core_start(struct rtw89_dev *rtwdev)
{
#if defined(OWLY_AWDL_RADIO_SCC) && OWLY_AWDL_RADIO_SCC
    owly_fake_install_scan_model(rtwdev->hw);
#endif
    /* The driver checks these enable bits before touching the MAC. */
    rtw89_write32_set(rtwdev, R_AX_DMAC_FUNC_EN, B_AX_MAC_FUNC_EN | B_AX_DMAC_FUNC_EN);
    rtw89_write32_set(rtwdev, R_AX_CMAC_FUNC_EN, B_AX_CMAC_EN);

    set_bit(RTW89_FLAG_POWERON, rtwdev->flags);

    /* As the real start does: the periodic tracking works run while up. */
    wiphy_delayed_work_queue(rtwdev->hw->wiphy, &rtwdev->track_work,
                             RTW89_TRACK_WORK_PERIOD);
    wiphy_delayed_work_queue(rtwdev->hw->wiphy, &rtwdev->track_ps_work,
                             RTW89_TRACK_PS_WORK_PERIOD);

    set_bit(RTW89_FLAG_RUNNING, rtwdev->flags);
    return 0;
}

void rtw89_core_stop(struct rtw89_dev *rtwdev)
{
    struct wiphy *wiphy = rtwdev->hw->wiphy;

    if (!test_bit(RTW89_FLAG_RUNNING, rtwdev->flags))
        return;

    clear_bit(RTW89_FLAG_RUNNING, rtwdev->flags);
    wiphy_delayed_work_cancel(wiphy, &rtwdev->track_work);
    wiphy_delayed_work_cancel(wiphy, &rtwdev->track_ps_work);
    cancel_delayed_work_sync(&rtwdev->txq_reinvoke_work);
    /* As the real stop does: frames the chip never reported as sent are
     * released and the rings start from zero. The pretend chip reports none,
     * so without this a second start (Wi-Fi off and on, sleep and wake)
     * finds no transmit room left. */
    rtw89_hci_reset(rtwdev);
    clear_bit(RTW89_FLAG_POWERON, rtwdev->flags);
}

int rtw89_chip_info_setup(struct rtw89_dev *rtwdev)
{
    static const u8 mac[ETH_ALEN] = { 0x00, 0xe0, 0x4c, 0x88, 0x52, 0xbe };
    const struct rtw89_chip_info *chip = rtwdev->chip;
    struct rtw89_efuse *efuse = &rtwdev->efuse;
    struct rtw89_hal *hal = &rtwdev->hal;
    int ret;

    hal->cv = CHIP_CBV;                 /* rtw89_read_chip_ver() */

    ret = rtw89_wait_firmware_completion(rtwdev);
    if (ret)
        return ret;

    ret = rtw89_fw_recognize(rtwdev);
    if (ret)
        return ret;

    /* rtw89_chip_efuse_info_setup(): efuse and PHY capability */
    ether_addr_copy(efuse->addr, mac);
    efuse->rfe_type = 1;
    hal->tx_nss = chip->tx_nss;
    hal->rx_nss = chip->rx_nss;
    hal->antenna_tx = RF_AB;
    hal->antenna_rx = RF_AB;
    rtw89_core_setup_phycap(rtwdev);

    ret = rtw89_fw_recognize_elements(rtwdev);
    if (ret)
        return ret;

    ret = rtw89_chip_board_info_setup(rtwdev);
    if (ret)
        return ret;

    ret = rtw89_chip_data_setup(rtwdev);
    if (ret)
        return ret;

    rtw89_core_setup_rfe_parms(rtwdev);
    rtwdev->ps_mode = rtw89_update_ps_mode(rtwdev);

    return 0;
}
