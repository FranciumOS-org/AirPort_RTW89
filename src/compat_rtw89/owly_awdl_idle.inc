/* SPDX-License-Identifier: GPL-2.0 */
/* Modified for AirPort_RTW89: no unassign_vif_chanctx call on chips without one. */
/* The idle-channel transaction follows FranciumOS-org/AirPort_RTW89's
 * rtw89_mlme_awdl_hold_channel(), with the auxiliary-VIF release hook and
 * the existing regulatory checks retained. Called only under wiphy. */
int rtw89_compat_awdl_self_addr(struct ieee80211_vif *vif,const u8 *addr,bool force);

int rtw89_mlme_awdl_set_self_addr(const u8 *addr)
{
    int ret;
    if(!addr && !mlme.awdl_self_addr)return 0;
    if(!mlme.running || !mlme.hw || !mlme.vif)return -ENETDOWN;
    lockdep_assert_wiphy(mlme.hw->wiphy);
    if(addr && (mlme.state!=RTW89_MLME_IDLE || !mlme.awdl_chanctx))return -EBUSY;
    ret=rtw89_compat_awdl_self_addr(mlme.vif,addr ? addr : mlme.vif->addr,!addr);
    /*
     * -EOPNOTSUPP is this chip having no self-address write at all, not a
     * write that went wrong: rtw89_compat_awdl_self_addr() refuses on the
     * chip check before it touches the CAM. Nothing was changed, so there is
     * nothing to remember or restore, and an optional AirDrop feature the
     * card never had must not hold back an ordinary join. Seen on the
     * RTL8852BTE (10ec:b520): it has the idle channel, so this path runs, and
     * every join aborted with -95 before the first frame was sent.
     */
    if(ret==-EOPNOTSUPP) {
        mlme.awdl_self_addr=false;
        mlme.awdl_self_addr_error=0;
        return 0;
    }
    if(ret>=0) {
        mlme.awdl_self_addr=addr!=NULL;
        mlme.awdl_self_addr_error=0;
    } else {
        if(addr)mlme.awdl_self_addr=true; /* uncertain writes require forced restore */
        mlme.awdl_self_addr_error=ret;
        mlme_info("AWDL self-address: mode=%s firmware_result=%d (not RX/ACK proof)",
                  addr ? "awdl0" : "station",ret);
    }
    return ret<0 ? ret : 0;
}

static void owly_mlme_release_chanctx(void)
{
    const struct ieee80211_ops *ops = mlme.local->ops;
    struct ieee80211_bss_conf *conf = &mlme.vif->bss_conf;
    const bool owned = mlme.awdl_chanctx;
    /* Restore before unassign/free and before another AP can use this port. */
    (void)rtw89_mlme_awdl_set_self_addr(NULL);
    mlme.awdl_chanctx = false; /* withdraw RX eligibility before unassignment */
    if (mlme.chanctx) {
        if (owly_core04d_before_release)
            owly_core04d_before_release(mlme.chanctx);
        if (mlme.chanctx_assigned) {
            /* absent when rtw89 emulates channel contexts (RTL8851B,
             * RTL8852A): every join's release comes through here */
            if (ops->unassign_vif_chanctx)
                ops->unassign_vif_chanctx(mlme.hw, mlme.vif, conf, mlme.chanctx);
            conf->chanctx_conf = NULL;
            mlme.chanctx_assigned = false;
        }
        ops->remove_chanctx(mlme.hw, mlme.chanctx);
        kfree(mlme.chanctx);
        mlme.chanctx = NULL;
    }
    mlme.awdl_chanctx = false;
    if (owned) { mlme.chan = NULL; mlme.sband = NULL; }
    memset(&conf->chanreq, 0, sizeof(conf->chanreq));
}

int rtw89_mlme_awdl_hold_channel(u16 freq)
{
    const struct ieee80211_ops *ops;
    struct ieee80211_bss_conf *conf;
    struct ieee80211_channel *chan;
    struct ieee80211_chanctx_conf *ctx;
    struct cfg80211_chan_def chandef;
    int ret;
    if (!mlme.running || !mlme.hw || !mlme.vif || !mlme.local)
        return -ENETDOWN;
    lockdep_assert_wiphy(mlme.hw->wiphy);
    if (mlme.state != RTW89_MLME_IDLE || (mlme.chanctx && !mlme.awdl_chanctx))
        return -EBUSY;
    if (freq != 2437 && freq != 5220 && freq != 5745) return -EINVAL;
    chan = ieee80211_get_channel(mlme.hw->wiphy, freq);
    if (!chan || (chan->flags & (IEEE80211_CHAN_DISABLED | IEEE80211_CHAN_NO_IR |
                                IEEE80211_CHAN_RADAR))) return -EACCES;
    if (mlme.awdl_chanctx && mlme.chan == chan) return 0;
    ops = mlme.local->ops;
    if (!ops->add_chanctx || !ops->remove_chanctx ||
        !ops->assign_vif_chanctx || !ops->unassign_vif_chanctx) return -EOPNOTSUPP;
    ctx = kzalloc(sizeof(*ctx) + mlme.hw->chanctx_data_size, GFP_KERNEL);
    if (!ctx) return -ENOMEM;
    cfg80211_chandef_create(&chandef, chan, NL80211_CHAN_NO_HT);
    ctx->def = ctx->min_def = chandef;
    ctx->rx_chains_static = ctx->rx_chains_dynamic = 1;
    if (mlme.awdl_chanctx) owly_mlme_release_chanctx();
    ret = ops->add_chanctx(mlme.hw, ctx);
    if (ret) { kfree(ctx); return ret; }
    conf = &mlme.vif->bss_conf;
    conf->chanreq.oper = chandef;
    ret = ops->assign_vif_chanctx(mlme.hw, mlme.vif, conf, ctx);
    if (ret) {
        ops->remove_chanctx(mlme.hw, ctx); kfree(ctx);
        memset(&conf->chanreq, 0, sizeof(conf->chanreq));
        return ret;
    }
    conf->chanctx_conf = ctx;
    mlme.chanctx = ctx; mlme.chanctx_assigned = true; mlme.awdl_chanctx = true;
    mlme.chan = chan; mlme.sband = mlme.hw->wiphy->bands[chan->band];
    mlme.chandef = chandef;
    mlme_info("AWDL owns %u MHz / 20 MHz; station remains unassociated", freq);
    return 0;
}

void rtw89_mlme_awdl_release_channel(void)
{
    if (!mlme.running || !mlme.awdl_chanctx) return;
    lockdep_assert_wiphy(mlme.hw->wiphy);
    owly_mlme_release_chanctx();
}
