/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_SCC_RX_POLICY_H
#define OWLY_SCC_RX_POLICY_H

/* AP must be associated AND the auxiliary Realtek VIF must exist.
 * Social frequencies: ch6=2437, ch44=5220, ch149=5745 MHz.
 * This is only a receive-filter policy, NOT AWDL scheduling or a TX grant.
 * A new AP channel is never inferred from scan RX frequency.
 */
static inline int owly_scc_rx_should_enable(int connected,
                                            int auxiliary_vif_registered,
                                            unsigned int primary_ap_freq_mhz)
{
    if (!connected || !auxiliary_vif_registered)
        return 0;
    return primary_ap_freq_mhz == 2437u ||
           primary_ap_freq_mhz == 5220u ||
           primary_ap_freq_mhz == 5745u;
}
#endif
