// SPDX-License-Identifier: MIT
// Core-04B: strict AWDL Action frame preflight. No TX and no global state.
#ifndef RTW89_AWDL_MGMT_GATE_H
#define RTW89_AWDL_MGMT_GATE_H
#include <stddef.h>

#define OWLY_AWDL_MGMT_MIN 40u
#define OWLY_AWDL_MGMT_MAX 1024u

static inline int owly_awdl_mgmt_gate(const unsigned char *f, size_t n,
                                      const unsigned char *local_mac)
{
    static const unsigned char bssid[6] = {0x00,0x25,0x00,0xff,0x94,0x73};
    unsigned int i;
    if (!f || !local_mac || n < OWLY_AWDL_MGMT_MIN || n > OWLY_AWDL_MGMT_MAX)
        return 0;
    /* An unprotected management Action frame without DS direction bits. */
    if (f[0] != 0xd0 || f[1] != 0 || f[2] != 0 || f[3] != 0)
        return 0;
    for (i = 4; i < 10; ++i)
        if (f[i] != 0xff) return 0; /* broadcast destination => NO_ACK */
    for (i = 0; i < 6; ++i) {
        if (f[10 + i] != local_mac[i]) return 0;
        if (f[16 + i] != bssid[i]) return 0;
    }
    /* Apple vendor Action, OUI 00:17:f2, AWDL type 08, PSF/MIF. */
    if (f[24] != 127 || f[25] != 0 || f[26] != 0x17 ||
        f[27] != 0xf2 || f[28] != 0x08 || f[29] == 0 ||
        (f[30] != 0 && f[30] != 3) || f[31] != 0)
        return 0;
    /* Syntactic preflight only. This does not validate TLVs/election/TSF. */
    return 1;
}
#endif
