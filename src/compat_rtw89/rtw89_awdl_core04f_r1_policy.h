// SPDX-License-Identifier: MIT
// OWLY Core-04F R1: conservative 2.4 GHz-only diagnostic channel predicate.
// This does not grant regulatory permission: existing channel flags must allow TX.
#ifndef RTW89_AWDL_CORE04F_R1_POLICY_H
#define RTW89_AWDL_CORE04F_R1_POLICY_H
static inline int owly_core04f_r1_chan_eligible(unsigned int freq_mhz,
                                                 int is_2ghz,
                                                 unsigned int flags,
                                                 unsigned int forbidden_mask)
{
    return is_2ghz && freq_mhz >= 2412 && freq_mhz <= 2462 &&
           ((freq_mhz - 2412) % 5u) == 0u &&
           (flags & forbidden_mask) == 0u;
}
#endif
