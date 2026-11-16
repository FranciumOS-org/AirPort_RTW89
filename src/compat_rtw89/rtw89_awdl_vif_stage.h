// SPDX-License-Identifier: MIT
// OWLY Core-04C: address policy for a *staged* P2P-client VIF.
// NOT an AWDL link implementation. Pure helper, no hardware access.
#ifndef RTW89_AWDL_VIF_STAGE_H
#define RTW89_AWDL_VIF_STAGE_H
static inline int owly_core04c_make_mac(const unsigned char src[6],
                                         unsigned char dst[6])
{
    unsigned int i;
    unsigned int nonzero = 0;
    if (!src || !dst || src == dst)
        return 0;
    for (i = 0; i < 6u; ++i) {
        dst[i] = src[i];
        nonzero |= src[i];
    }
    if (!nonzero || (src[0] & 1u))
        return 0;
    dst[0] = (unsigned char)((src[0] | 0x02u) & 0xfeu);
    dst[5] ^= 0x80u; /* distinct even if source is already locally administered */
    return 1;
}
#endif
