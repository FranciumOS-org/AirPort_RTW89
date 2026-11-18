/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Software TKIP (WPA, IEEE 802.11-2020 12.5.2) for the frames the chip hands
 * up still encrypted: the per-packet RC4 key mixing, RC4 with the CRC-32 ICV,
 * and the Michael MIC. Plain C with no Linux or kernel types, so the userspace
 * test can build the same code.
 *
 * The S-box and the key mixing follow net/mac80211/tkip.c and the Michael MIC
 * follows net/wireless/michael-mic.c in Linux (GPL-2.0). Replay checks and the
 * Michael MIC check on receive are the caller's job.
 */
#ifndef _RTW89_TKIP_H
#define _RTW89_TKIP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key: temporal key 16 | AP-to-station MIC key 8 | station-to-AP MIC key 8. */
#define RTW89_TKIP_KEY_LEN 32
/* Header: TSC1 WEPSeed TSC0 KeyID|ExtIV TSC2 TSC3 TSC4 TSC5. */
#define RTW89_TKIP_HDR_LEN 8
#define RTW89_TKIP_MIC_LEN 8
#define RTW89_TKIP_ICV_LEN 4

/* Michael MIC (IEEE 802.11 12.5.2.3) over DA | SA | priority | 0 0 0 | data. */
void rtw89_michael_mic(const uint8_t key[8], const uint8_t da[6], const uint8_t sa[6],
                       uint8_t priority, const uint8_t *data, size_t len,
                       uint8_t mic[RTW89_TKIP_MIC_LEN]);

/*
 * Decrypt one TKIP MPDU in place. @body is everything after the 802.11 header:
 * the 8-byte TKIP header, then the ciphertext of (data | 8-byte MIC | 4-byte ICV);
 * @body_len counts all of it. @ta is the transmitter address (addr2).
 * Returns 0 and the 48-bit TSC in *@tsc when the ICV matches: the plaintext
 * (data | MIC) is then at body + 8, body_len - 12 bytes long. Returns -1 if the
 * frame is too short (body_len < 8 + 8 + 4) or has no extended IV (bit 0x20 of
 * body[3] clear), -2 if the ICV does not match (the body is then garbage).
 * Does NOT check the Michael MIC or replay: the caller does.
 */
int rtw89_tkip_decrypt(const uint8_t tk[16], const uint8_t ta[6], uint8_t *body, size_t body_len,
                       uint64_t *tsc);

/*
 * The reverse, for the tests: @body has room for 8 + plain_len + 4 bytes with the
 * plaintext (data | MIC) already at body + 8. Writes the TKIP header for @tsc and
 * key id @keyid (0..3) at body, encrypts, and appends the encrypted ICV.
 */
void rtw89_tkip_encrypt(const uint8_t tk[16], const uint8_t ta[6], uint64_t tsc, uint8_t keyid,
                        uint8_t *body, size_t plain_len);

#ifdef __cplusplus
}
#endif

#endif /* _RTW89_TKIP_H */
