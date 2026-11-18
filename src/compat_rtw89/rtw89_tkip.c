// SPDX-License-Identifier: GPL-2.0
/* See rtw89_tkip.h. The S-box and the phase 1 / phase 2 key mixing are copied
 * from net/mac80211/tkip.c, the Michael MIC is written after
 * net/wireless/michael-mic.c (both Linux, GPL-2.0). CRC-32 is bitwise and RC4
 * is a plain 256-byte state, both written for this file. Checked in
 * tools/hosttest against frames encrypted by hostap's wlantest. */
#include "rtw89_tkip.h"

/* The kernel and libc both provide these; no header is common to both. */
void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *s, int c, size_t n);

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */

static uint16_t le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t rol32(uint32_t v, unsigned int n)
{
    return (v << n) | (v >> (32 - n));
}

/* ------------------------------------------------------------------ */
/*  Michael MIC                                                         */
/* ------------------------------------------------------------------ */

struct michael_state {
    uint32_t l, r;
};

static void michael_block(struct michael_state *m, uint32_t val)
{
    m->l ^= val;
    m->r ^= rol32(m->l, 17);
    m->l += m->r;
    m->r ^= ((m->l & 0xff00ff00u) >> 8) | ((m->l & 0x00ff00ffu) << 8);
    m->l += m->r;
    m->r ^= rol32(m->l, 3);
    m->l += m->r;
    m->r ^= rol32(m->l, 30);
    m->l += m->r;
}

/* Michael over @hdr (a multiple of 4 bytes, possibly empty), then @data. */
static void michael_run(const uint8_t key[8], const uint8_t *hdr, size_t hdr_len,
                        const uint8_t *data, size_t len, uint8_t mic[RTW89_TKIP_MIC_LEN])
{
    struct michael_state m;
    uint32_t val;
    size_t i, full = len / 4, left = len % 4;

    m.l = le32(key);
    m.r = le32(key + 4);
    for (i = 0; i < hdr_len; i += 4)
        michael_block(&m, le32(hdr + i));
    for (i = 0; i < full; i++)
        michael_block(&m, le32(data + 4 * i));

    /* The last 0..3 bytes, then 0x5a and zeros up to the next word, then one zero word. */
    val = 0x5a;
    while (left > 0) {
        left--;
        val = (val << 8) | data[4 * full + left];
    }
    michael_block(&m, val);
    michael_block(&m, 0);

    put_le32(mic, m.l);
    put_le32(mic + 4, m.r);
}

void rtw89_michael_mic(const uint8_t key[8], const uint8_t da[6], const uint8_t sa[6],
                       uint8_t priority, const uint8_t *data, size_t len,
                       uint8_t mic[RTW89_TKIP_MIC_LEN])
{
    uint8_t hdr[16];

    memcpy(hdr, da, 6);
    memcpy(hdr + 6, sa, 6);
    hdr[12] = priority;
    memset(hdr + 13, 0, 3);
    michael_run(key, hdr, sizeof(hdr), data, len, mic);
}

/* ------------------------------------------------------------------ */
/*  CRC-32 (ICV) and RC4                                                */
/* ------------------------------------------------------------------ */

/* Bitwise reflected CRC-32, polynomial 0xEDB88320. */
static uint32_t crc32_le(uint32_t crc, const uint8_t *p, size_t len)
{
    size_t i;
    int bit;

    for (i = 0; i < len; i++) {
        crc ^= p[i];
        for (bit = 0; bit < 8; bit++)
            crc = (crc & 1) ? (crc >> 1) ^ 0xedb88320u : crc >> 1;
    }
    return crc;
}

/* The ICV value over @data: ~crc32_le(~0, data), sent little-endian. */
static uint32_t icv_value(const uint8_t *data, size_t len)
{
    return ~crc32_le(~0u, data, len);
}

/* RC4 with a 256-byte state on the stack. Encrypts and decrypts alike. */
static void rc4_crypt(const uint8_t *key, size_t key_len, uint8_t *data, size_t len)
{
    uint8_t s[256], t;
    unsigned int i, j, k;

    for (i = 0; i < 256; i++)
        s[i] = (uint8_t)i;
    for (i = 0, j = 0; i < 256; i++) {
        j = (j + s[i] + key[i % key_len]) & 0xff;
        t = s[i];
        s[i] = s[j];
        s[j] = t;
    }
    for (k = 0, i = 0, j = 0; k < len; k++) {
        i = (i + 1) & 0xff;
        j = (j + s[i]) & 0xff;
        t = s[i];
        s[i] = s[j];
        s[j] = t;
        data[k] ^= s[(s[i] + s[j]) & 0xff];
    }
}

/* ------------------------------------------------------------------ */
/*  TKIP key mixing (IEEE 802.11 12.5.2.4)                              */
/* ------------------------------------------------------------------ */

static const uint16_t tkip_sbox[256] = {
    0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154,
    0x6050, 0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A,
    0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
    0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B,
    0x75C2, 0xE11C, 0x3DAE, 0x4C6A, 0x6C5A, 0x7E41, 0xF502, 0x834F,
    0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
    0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5,
    0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD, 0xEA9F,
    0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
    0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397,
    0xA6F5, 0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED,
    0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
    0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194,
    0x8ACF, 0xE910, 0x0406, 0xFE81, 0xA0F0, 0x7844, 0x25BA, 0x4BE3,
    0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
    0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D,
    0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC, 0x2E39,
    0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
    0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83,
    0x8CCA, 0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76,
    0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
    0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B,
    0xD532, 0x8B43, 0x6E59, 0xDAB7, 0x018C, 0xB164, 0x9CD2, 0x49E0,
    0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
    0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751,
    0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86, 0x0F85,
    0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
    0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9,
    0xD938, 0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7,
    0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
    0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8,
    0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A,
};

static uint16_t swap16(uint16_t v)
{
    return (uint16_t)((v >> 8) | (v << 8));
}

static uint16_t ror16_1(uint16_t v)
{
    return (uint16_t)((v >> 1) | (v << 15));
}

static uint16_t tkip_s(uint16_t v)
{
    return (uint16_t)(tkip_sbox[v & 0xff] ^ swap16(tkip_sbox[v >> 8]));
}

/* Phase 1: P1K (five 16-bit words) from TA, TK and the upper 32 bits of the TSC.
 * Done on every call; there is no cache. */
static void tkip_phase1(const uint8_t tk[16], const uint8_t ta[6], uint32_t iv32,
                        uint16_t p1k[5])
{
    unsigned int i, j;

    p1k[0] = (uint16_t)(iv32 & 0xffff);
    p1k[1] = (uint16_t)(iv32 >> 16);
    p1k[2] = le16(ta);
    p1k[3] = le16(ta + 2);
    p1k[4] = le16(ta + 4);

    for (i = 0; i < 8; i++) {
        j = 2 * (i & 1);
        p1k[0] = (uint16_t)(p1k[0] + tkip_s((uint16_t)(p1k[4] ^ le16(tk + j))));
        p1k[1] = (uint16_t)(p1k[1] + tkip_s((uint16_t)(p1k[0] ^ le16(tk + 4 + j))));
        p1k[2] = (uint16_t)(p1k[2] + tkip_s((uint16_t)(p1k[1] ^ le16(tk + 8 + j))));
        p1k[3] = (uint16_t)(p1k[3] + tkip_s((uint16_t)(p1k[2] ^ le16(tk + 12 + j))));
        p1k[4] = (uint16_t)(p1k[4] + tkip_s((uint16_t)(p1k[3] ^ le16(tk + j))) + i);
    }
}

/* Phase 2: the 16-byte per-packet RC4 key. Bytes 0..2 are the TKIP header IV. */
static void tkip_phase2(const uint8_t tk[16], const uint16_t p1k[5], uint16_t iv16,
                        uint8_t rc4key[16])
{
    uint16_t ppk[6];
    unsigned int i;

    for (i = 0; i < 5; i++)
        ppk[i] = p1k[i];
    ppk[5] = (uint16_t)(p1k[4] + iv16);

    ppk[0] = (uint16_t)(ppk[0] + tkip_s((uint16_t)(ppk[5] ^ le16(tk + 0))));
    ppk[1] = (uint16_t)(ppk[1] + tkip_s((uint16_t)(ppk[0] ^ le16(tk + 2))));
    ppk[2] = (uint16_t)(ppk[2] + tkip_s((uint16_t)(ppk[1] ^ le16(tk + 4))));
    ppk[3] = (uint16_t)(ppk[3] + tkip_s((uint16_t)(ppk[2] ^ le16(tk + 6))));
    ppk[4] = (uint16_t)(ppk[4] + tkip_s((uint16_t)(ppk[3] ^ le16(tk + 8))));
    ppk[5] = (uint16_t)(ppk[5] + tkip_s((uint16_t)(ppk[4] ^ le16(tk + 10))));
    ppk[0] = (uint16_t)(ppk[0] + ror16_1((uint16_t)(ppk[5] ^ le16(tk + 12))));
    ppk[1] = (uint16_t)(ppk[1] + ror16_1((uint16_t)(ppk[0] ^ le16(tk + 14))));
    ppk[2] = (uint16_t)(ppk[2] + ror16_1(ppk[1]));
    ppk[3] = (uint16_t)(ppk[3] + ror16_1(ppk[2]));
    ppk[4] = (uint16_t)(ppk[4] + ror16_1(ppk[3]));
    ppk[5] = (uint16_t)(ppk[5] + ror16_1(ppk[4]));

    rc4key[0] = (uint8_t)(iv16 >> 8);
    rc4key[1] = (uint8_t)(((iv16 >> 8) | 0x20) & 0x7f);
    rc4key[2] = (uint8_t)(iv16 & 0xff);
    rc4key[3] = (uint8_t)(((ppk[5] ^ le16(tk)) >> 1) & 0xff);
    for (i = 0; i < 6; i++) {
        rc4key[4 + 2 * i] = (uint8_t)(ppk[i] & 0xff);
        rc4key[5 + 2 * i] = (uint8_t)(ppk[i] >> 8);
    }
}

/* The per-packet RC4 key for @tsc (48 bits): phase 1 then phase 2. */
static void tkip_packet_key(const uint8_t tk[16], const uint8_t ta[6], uint64_t tsc,
                            uint8_t rc4key[16])
{
    uint16_t p1k[5];

    tkip_phase1(tk, ta, (uint32_t)(tsc >> 16), p1k);
    tkip_phase2(tk, p1k, (uint16_t)(tsc & 0xffff), rc4key);
}

/* TSC from the header: TSC0 = body[2], TSC1 = body[0], TSC2..TSC5 = body[4..7]. */
static uint64_t tkip_header_tsc(const uint8_t *body)
{
    uint16_t iv16 = (uint16_t)((body[0] << 8) | body[2]);
    uint32_t iv32 = le32(body + 4);

    return ((uint64_t)iv32 << 16) | iv16;
}

/* ------------------------------------------------------------------ */
/*  TKIP MPDU                                                           */
/* ------------------------------------------------------------------ */

int rtw89_tkip_decrypt(const uint8_t tk[16], const uint8_t ta[6], uint8_t *body, size_t body_len,
                       uint64_t *tsc)
{
    uint8_t rc4key[16];
    uint8_t *cipher = body + RTW89_TKIP_HDR_LEN;
    uint64_t t;
    size_t plain_len;

    if (body_len < RTW89_TKIP_HDR_LEN + RTW89_TKIP_MIC_LEN + RTW89_TKIP_ICV_LEN)
        return -1;
    if (!(body[3] & 0x20))
        return -1;

    t = tkip_header_tsc(body);
    tkip_packet_key(tk, ta, t, rc4key);
    rc4_crypt(rc4key, sizeof(rc4key), cipher, body_len - RTW89_TKIP_HDR_LEN);

    plain_len = body_len - RTW89_TKIP_HDR_LEN - RTW89_TKIP_ICV_LEN;
    if (le32(cipher + plain_len) != icv_value(cipher, plain_len))
        return -2;

    *tsc = t;
    return 0;
}

void rtw89_tkip_encrypt(const uint8_t tk[16], const uint8_t ta[6], uint64_t tsc, uint8_t keyid,
                        uint8_t *body, size_t plain_len)
{
    uint8_t rc4key[16];
    uint8_t *plain = body + RTW89_TKIP_HDR_LEN;
    uint16_t iv16 = (uint16_t)(tsc & 0xffff);
    uint32_t iv32 = (uint32_t)(tsc >> 16);

    body[0] = (uint8_t)(iv16 >> 8);
    body[1] = (uint8_t)(((iv16 >> 8) | 0x20) & 0x7f);
    body[2] = (uint8_t)(iv16 & 0xff);
    body[3] = (uint8_t)(((keyid & 3) << 6) | 0x20);
    put_le32(body + 4, iv32);

    put_le32(plain + plain_len, icv_value(plain, plain_len));
    tkip_packet_key(tk, ta, tsc, rc4key);
    rc4_crypt(rc4key, sizeof(rc4key), plain, plain_len + RTW89_TKIP_ICV_LEN);
}
