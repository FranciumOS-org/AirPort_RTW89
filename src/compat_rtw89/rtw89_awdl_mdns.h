/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Our services, as AWDL service response TLVs (type 2).
 *
 * Real MIFs carry a device's services in these and the family gives us nothing
 * to build them from, but the same records go past in our own mDNS on awdl0, so
 * they are read from there. Laid out as an iPhone's were on 2026-11-03:
 *
 *   u16 key length + 1, key, u8 DNS type, u16 data length, u16 0, data
 *
 * Lengths are little endian. A key is its labels and then c0 0a, which stands
 * for _tcp.local, and instance names in it are lower case. In the data c0 00
 * points at the start of the key and c0 0c stands for .local.
 *
 * Included by rtw89_awdl.c only: static, and nothing here touches the kernel,
 * so a parser fed from the wire can be tested on its own.
 */
#ifndef RTW89_AWDL_MDNS_H
#define RTW89_AWDL_MDNS_H

#define AWDL_SVC_MAX        32
#define AWDL_SVC_TLV_MAX    255
#define AWDL_SVC_BUDGET     900     /* bytes of them in one frame */
#define AWDL_MDNS_NAME_MAX  256
#define AWDL_DNS_PTR        12
#define AWDL_DNS_TXT        16
#define AWDL_DNS_SRV        33

struct awdl_svc {
    u16 len;                        /* of tlv, 0 for a free slot */
    u32 stamp;                      /* when last announced, on gSvcStamp */
    u8  tlv[AWDL_SVC_TLV_MAX];
};

static struct awdl_svc gSvc[AWDL_SVC_MAX];
static unsigned int gSvcNext;
static u32 gSvcStamp;

/* A record's key for the log: length bytes and anything odd come out as dots. */
static void awdl_svc_key(const u8 *tlv, char *out, size_t size)
{
    size_t klen = (size_t)(tlv[3] | (tlv[4] << 8)), i, at = 0;

    for (i = 1; i + 3 <= klen && at + 1 < size; i++) {
        u8 c = tlv[5 + i];

        out[at++] = c >= 0x20 && c < 0x7f ? (char)c : '.';
    }
    out[at] = 0;
}

static void awdl_svc_log(const char *what, const u8 *tlv, size_t len)
{
    char key[80];

    awdl_svc_key(tlv, key, sizeof(key));
    awdl_log("    service record %s: %s, type %u, %u bytes", what, key,
             (unsigned int)tlv[5 + (tlv[3] | (tlv[4] << 8)) - 1], (unsigned int)len);
}

/* What the MIFs are carrying, whole, so that a record never sent can be told
 * from one sent and ignored. */
static void awdl_svc_log_all(void)
{
    unsigned int i, used = 0;

    for (i = 0; i < AWDL_SVC_MAX; i++)
        if (gSvc[i].len) {
            used++;
            awdl_svc_log("carried", gSvc[i].tlv, gSvc[i].len);
        }
    awdl_log("    %u service record(s) carried, of %u", used, (unsigned int)AWDL_SVC_MAX);
}

/* A name, with its pointers followed, as uncompressed labels and the final 0.
 * Returns its length, or 0 if it is not one. *next is what follows it. */
static size_t awdl_mdns_name(const u8 *m, size_t len, size_t off, u8 *out, size_t *next)
{
    size_t at = 0;
    unsigned int hops = 0;
    bool jumped = false;

    for (;;) {
        u8 l;

        if (off >= len)
            return 0;
        l = m[off];
        if ((l & 0xc0) == 0xc0) {
            if (off + 2 > len || ++hops > 16)
                return 0;
            if (!jumped && next)
                *next = off + 2;
            jumped = true;
            off = (size_t)(l & 0x3f) << 8 | m[off + 1];
            continue;
        }
        if (l & 0xc0)
            return 0;
        if (off + 1 + l > len || at + 1 + l > AWDL_MDNS_NAME_MAX)
            return 0;
        memcpy(out + at, m + off, 1 + (size_t)l);
        at += 1 + (size_t)l;
        off += 1 + (size_t)l;
        if (!l) {
            if (!jumped && next)
                *next = off;
            return at;
        }
    }
}

/* Whether a name ends in these labels; *head is the length before them. */
static bool awdl_mdns_suffix(const u8 *name, size_t len, const u8 *suffix, size_t slen,
                             size_t *head)
{
    size_t at = 0;

    while (at < len) {
        if (len - at == slen && !memcmp(name + at, suffix, slen)) {
            *head = at;
            return true;
        }
        if (!name[at])
            break;
        at += 1 + (size_t)name[at];
    }
    return false;
}

static void awdl_svc_store(const u8 *tlv, size_t len, size_t key_end, bool gone)
{
    unsigned int i, free_slot = AWDL_SVC_MAX, oldest = 0;
    bool known = false;

    for (i = 0; i < AWDL_SVC_MAX; i++) {
        struct awdl_svc *s = &gSvc[i];

        if (!s->len) {
            if (free_slot == AWDL_SVC_MAX)
                free_slot = i;
            continue;
        }
        if ((s32)(s->stamp - gSvc[oldest].stamp) < 0 || !gSvc[oldest].len)
            oldest = i;
        /* The same key and type is the same record. */
        if (s->len > key_end && !memcmp(s->tlv + 3, tlv + 3, key_end - 3)) {
            s->len = 0;
            if (gone) {
                awdl_svc_log("withdrawn", tlv, len);
                return;
            }
            known = true;
            free_slot = i;
            break;
        }
    }
    if (gone)
        return;
    /*
     * Full: the one announced longest ago makes room. Nothing ages out by
     * itself, and the AirDrop instance name changes every time it is published
     * with the old one not always withdrawn, so refusing here would in time
     * keep the current name off the air in favour of dead ones.
     */
    if (free_slot == AWDL_SVC_MAX) {
        awdl_svc_log("replaced", gSvc[oldest].tlv, gSvc[oldest].len);
        gSvc[oldest].len = 0;
        free_slot = oldest;
    }
    /* The tick reads these on another thread with no lock. The length goes in
     * last, and a frame with a half-written record costs nothing a peer does
     * not already have to survive. */
    memcpy(gSvc[free_slot].tlv, tlv, len);
    gSvc[free_slot].stamp = ++gSvcStamp;
    gSvc[free_slot].len = (u16)len;
    if (!known)
        awdl_svc_log("added", tlv, len);
}

static void awdl_mdns_record(const u8 *m, size_t mlen, const u8 *owner, size_t olen,
                             u16 type, u32 ttl, size_t rd, size_t rdlen)
{
    static const u8 kTcpLocal[] = { 4, '_', 't', 'c', 'p', 5, 'l', 'o', 'c', 'a', 'l', 0 };
    static const u8 kLocal[] = { 5, 'l', 'o', 'c', 'a', 'l', 0 };
    u8 tlv[AWDL_SVC_TLV_MAX];
    u8 name[AWDL_MDNS_NAME_MAX];
    size_t head, at, i, nlen, data, key_end;

    if (!awdl_mdns_suffix(owner, olen, kTcpLocal, sizeof(kTcpLocal), &head) || !head)
        return;
    if (head + 16 > sizeof(tlv))
        return;

    /* the key; the labels' length bytes are below 'A', so lowering is safe */
    at = 5;
    for (i = 0; i < head; i++) {
        u8 c = owner[i];

        tlv[at++] = c >= 'A' && c <= 'Z' ? (u8)(c + 32) : c;
    }
    tlv[at++] = 0xc0;
    tlv[at++] = 0x0a;
    tlv[at++] = (u8)type;
    key_end = at;
    data = at + 4;

    if (type == AWDL_DNS_PTR) {
        if (!awdl_mdns_name(m, mlen, rd, name, NULL) || !name[0])
            return;
        nlen = 1 + (size_t)name[0];
        if (data + nlen + 2 > sizeof(tlv))
            return;
        memcpy(tlv + data, name, nlen);
        at = data + nlen;
        tlv[at++] = 0xc0;
        tlv[at++] = 0x00;
    } else if (type == AWDL_DNS_SRV) {
        size_t tlen;

        if (rdlen < 7)
            return;
        tlen = awdl_mdns_name(m, mlen, rd + 6, name, NULL);
        if (!tlen || !awdl_mdns_suffix(name, tlen, kLocal, sizeof(kLocal), &nlen) || !nlen)
            return;
        if (data + 6 + nlen + 2 > sizeof(tlv))
            return;
        memcpy(tlv + data, m + rd, 6);
        memcpy(tlv + data + 6, name, nlen);
        at = data + 6 + nlen;
        tlv[at++] = 0xc0;
        tlv[at++] = 0x0c;
    } else {
        if (data + rdlen > sizeof(tlv))
            return;
        memcpy(tlv + data, m + rd, rdlen);
        at = data + rdlen;
    }

    tlv[0] = 2;
    tlv[1] = (u8)(at - 3);
    tlv[2] = (u8)((at - 3) >> 8);
    tlv[3] = (u8)(key_end - 5);     /* the key and its type */
    tlv[4] = (u8)((key_end - 5) >> 8);
    tlv[key_end] = (u8)(at - data);
    tlv[key_end + 1] = (u8)((at - data) >> 8);
    tlv[key_end + 2] = 0;
    tlv[key_end + 3] = 0;
    awdl_svc_store(tlv, at, key_end, ttl == 0);
}

/* One mDNS message of ours. Only responses: a probe's records are not ours yet. */
static void awdl_mdns_note(const u8 *m, size_t len)
{
    unsigned int i, q, rr;
    size_t off = 12;
    u8 owner[AWDL_MDNS_NAME_MAX];

    if (len < 12 || !(m[2] & 0x80))
        return;
    q = (unsigned int)m[4] << 8 | m[5];
    rr = ((unsigned int)m[6] << 8 | m[7]) + ((unsigned int)m[8] << 8 | m[9]) +
         ((unsigned int)m[10] << 8 | m[11]);

    for (i = 0; i < q; i++) {
        if (!awdl_mdns_name(m, len, off, owner, &off) || off + 4 > len)
            return;
        off += 4;
    }
    for (i = 0; i < rr; i++) {
        size_t olen = awdl_mdns_name(m, len, off, owner, &off), rdlen;
        u16 type;
        u32 ttl;

        if (!olen || off + 10 > len)
            return;
        type = (u16)(m[off] << 8 | m[off + 1]);
        ttl = (u32)m[off + 4] << 24 | (u32)m[off + 5] << 16 | (u32)m[off + 6] << 8 | m[off + 7];
        rdlen = (size_t)m[off + 8] << 8 | m[off + 9];
        off += 10;
        if (off + rdlen > len)
            return;
        if (type == AWDL_DNS_PTR || type == AWDL_DNS_SRV || type == AWDL_DNS_TXT)
            awdl_mdns_record(m, len, owner, olen, type, ttl, off, rdlen);
        off += rdlen;
    }
}

/* A frame from awdl0, as the family built it: 802.3 header, Apple's SNAP and
 * AWDL headers, then IPv6 at 30 and UDP at 70. */
static void awdl_mdns_note_frame(const u8 *eth, size_t len)
{
    if (len < 78 || eth[28] != 0x86 || eth[29] != 0xdd || eth[36] != 17 ||
        eth[72] != 0x14 || eth[73] != 0xe9)
        return;
    awdl_mdns_note(eth + 78, len - 78);
}

/* As many records as fit, carrying on from where the last frame stopped. */
static size_t awdl_svc_append(u8 *out, size_t size)
{
    size_t at = 0;
    unsigned int i;

    if (size > AWDL_SVC_BUDGET)
        size = AWDL_SVC_BUDGET;
    for (i = 0; i < AWDL_SVC_MAX; i++) {
        unsigned int n = (gSvcNext + i) % AWDL_SVC_MAX;
        size_t l = gSvc[n].len;

        if (!l)
            continue;
        if (at + l > size) {
            gSvcNext = n;
            return at;
        }
        memcpy(out + at, gSvc[n].tlv, l);
        at += l;
    }
    return at;
}

#endif
