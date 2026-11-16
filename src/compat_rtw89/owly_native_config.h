/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_NATIVE_CONFIG_H
#define OWLY_NATIVE_CONFIG_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Fixed kernel-owned payloads. Sizes/offsets checked against Legacy4C07538B
 * and compared with MtkWireless f04aa757. No private object offsets here. */
struct owly_cfg_bssid { uint32_t version; uint8_t bssid[6], opaque_mac[6]; } __attribute__((packed));
struct owly_cfg_u32 { uint32_t version, value; } __attribute__((packed));
struct owly_cfg_rssi { uint32_t version, reserved[3]; int32_t threshold; } __attribute__((packed));
struct owly_cfg_sync {
    uint32_t version, state; uint8_t master[6], reserved[2];
    uint32_t flags; uint8_t mode_flags, reserved2[3];
} __attribute__((packed));
struct owly_cfg_channel { uint32_t version, channel, flags; } __attribute__((packed));
struct owly_cfg_sequence {
    uint32_t version; uint8_t pad, length, encoding, step, duplicate, fill, reserved[2];
    struct owly_cfg_channel channels[32]; uint8_t tail[4];
} __attribute__((packed));
struct owly_cfg_params { uint32_t version, aw_length, aw_period, extension, psf_period, non_election_master; } __attribute__((packed));
struct owly_cfg_rate { uint32_t version; uint8_t half_mbps; } __attribute__((packed));
struct owly_native_config {
    uint32_t committed, election_id, master_channel, psf_period_ms;
    int32_t peer_rssi;
    struct owly_cfg_sync sync;
    uint8_t bssid_opaque[6]; /* Native's second address has no proven RF role. */
};
enum { OWLY_CFG_BSSID=1, OWLY_CFG_ELECTION=2, OWLY_CFG_MASTER=4,
       OWLY_CFG_RSSI=8, OWLY_CFG_SYNC=16, OWLY_CFG_PARAMS=32, OWLY_CFG_SEQUENCE=64 };

#define OWLY_MI_TEMPLATE_MAX 1200u

static inline bool owly_cfg_known(unsigned n)
{ return n==116 || n==122 || n==125 || n==129 || n==132 || n==134 || n==135 || n==213; }

/* Native descriptors are 12 bytes, NOT three packed channel bytes. The
 * length is an actual count (16); the over-the-air SIMPLE encoding uses 15. */
static inline void owly_config_sequence(struct owly_cfg_sequence *out, uint8_t ch)
{
    unsigned i;
    memset(out,0,sizeof(*out)); out->version=1;
    if (ch!=6 && ch!=44 && ch!=149) return;
    out->length=16; out->encoding=1; out->step=3; out->fill=255;
    for (i=0;i<16;i++) {
        out->channels[i].version=1; out->channels[i].channel=ch;
        out->channels[i].flags=2u | (ch>14 ? 0x10u : 8u);
    }
}

#ifdef __cplusplus
extern "C" {
#endif
/* Returns 0 or Linux negative errno; SET is transactional. Only the actual
 * bound SCC channel and local-master mode are implemented. Remote-clock or
 * off-channel requests remain unsupported rather than being acknowledged. */
int owly_config_request(struct owly_native_config *cfg, bool set, unsigned number,
                       void *data, const uint8_t local[6], uint8_t bound_channel);
bool owly_config_rx_allowed(int threshold_dbm, int signal_dbm);
#ifdef __cplusplus
}
static_assert(sizeof(owly_cfg_bssid)==16,"Legacy BSSID16");
static_assert(sizeof(owly_cfg_rssi)==20 && offsetof(owly_cfg_rssi,threshold)==16,"Legacy RSSI20/+16");
static_assert(sizeof(owly_cfg_sync)==24 && offsetof(owly_cfg_sync,master)==8,"Legacy sync24/+8");
static_assert(sizeof(owly_cfg_sequence)==400 && offsetof(owly_cfg_sequence,channels)==12,"Legacy sequence400/+12");
static_assert(sizeof(owly_cfg_params)==24,"Legacy params24");
#endif
#endif
