/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_ABI6_RX_H
#define OWLY_ABI6_RX_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "rtw89_awdl_action_decode.h"

/* A pure 802.11-to-AWDL receive demultiplexer. Does not touch hardware,
 * Apple interfaces, skb ownership, transmission or channel context.
 * All input buffers and subframe pointers are borrowed for the duration
 * of dispatch. 'accepted' means consumer accepted a borrowed frame, NOT
 * peer authentication, AWDL synchronization or completed native delivery. */
struct owly_abi6_rx_context {
    unsigned int rx_freq_mhz;
    unsigned int sta_freq_mhz;
    unsigned int sta_center_freq_mhz; /* negotiated channel center; 0 if unknown */
    unsigned int sta_width_mhz; /* associated channel width 20/40/80; 0=unknown */
    bool crc_ok;
    bool sta_connected;
    bool standalone_channel; /* an assigned, owned 20 MHz idle context */
    bool aux_present;
    bool scanning;
};
struct owly_abi6_rx_sinks {
    void *ctx;
    /* Raw validated 802.11 Action bytes are borrowed, without FCS. */
    bool (*action)(void *ctx, const uint8_t source[6],
                   const struct owly_action_info *decoded,
                   const uint8_t *raw_frame, size_t frame_len);
    bool (*ipv6)(void *ctx, const uint8_t dst[6], const uint8_t src[6],
                 const uint8_t *ipv6, size_t len);
};
enum owly_abi6_rx_kind {
    OWLY_ABI6_RX_NOT_ELIGIBLE = 0,
    OWLY_ABI6_RX_NOT_AWDL = 1,
    OWLY_ABI6_RX_INVALID_AWDL = 2,
    OWLY_ABI6_RX_ACTION = 3,
    OWLY_ABI6_RX_IPV6 = 4,
};
struct owly_abi6_rx_result {
    enum owly_abi6_rx_kind kind;
    unsigned int valid_units;
    unsigned int sink_accepted;
    bool consumed; /* recognized AWDL frame owned/dropped here, regardless of sink acceptance */
};
struct owly_abi6_rx_result owly_abi6_demux(
    const uint8_t *frame, size_t len,
    const struct owly_abi6_rx_context *state,
    const struct owly_abi6_rx_sinks *sink);
#endif
