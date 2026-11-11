// SPDX-License-Identifier: GPL-2.0
#ifndef RTW89_SCAN_TARGET_HPP
#define RTW89_SCAN_TARGET_HPP
#include <IOKit/80211/apple80211_ioctl.h>

/* Some native ioctl clients retry the scan REQUEST after SCAN_RESULT returns
 * Busy. Keep a completed directed request until its result list is consumed,
 * otherwise each retry starts another scan and can never read its results. */
struct Rtw89ScanCompletion {
    uint8_t ssid[APPLE80211_MAX_SSID_LEN] = {};
    uint32_t length = 0;
    uint16_t frequencies[APPLE80211_MAX_CHANNELS] = {};
    uint32_t frequencyCount = 0;
    bool pending = false;
    bool ready = false;
    bool hostOwned = false;
    uint32_t generation = 0;
    uint64_t expiresAt = 0;
    bool reuseChannels(const uint8_t *name, uint32_t len, const uint16_t *freqs,
                       uint32_t count, uint64_t now = 0) const {
        if (!pending || (ready && expiresAt && now >= expiresAt)) return false;
        if (!len) return true; // internal background readers share the result list
        if (!name || len != length || count != frequencyCount || (count && !freqs)) return false;
        for (uint32_t i = 0; i < len; i++) if (name[i] != ssid[i]) return false;
        for (uint32_t i = 0; i < count; i++) if (freqs[i] != frequencies[i]) return false;
        return true;
    }
    void beginChannels(const uint8_t *name, uint32_t len, const uint16_t *freqs,
                       uint32_t count, bool host = false) {
        consume();
        if (!name || !len || len > sizeof(ssid) || count > APPLE80211_MAX_CHANNELS ||
            (count && !freqs)) return;
        for (uint32_t i = 0; i < len; i++) ssid[i] = name[i];
        for (uint32_t i = 0; i < count; i++) frequencies[i] = freqs[i];
        length = len; frequencyCount = count; pending = true; hostOwned = host;
    }
    bool reuse(const uint8_t *name, uint32_t len, uint16_t freq, uint64_t now = 0) const {
        return reuseChannels(name, len, freq ? &freq : nullptr, freq ? 1 : 0, now);
    }
    void begin(const uint8_t *name, uint32_t len, uint16_t freq, bool host = false) {
        beginChannels(name, len, freq ? &freq : nullptr, freq ? 1 : 0, host);
    }
    void finish(bool aborted, uint64_t now = 0) {
        if (aborted) consume();
        else {
            ready = pending;
            // A cancelled host request must not pin old results indefinitely.
            // This bounds snapshot reuse; it does not lengthen any scan timeout.
            expiresAt = now ? now + 2000000000ULL : 0;
        }
    }
    void consume() { pending = ready = hostOwned = false; expiresAt = 0; generation = 0; }
    void resultsConsumed(bool hostReader) {
        // IO80211ScanManager drains results synchronously on SCAN_DONE to
        // populate its own cache. That is not the BSD requester's result read.
        if (!hostOwned || hostReader) consume();
    }
    bool busy() const { return pending && !ready; }
};

/* Pointers remain valid only while the caller owns the full native payload.
 * The glue copies the target before the request returns. Zero frequency
 * requests a full scan, preserving multi-channel and unspecified requests. */
static inline bool rtw89ScanTarget(int number, const void *data,
                                  const uint8_t *&target, uint32_t &targetLen,
                                  uint16_t &targetFreq)
{
    const struct apple80211_channel *targetChannel = nullptr;
    target = nullptr;
    targetLen = 0;
    targetFreq = 0;
    if (!data)
        return false;
    /* Select one explicit target in either native request form.
     * Multi-name background scans retain their existing wildcard behavior. */
    if (number == APPLE80211_IOC_SCAN_REQ) {
        const auto *d = static_cast<const struct apple80211_scan_data *>(data);
        if (d->ssid_len > APPLE80211_MAX_SSID_LEN ||
            d->num_channels > APPLE80211_MAX_CHANNELS)
            return false;
        target = d->ssid;
        targetLen = d->ssid_len;
        if (d->num_channels == 1)
            targetChannel = &d->channels[0];
    } else if (number == APPLE80211_IOC_SCAN_REQ_MULTIPLE) {
        const auto *d = static_cast<const struct apple80211_scan_multiple_data *>(data);
        if (d->ssid_count > 16 || d->num_channels > 128)
            return false;
        bool distinctNames = false;
        for (uint32_t i = 0; i < d->ssid_count; i++) {
            if (d->ssids[i].ssid_len > APPLE80211_MAX_SSID_LEN)
                return false;
            const auto &candidate = d->ssids[i];
            if (!candidate.ssid_len) continue;
            if (!targetLen) {
                target = candidate.ssid_bytes;
                targetLen = candidate.ssid_len;
            } else {
                bool same = candidate.ssid_len == targetLen;
                for (uint32_t j = 0; same && j < targetLen; j++)
                    if (target[j] != candidate.ssid_bytes[j]) same = false;
                if (!same) distinctNames = true;
            }
        }
        if (distinctNames) { target = nullptr; targetLen = 0; }
        if (d->num_channels == 1)
            targetChannel = &d->channels[0];
    }
    if (number != APPLE80211_IOC_SCAN_REQ && number != APPLE80211_IOC_SCAN_REQ_MULTIPLE)
        return false;
    if (targetLen && targetChannel) {
        unsigned int c = targetChannel->channel;
        if ((targetChannel->flags & 0x2000) && (c == 2 || (c >= 1 && c <= 233 && c % 4 == 1)))
            targetFreq = static_cast<uint16_t>(c == 2 ? 5935 : 5950 + 5 * c);
        else if ((targetChannel->flags & APPLE80211_C_FLAG_2GHZ) && c >= 1 && c <= 14)
            targetFreq = static_cast<uint16_t>(c == 14 ? 2484 : 2407 + 5 * c);
        else if ((targetChannel->flags & APPLE80211_C_FLAG_5GHZ) && c >= 32 && c <= 177)
            targetFreq = static_cast<uint16_t>(5000 + 5 * c);
        else
            return false;
    }
    return true;
}
#endif
