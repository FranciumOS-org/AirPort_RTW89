// SPDX-License-Identifier: GPL-2.0
// Anonymous wire fixtures use observed offsets, not SDK-shaped structures.
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "../../src/kext/rtw89_scan_ioctl.hpp"
#include "../../src/kext/rtw89_scan_target.hpp"
#include "../../src/kext/rtw89_scan_freshness.hpp"

static void word(uint8_t *b, size_t offset, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) b[offset+i] = (uint8_t)(value >> (8*i));
}

static void testCompletion()
{
    const uint8_t name[] = {'H', 0, 'S'};
    const uint16_t channels[] = {2437, 5745};
    const uint16_t changed[] = {2437, 5180};
    Rtw89ScanCompletion c;
    assert(!c.reuseChannels(name, sizeof(name), channels, 2));
    c.beginChannels(name, sizeof(name), channels, 2, true);
    c.generation = 8;
    assert(c.busy() && c.reuseChannels(name, sizeof(name), channels, 2));
    assert(!c.reuseChannels(name, sizeof(name), channels, 1));
    assert(!c.reuseChannels(name, sizeof(name), changed, 2));
    c.finish(false, 1000000000ULL);
    assert(c.ready && !c.busy());
    c.resultsConsumed(false); // synchronous family cache fill is not host EOF
    assert(c.ready && c.generation == 8);
    assert(c.reuseChannels(name, sizeof(name), channels, 2, 1200000000ULL));
    c.resultsConsumed(false);
    assert(c.reuseChannels(name, sizeof(name), channels, 2, 1300000000ULL));
    c.resultsConsumed(true);
    assert(!c.pending && c.generation == 0);
    c.beginChannels(name, sizeof(name), channels, 2, true);
    c.finish(false, 1000000000ULL);
    assert(!c.reuseChannels(name, sizeof(name), channels, 2, 3000000000ULL));
    c.finish(true);
    assert(!c.pending && !c.hostOwned);
    c.beginChannels(name, sizeof(name), channels, 2, false);
    c.finish(false);
    c.resultsConsumed(false);
    assert(!c.pending);
    c.beginChannels(name, sizeof(name), channels, APPLE80211_MAX_CHANNELS + 1, true);
    assert(!c.pending);
    assert(rtw89ScanObservedSince(7, 0));
    assert(!rtw89ScanObservedSince(7, 8));
    assert(rtw89ScanObservedSince(8, 8) && rtw89ScanObservedSince(9, 8));
    assert(rtw89ScanObservedSince(1, 0xffffffffU));
    assert(!rtw89ScanObservedSince(0xffffffffU, 1));
    puts("== scan completion ownership, channel-list retries and observation freshness: 0 failure(s)");
}

int main(int argc, char **argv)
{
    testCompletion();
    static_assert(sizeof(apple80211req) == 40, "observed user request envelope");
    static_assert(sizeof(apple80211_channel) == 12, "channel record layout");
    assert(rtw89ScanSet40(0x802869c8UL, 10));
    assert(rtw89ScanSet40(0x802869c8UL, 86));
    assert(rtw89ScanGet40(0xc02869c9UL, 11));
    assert(!rtw89ScanSet40(0x802869c8UL, APPLE80211_IOC_ASSOCIATE));
    assert(!rtw89ScanGet40(0xc02869c9UL, APPLE80211_IOC_CIPHER_KEY));
    assert(!rtw89ScanSet40(0xc02869c9UL, 10));
    assert(!rtw89ScanGet40(0x802869c8UL, 11));
    assert(rtw89HostScanLayout(10, 5528) && rtw89HostScanLayout(86, 5352));
    assert(!rtw89HostScanLayout(86, sizeof(apple80211_scan_multiple_data)));
    assert(!rtw89HostScanLayout(APPLE80211_IOC_ASSOCIATE, 5352));

    const uint8_t name[] = {'p','r',0,'t','e','s','t'};
    uint8_t wire[5352] = {};
    word(wire, 0, 1); word(wire, 4, 3); word(wire, 8, 2);
    word(wire, 12, 1); word(wire, 16, sizeof(name));
    memcpy(wire+20, name, sizeof(name));
    word(wire, 52, 1); // second SSID is an empty wildcard
    word(wire, 528, 1); word(wire, 532, 1);
    word(wire, 536, 149); word(wire, 540, 0x92);
    apple80211_scan_data out = {};
    assert(rtw89DecodeHostScan(86, wire, sizeof(wire), out));
    assert(out.ssid_len == sizeof(name) && !memcmp(out.ssid, name, sizeof(name)));
    assert(out.num_channels == 1 && out.channels[0].channel == 149 && out.channels[0].flags == 0x92);

    // Empty entries before/after the target and duplicate targets are equivalent.
    word(wire, 16, 0); word(wire, 56, sizeof(name)); memcpy(wire+60, name, sizeof(name));
    assert(rtw89DecodeHostScan(86, wire, sizeof(wire), out) && out.ssid_len == sizeof(name));
    assert(!memcmp(out.ssid, name, sizeof(name)));
    word(wire, 16, sizeof(name));
    assert(rtw89DecodeHostScan(86, wire, sizeof(wire), out) && out.ssid_len == sizeof(name));
    wire[60] = 'x';
    assert(rtw89DecodeHostScan(86, wire, sizeof(wire), out) && out.ssid_len == 0);
    assert(out.num_channels == 1); // distinct names must not erase channel constraints
    word(wire, 16, 0); word(wire, 56, 0);
    assert(rtw89DecodeHostScan(86, wire, sizeof(wire), out) && out.ssid_len == 0);

    // Valid 20-channel packet: a legacy 16-SSID parser reads flags 146 as its
    // channel count at byte 768 and rejects it. Keep every channel, including
    // those after entry 16, in the normalized native request.
    const unsigned channels[] = {1,6,11,2,5,7,8,9,13,14,36,40,52,56,60,64,108,112,116,149};
    word(wire, 8, 2); word(wire, 16, sizeof(name)); word(wire, 528, 20);
    for (unsigned i = 0; i < 20; ++i) {
        word(wire, 532+12*i, 1); word(wire, 536+12*i, channels[i]);
        word(wire, 540+12*i, i < 10 ? 0x8a : 0x92);
    }
    assert(rtw89ScanWord(wire+768) == 146);
    assert(rtw89DecodeHostScan(86, wire, sizeof(wire), out));
    assert(out.ssid_len == sizeof(name) && out.num_channels == 20);
    for (unsigned i = 0; i < 20; ++i) {
        assert(out.channels[i].version == 1 && out.channels[i].channel == channels[i]);
        assert(out.channels[i].flags == (i < 10 ? 0x8aU : 0x92U));
    }
    // Respect the native structure's existing capacity without over-running it.
    word(wire, 528, APPLE80211_MAX_CHANNELS+1);
    assert(rtw89DecodeHostScan(86, wire, sizeof(wire), out));
    assert(out.num_channels == APPLE80211_MAX_CHANNELS);
    word(wire, 528, 1000);
    assert(!rtw89DecodeHostScan(86, wire, sizeof(wire), out));
    word(wire, 528, 0); word(wire, 8, 11);
    assert(!rtw89DecodeHostScan(86, wire, sizeof(wire), out));
    word(wire, 8, 2); word(wire, 56, 33);
    assert(!rtw89DecodeHostScan(86, wire, sizeof(wire), out));
    word(wire, 56, 0); word(wire, 0, 2);
    assert(!rtw89DecodeHostScan(86, wire, sizeof(wire), out));
    word(wire, 0, 1);
    assert(!rtw89DecodeHostScan(86, wire, sizeof(wire)-1, out));
    assert(!rtw89DecodeHostScan(86, nullptr, sizeof(wire), out));
    assert(!rtw89DecodeHostScan(20, wire, sizeof(wire), out));

    uint8_t single[5528] = {};
    word(single, 0, 1); word(single, 4, 3); word(single, 16, sizeof(name));
    memcpy(single+20, name, sizeof(name));
    word(single, 68, 1); word(single, 72, 1); word(single, 76, 6); word(single, 80, 0x8a);
    assert(rtw89DecodeHostScan(10, single, sizeof(single), out));
    assert(out.ssid_len == sizeof(name) && out.num_channels == 1 && out.channels[0].channel == 6);
    word(single, 16, 0); // channel-only directed scan
    assert(rtw89DecodeHostScan(10, single, sizeof(single), out));
    assert(out.ssid_len == 0 && out.num_channels == 1);
    word(single, 16, 33);
    assert(!rtw89DecodeHostScan(10, single, sizeof(single), out));
    word(single, 16, 0); word(single, 68, 1000);
    assert(!rtw89DecodeHostScan(10, single, sizeof(single), out));

    // Optional private captures stay outside the repository. No names/addresses
    // are printed or committed; test the observed one-name-plus-wildcard shape.
    for (int i = 1; i < argc; ++i) {
        uint8_t captured[8192] = {}; FILE *f = fopen(argv[i], "rb"); assert(f);
        size_t n = fread(captured, 1, sizeof(captured), f); fclose(f);
        assert(n == 5528 || n == 5352);
        unsigned type = n == 5528 ? 10 : 86;
        assert(rtw89DecodeHostScan(type, captured, n, out));
        assert(out.ssid_len == 14 && !memcmp(out.ssid, captured+20, out.ssid_len));
        uint32_t count = rtw89ScanWord(captured + (type == 10 ? 68 : 528));
        assert(out.num_channels == count);
        if (count == 1) assert(out.channels[0].channel == 149);
    }
    puts("== native scan wire fixtures: 0 failure(s)");
}
