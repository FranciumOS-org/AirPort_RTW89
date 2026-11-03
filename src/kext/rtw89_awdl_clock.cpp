// SPDX-License-Identifier: GPL-2.0
/*
 * The AWDL availability window clock.
 *
 * AWDL is a timeline, not a link: every peer divides time into availability
 * windows of 16 TU and agrees to be listening in them. The protocol engine
 * lives in IO80211FamilyLegacy and hands us a template; the schedule and the
 * radio are ours. This is the part that keeps time.
 *
 * rtw89_awdl_timing.cpp already asked the only question that mattered before
 * writing it -- whether this host wakes punctually enough, every time, with
 * the tail and not the average deciding it -- so this reuses its shape: a
 * thread_call on absolute deadlines counted from the instant the clock
 * started, never an interval from now. An interval from now makes every
 * overshoot cumulative, which once read as two thirds of a second of drift
 * and made the machine look hopeless when it was the measurement that was
 * wrong.
 *
 * Each wake-up calls the compat side with the time the window was *due*, not
 * the time the call arrived, so a late wake-up still stamps its frame with the
 * window it belongs to. The transmit loop decides whether that window carries
 * a frame; most do not.
 */
#include "AirPortRTW89.hpp"

#include <IOKit/IOLib.h>
#include <kern/thread_call.h>

#define LOG(fmt, ...) IOLog("AirPort_RTW89: " fmt "\n", ##__VA_ARGS__)

/* One availability window: 16 TU, a TU being 1024 us. */
#define AW_PERIOD_US    16384
/* How often to say we are still running: every ~30 s, not every window. */
#define AW_REPORT_EVERY 1800

namespace {

struct Clock {
    thread_call_t call = nullptr;
    uint64_t baseAbs = 0;       /* mach_absolute_time() when the clock started */
    uint64_t periodAbs = 0;     /* one window, in mach absolute units */
    uint64_t baseUs = 0;        /* the same instant, in us */
    uint64_t windows = 0;       /* windows since the start, counting every one */
    uint32_t missed = 0;        /* wake-ups a whole window or more late */
    bool running = false;
    volatile bool inTick = false;
};

Clock gClock;

uint64_t nowUs()
{
    uint64_t ns;

    absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
    return ns / 1000;
}

void tick(thread_call_param_t, thread_call_param_t)
{
    uint64_t due, deadline;
    int64_t late;

    if (!gClock.running)
        return;
    gClock.inTick = true;

    due = gClock.baseUs + gClock.windows * AW_PERIOD_US;
    late = (int64_t)(nowUs() - due);
    if (late >= AW_PERIOD_US)
        gClock.missed++;

    /*
     * The window's own time, truncated to 32 bits as AWDL's timestamps are.
     * The loop keeps the schedule and sends a sync frame every seventh
     * window; the rest it counts and returns from.
     */
    rtw89_glue_awdl_tick((uint32_t)due);

    gClock.windows++;
    if (gClock.windows % AW_REPORT_EVERY == 0) {
        uint32_t sent = 0, failed = 0, dsent = 0, dfailed = 0;

        rtw89_glue_awdl_tx_counts(&sent, &failed);
        /*
         * The data frames too, which until now were reported once and never
         * again: the only line about them said the first could not be sent,
         * and whether any of the hundreds after it went out was unknowable.
         * They are the ones a transfer is made of, so they are counted here
         * beside the sync frames.
         */
        rtw89_glue_awdl_data_counts(&dsent, &dfailed);
        LOG("awdl clock: %llu windows, %u frame(s) sent, %u not, %u window(s) missed; "
            "data frames %u sent, %u not",
            (unsigned long long)gClock.windows, sent, failed, gClock.missed,
            dsent, dfailed);
    }

    deadline = gClock.baseAbs + gClock.windows * gClock.periodAbs;
    thread_call_enter_delayed(gClock.call, deadline);
    gClock.inTick = false;
}

} /* namespace */

void rtw89_awdl_clock_start(uint8_t channel)
{
    uint64_t deadline;

    if (gClock.running)
        return;
    if (!gClock.call)
        gClock.call = thread_call_allocate(tick, nullptr);
    if (!gClock.call) {
        LOG("awdl clock: no thread_call could be allocated; nothing will transmit");
        return;
    }
    gClock.windows = 1;         /* the first wake-up is window 1 */
    gClock.missed = 0;
    gClock.running = true;
    nanoseconds_to_absolutetime((uint64_t)AW_PERIOD_US * 1000, &gClock.periodAbs);
    gClock.baseAbs = mach_absolute_time();
    gClock.baseUs = nowUs();
    rtw89_glue_awdl_tx_start(channel);
    LOG("awdl clock: running on channel %u, a window every %u us",
        (unsigned int)channel, (unsigned int)AW_PERIOD_US);
    deadline = gClock.baseAbs + gClock.periodAbs;
    thread_call_enter_delayed(gClock.call, deadline);
}

void rtw89_awdl_clock_stop(void)
{
    if (!gClock.call)
        return;
    /* thread_call_cancel_wait() is in com.apple.kpi.private, which this kext
     * does not link against: cancel, then wait out a tick already running. */
    gClock.running = false;
    thread_call_cancel(gClock.call);
    for (unsigned int ms = 0; gClock.inTick && ms < 200; ms++)
        IOSleep(1);
    rtw89_glue_awdl_tx_stop();
    LOG("awdl clock: stopped after %llu window(s), %u missed",
        (unsigned long long)gClock.windows, gClock.missed);
    thread_call_free(gClock.call);
    gClock.call = nullptr;
}
