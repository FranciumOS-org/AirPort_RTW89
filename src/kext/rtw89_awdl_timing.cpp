// SPDX-License-Identifier: GPL-2.0
/*
 * Can this machine wake up on an AWDL schedule?
 *
 * The receive spike measured what AWDL asks for: availability windows of
 * 16 TU (16.384 ms), and Apple's own radio missing its own transmit time by
 * 400 us on 2.4 GHz and up to 1742 us on 5 GHz. So the driver does not have to
 * hit a microsecond deadline; it has to land inside a window, with something
 * over a millisecond of room.
 *
 * What is not known is whether this host can be relied on to wake up that
 * punctually, every time. rtw89ctl already reports frames reaching the driver
 * more than 5 ms after the chip had them, worst case several seconds, and one
 * such stall would drop us out of the schedule. Averages are no use here: the
 * tail is the whole question.
 *
 * So this asks a thread_call to wake at one availability window after another,
 * at microsecond scale -- the same primitive an AWDL loop would use -- and
 * records how late each wake-up was. Nothing is transmitted and the radio is
 * not touched; it is a clock measurement. It runs once, for a fixed number of
 * windows, and then reports and stops.
 */
#include "AirPortRTW89.hpp"

#include <IOKit/IOLib.h>
#include <kern/thread_call.h>

#define LOG(fmt, ...) IOLog("AirPort_RTW89: " fmt "\n", ##__VA_ARGS__)

/* One availability window: 16 TU, a TU being 1024 us. */
#define AW_PERIOD_US    16384
/* ~30 s of windows, enough for the tail to show itself without running forever */
#define AW_TICKS        1800

namespace {

struct Probe {
    thread_call_t call = nullptr;
    uint64_t baseAbs = 0;       /* mach_absolute_time() when the run started */
    uint64_t periodAbs = 0;     /* one window, in mach absolute units */
    uint64_t baseUs = 0;        /* the same instant, in us */
    uint64_t target = 0;        /* when this tick was due, in us */
    unsigned int ticks = 0;
    unsigned int late[6] = {};  /* <100us, <500us, <1ms, <5ms, <16ms, >=16ms */
    int64_t worst = 0;
    int64_t sum = 0;
    bool running = false;
    volatile bool inTick = false;
};

Probe gProbe;

uint64_t nowUs()
{
    uint64_t ns;

    absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
    return ns / 1000;
}

void bucket(int64_t err)
{
    unsigned int i = err < 100 ? 0 : err < 500 ? 1 : err < 1000 ? 2 :
                     err < 5000 ? 3 : err < AW_PERIOD_US ? 4 : 5;

    gProbe.late[i]++;
}

void report()
{
    const unsigned int n = gProbe.ticks ? gProbe.ticks : 1;

    /* The run's own length against what it should have been: if these differ
     * by much, the schedule drifted and the per-window figures below are
     * measuring the probe, not the machine. */
    LOG("awdl timing: %u windows of %u us, mean %lld us late, worst %lld us; "
        "the run took %llu us against %llu expected",
        gProbe.ticks, (unsigned int)AW_PERIOD_US, (long long)(gProbe.sum / n),
        (long long)gProbe.worst, (unsigned long long)(nowUs() - gProbe.baseUs),
        (unsigned long long)((uint64_t)gProbe.ticks * AW_PERIOD_US));
    LOG("awdl timing: under 100us %u, under 500us %u, under 1ms %u, "
        "under 5ms %u, under one window %u, a window or more late %u",
        gProbe.late[0], gProbe.late[1], gProbe.late[2], gProbe.late[3],
        gProbe.late[4], gProbe.late[5]);
    /* The last bucket is the one that matters: those are the windows an AWDL
     * loop would have missed outright. */
    if (gProbe.late[5])
        LOG("awdl timing: %u window(s) missed -- a software AWDL timeline would "
            "have fallen out of the schedule that many times in %u s",
            gProbe.late[5], (unsigned int)(AW_TICKS * AW_PERIOD_US / 1000000));
    else
        LOG("awdl timing: no window missed");
}

void tick(thread_call_param_t, thread_call_param_t)
{
    uint64_t deadline;
    int64_t err;

    if (!gProbe.running)
        return;
    gProbe.inTick = true;
    err = (int64_t)(nowUs() - gProbe.target);
    if (err < 0)            /* early: the deadline is a floor, so this is 0 late */
        err = 0;
    bucket(err);
    gProbe.sum += err;
    if (err > gProbe.worst)
        gProbe.worst = err;

    if (++gProbe.ticks >= AW_TICKS) {
        gProbe.running = false;
        report();
        gProbe.inTick = false;
        return;
    }
    /*
     * Each deadline is absolute, counted from the instant the run started, so
     * one late wake-up cannot push the rest along. An earlier version asked
     * for an interval from *now* instead, which made every overshoot
     * cumulative: the error grew by ~340 us a window until it read as two
     * thirds of a second, and the machine looked hopeless when it was the
     * measurement that was wrong.
     */
    gProbe.target = gProbe.baseUs + (uint64_t)gProbe.ticks * AW_PERIOD_US;
    deadline = gProbe.baseAbs + (uint64_t)gProbe.ticks * gProbe.periodAbs;
    thread_call_enter_delayed(gProbe.call, deadline);
    gProbe.inTick = false;
}

} /* namespace */

void rtw89_awdl_timing_start(void)
{
    uint64_t deadline;

    if (gProbe.running)
        return;
    if (!gProbe.call)
        gProbe.call = thread_call_allocate(tick, nullptr);
    if (!gProbe.call)
        return;
    bzero(gProbe.late, sizeof(gProbe.late));
    gProbe.ticks = 0;
    gProbe.worst = 0;
    gProbe.sum = 0;
    gProbe.running = true;
    nanoseconds_to_absolutetime((uint64_t)AW_PERIOD_US * 1000, &gProbe.periodAbs);
    gProbe.baseAbs = mach_absolute_time();
    gProbe.baseUs = nowUs();
    gProbe.target = gProbe.baseUs + AW_PERIOD_US;
    LOG("awdl timing: measuring %u windows of %u us (%u s), nothing is transmitted",
        (unsigned int)AW_TICKS, (unsigned int)AW_PERIOD_US,
        (unsigned int)(AW_TICKS * AW_PERIOD_US / 1000000));
    deadline = gProbe.baseAbs + gProbe.periodAbs;
    thread_call_enter_delayed(gProbe.call, deadline);
}

void rtw89_awdl_timing_stop(void)
{
    if (!gProbe.call)
        return;
    /* thread_call_cancel_wait() is in com.apple.kpi.private, which this kext
     * does not link against: cancel, then wait out a tick already running. */
    gProbe.running = false;
    thread_call_cancel(gProbe.call);
    for (unsigned int ms = 0; gProbe.inTick && ms < 200; ms++)
        IOSleep(1);
    thread_call_free(gProbe.call);
    gProbe.call = nullptr;
}
