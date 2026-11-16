/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OWLY_READINESS_HPP
#define OWLY_READINESS_HPP
#include <stdint.h>

/* One atomic snapshot prevents a late callback from re-enabling a stopped
 * service. Each bit is released only after its associated resources exist. */
class OwlyReadiness {
public:
    enum : uint32_t { Routes = 1, Frontend = 2, Runtime = 4, Stopped = 8 };
    void routes() { __atomic_fetch_or(&_bits, Routes, __ATOMIC_RELEASE); }
    void frontend(bool verified) {
        if (verified) __atomic_fetch_or(&_bits, Frontend, __ATOMIC_RELEASE);
        else __atomic_fetch_and(&_bits, ~uint32_t(Frontend), __ATOMIC_RELEASE);
    }
    void runtime() { __atomic_fetch_or(&_bits, Runtime, __ATOMIC_RELEASE); }
    void stop() { __atomic_fetch_or(&_bits, Stopped, __ATOMIC_RELEASE); }
    uint32_t snapshot() const { return __atomic_load_n(&_bits, __ATOMIC_ACQUIRE); }
    bool ready() const { return isReady(snapshot()); }
    static bool isReady(uint32_t value) {
        return (value & (Routes | Frontend | Runtime | Stopped)) ==
               (Routes | Frontend | Runtime);
    }
private:
    uint32_t _bits = 0;
};
#endif
