/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OWLY_STARTUP_PLAN_HPP
#define OWLY_STARTUP_PLAN_HPP
#include <stdint.h>

/* Immutable after module bootstrap. Each higher stage adds one execution
 * boundary. Missing opt-in leaves the plan at zero; malformed stages fail
 * closed. No IOKit, allocation, logging or kernel patcher calls here. */
class OwlyStartupPlan {
public:
    constexpr OwlyStartupPlan() : _stage(0) {}
    bool select(uint32_t value) {
        const bool valid = value >= 1 && value <= 4;
        __atomic_store_n(&_stage, valid ? value : 0, __ATOMIC_RELEASE);
        return valid;
    }
    uint32_t stage() const { return __atomic_load_n(&_stage, __ATOMIC_ACQUIRE); }
    bool registrationAllowed() const { return stage() >= 1; }
    bool runtimeAllowed() const { return stage() >= 2; }
    bool eventRouteAllowed() const { return stage() >= 3; }
    bool openRouteAllowed() const { return stage() >= 4; }
private:
    uint32_t _stage;
};
extern OwlyStartupPlan owlyStartupPlan;
#endif
