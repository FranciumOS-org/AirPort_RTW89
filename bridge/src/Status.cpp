/* SPDX-License-Identifier: GPL-2.0-only */
#include "OwlyStatus.hpp"
#include <IOKit/IORegistryEntry.h>
#include <libkern/libkern.h>

namespace {
enum Kind { Text, Number, Flag };
struct Slot {
    const char *key;
    Kind kind;
    uint64_t value;
    const char *string;
    bool present;
};
/* Fixed keys, no heap or IOKit dependency in recorders. */
Slot slots[] = {
    {"OwlyEB1Version", Text, 0, nullptr, false},
    {"OwlyEB1OpenForwardedWithoutAWDL", Flag, 0, nullptr, false},
    {"OwlyEB1NativeFactoryResult", Number, 0, nullptr, false},
    {"OwlyEB1NativeMethodSelector", Number, 0, nullptr, false},
    {"OwlyEB1NativeMemoryInstallResult", Number, 0, nullptr, false},
    {"OwlyEB1NativeMemoryRouteInstalled", Flag, 0, nullptr, false},
    {"OwlyEB1NativeClientRoutesInstalled", Flag, 0, nullptr, false},
    {"OwlyEB1NativeClientBound", Flag, 0, nullptr, false},
    {"OwlyEB1RequestedStage", Number, 0, nullptr, false},
    {"OwlyEB1StartupStage", Number, 0, nullptr, false},
    {"OwlyEB1RuntimeRequested", Flag, 0, nullptr, false},
    {"OwlyEB1BootstrapPhase", Text, 0, nullptr, false},
    {"OwlyEB1ClientPhase", Text, 0, nullptr, false},
    {"OwlyEB1ClientInitPhase", Text, 0, nullptr, false},
    {"OwlyEB1EntitlementSingleValue", Text, 0, nullptr, false},
    {"OwlyEB1EntitlementDictionaryValue", Text, 0, nullptr, false},
    {"OwlyEB1EntitlementSource", Text, 0, nullptr, false},
    {"OwlyEB1OpenCallerPID", Number, 0, nullptr, false},
    {"OwlyEB1OpenTaskIsCurrent", Flag, 0, nullptr, false},
    {"OwlyEB1OpenTaskIsKernel", Flag, 0, nullptr, false},
    {"OwlyEB1EntitlementDictionaryAvailable", Flag, 0, nullptr, false},
    {"OwlyEB1ParentClientInitialized", Flag, 0, nullptr, false},
    {"OwlyEB1LiluAccessResult", Number, 0, nullptr, false},
    {"OwlyEB1ShouldLoadResult", Number, 0, nullptr, false},
    {"OwlyEB1KextRegistrationResult", Number, 0, nullptr, false},
    {"OwlyEB1KextDescriptorsValid", Flag, 0, nullptr, false},
    {"OwlyEB1LastOpenType", Number, 0, nullptr, false},
    {"OwlyEB1LastScopeReason", Number, 0, nullptr, false},
    {"OwlyEB1EventRegisterResult", Number, 0, nullptr, false},
    {"OwlyEB1ModuleEntryReached", Flag, 0, nullptr, false},
    {"OwlyEB1OptInPresent", Flag, 0, nullptr, false},
    {"OwlyEB1ApiAccessReleased", Flag, 0, nullptr, false},
    {"OwlyEB1BootstrapAccepted", Flag, 0, nullptr, false},
    {"OwlyEB1PluginStartReached", Flag, 0, nullptr, false},
    {"OwlyEB1OpenHookReached", Flag, 0, nullptr, false},
    {"OwlyEB1EligibleOpenReached", Flag, 0, nullptr, false},
    {"OwlyEB1ClientAllocated", Flag, 0, nullptr, false},
    {"OwlyEB1EntitlementAllowed", Flag, 0, nullptr, false},
    {"OwlyEB1RoutesInstalled", Flag, 0, nullptr, false},
    {"OwlyEB1FrontendVerified", Flag, 0, nullptr, false},
    {"OwlyEB1HooksReady", Flag, 0, nullptr, false},
    {"OwlyEB1FrontendCallback", Flag, 0, nullptr, false},
    {"OwlyEB1FamilyCallback", Flag, 0, nullptr, false},
    {"OwlyEB1FamilyVerified", Flag, 0, nullptr, false},
    {"OwlyEB1FingerprintsVerified", Flag, 0, nullptr, false},
    {"OwlyEB1EventRouteInstalled", Flag, 0, nullptr, false},
    {"OwlyEB1EventSource", Text, 0, nullptr, false},
    {"OwlyEB1UserEventCalls", Number, 0, nullptr, false},
    {"OwlyEB1ActionEventCalls", Number, 0, nullptr, false},
    {"OwlyEB1EventsEnqueued", Number, 0, nullptr, false},
    {"OwlyEB1EventsDroppedFull", Number, 0, nullptr, false},
    {"OwlyEB1Rejected", Number, 0, nullptr, false},
    {"OwlyEB1RingFaults", Number, 0, nullptr, false},
    {"OwlyEB1NotificationFailures", Number, 0, nullptr, false},
    {"OwlyEB1OpenRouteInstalled", Flag, 0, nullptr, false},
    {"OwlyEB1ServiceStartReached", Flag, 0, nullptr, false},
    {"OwlyEB1ServiceParentStarted", Flag, 0, nullptr, false},
    {"OwlyEB1WorkLoopAllocated", Flag, 0, nullptr, false},
    {"OwlyEB1StatusTimerAvailable", Flag, 0, nullptr, false},
    {"OwlyEB1RuntimeInitAttempted", Flag, 0, nullptr, false},
    {"OwlyEB1RuntimeInitSucceeded", Flag, 0, nullptr, false},
    {"OwlyEB1ServiceStopped", Flag, 0, nullptr, false}
};

Slot *find(const char *key, Kind kind)
{
    if (!key) return nullptr;
    for (auto &slot : slots)
        if (slot.kind == kind && strcmp(slot.key, key) == 0) return &slot;
    return nullptr;
}
}

void OwlyStatus::text(const char *key, const char *value)
{
    auto *slot = find(key, Text);
    if (!slot || !value) return;
    __atomic_store_n(&slot->string, value, __ATOMIC_RELEASE);
    __atomic_store_n(&slot->present, true, __ATOMIC_RELEASE);
}

void OwlyStatus::number(const char *key, uint64_t value)
{
    auto *slot = find(key, Number);
    if (!slot) return;
    __atomic_store_n(&slot->value, value, __ATOMIC_RELEASE);
    __atomic_store_n(&slot->present, true, __ATOMIC_RELEASE);
}

void OwlyStatus::flag(const char *key, bool value)
{
    auto *slot = find(key, Flag);
    if (!slot) return;
    __atomic_store_n(&slot->value, value ? uint64_t(1) : uint64_t(0), __ATOMIC_RELEASE);
    __atomic_store_n(&slot->present, true, __ATOMIC_RELEASE);
}

void OwlyStatus::flush(IORegistryEntry *target)
{
    if (!target) return;
    for (auto &slot : slots) {
        if (!__atomic_load_n(&slot.present, __ATOMIC_ACQUIRE)) continue;
        if (slot.kind == Text) {
            const char *value = __atomic_load_n(&slot.string, __ATOMIC_ACQUIRE);
            if (value) target->setProperty(slot.key, value);
        } else {
            const uint64_t value = __atomic_load_n(&slot.value, __ATOMIC_ACQUIRE);
            if (slot.kind == Flag) target->setProperty(slot.key, value != 0);
            else target->setProperty(slot.key, value, 64);
        }
    }
}
