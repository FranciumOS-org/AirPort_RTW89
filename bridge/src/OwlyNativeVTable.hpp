/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OWLY_NATIVE_VTABLE_HPP
#define OWLY_NATIVE_VTABLE_HPP
#include <stdint.h>
#include <stddef.h>
namespace OwlyNativeVTable {
enum class Result { Invalid, Changed, WriteDenied, RestoreFailed, Installed };
/* Call only on a resolved, range-checked slot of the exact pinned Legacy
 * class. This changes one shared class method pointer, not an object's vptr,
 * metaclass, class size, or a kernel function body. Unmapped clients forward.
 * Writer serializes the brief protection window using Lilu's write lock.
 * Inactive partial installs keep a valid original target and forward. */
template <typename Writer>
Result install(uintptr_t *slot, uintptr_t expected, uintptr_t replacement, Writer &writer)
{
    if (!slot || reinterpret_cast<uintptr_t>(slot) % alignof(uintptr_t) ||
        !expected || !replacement || expected == replacement)
        return Result::Invalid;
    if (__atomic_load_n(slot, __ATOMIC_ACQUIRE) != expected) return Result::Changed;
    if (!writer.enable()) return Result::WriteDenied;
    uintptr_t current = expected;
    const bool changed = __atomic_compare_exchange_n(slot, &current, replacement,
        false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    const bool restored = writer.disable();
    if (!restored) return Result::RestoreFailed;
    return changed ? Result::Installed : Result::Changed;
}
}
#endif

