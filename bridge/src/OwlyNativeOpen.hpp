/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OWLY_NATIVE_OPEN_HPP
#define OWLY_NATIVE_OPEN_HPP
/* The production open transaction. Ops owns platform-specific preparation and
 * cleanup; this order is also exercised by failure-injection tests.
 * An output handle is never exposed until its native identity and sidecar
 * association are ready. Every unsuccessful native object is closed/released. */
template <typename Ops>
typename Ops::Status owlyOpenNative(Ops &ops)
{
    using Status = typename Ops::Status;
    typename Ops::Session *session = nullptr;
    typename Ops::Native *native = nullptr;
    ops.clearOutput();
    Status result = ops.prepare(session);
    if (result != Ops::success || !session) {
        ops.discard(session);
        return result == Ops::success ? Ops::notReady : result;
    }
    result = ops.openNative(native);
    if (result != Ops::success || !native) {
        ops.disposeNative(native);
        ops.discard(session);
        return result == Ops::success ? Ops::notReady : result;
    }
    if (!ops.expectedNative(native)) {
        ops.disposeNative(native);
        ops.discard(session);
        return Ops::unsupported;
    }
    if (!ops.bind(session, native)) {
        ops.disposeNative(native);
        ops.discard(session);
        return Ops::notReady;
    }
    ops.publish(native);
    ops.commit(session);
    return Ops::success;
}
#endif

