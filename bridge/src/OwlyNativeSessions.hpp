/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OWLY_NATIVE_SESSIONS_HPP
#define OWLY_NATIVE_SESSIONS_HPP
#include <stddef.h>

/* Fixed, reference-owning registry. Lock supplies valid(), enter(), leave().
 * An entry owns one session reference, never a native-client reference:
 * native close/stop/free remove it without creating a retain cycle.
 * find/snapshot return retained references; take/remove transfer the entry's
 * reference to the caller. No release, allocation or callback under the lock. */
template <typename Session, size_t Capacity, typename Lock>
class OwlyNativeSessions {
    struct Entry { Session *session = nullptr; const void *native = nullptr; };
    struct Guard {
        Lock &lock;
        typename Lock::Token token;
        explicit Guard(Lock &l) : lock(l), token(l.enter()) {}
        ~Guard() { lock.leave(token); }
    };
    Entry _entries[Capacity] {};
    Lock _lock {};
public:
    OwlyNativeSessions() = default;
    explicit OwlyNativeSessions(const Lock &lock) : _lock(lock) {}

    bool add(Session *session) {
        if (!session || !_lock.valid()) return false;
        Guard guard(_lock);
        for (const auto &e : _entries) if (e.session == session) return false;
        for (auto &e : _entries) if (!e.session) {
            session->retain();
            e.session = session;
            return true;
        }
        return false;
    }

    bool bind(Session *session, const void *native) {
        if (!session || !native || !_lock.valid()) return false;
        Guard guard(_lock);
        for (const auto &e : _entries) if (e.native == native) return false;
        for (auto &e : _entries) if (e.session == session && !e.native) {
            e.native = native;
            return true;
        }
        return false;
    }

    Session *find(const void *native) {
        if (!native || !_lock.valid()) return nullptr;
        Guard guard(_lock);
        for (auto &e : _entries) if (e.native == native) {
            e.session->retain();
            return e.session;
        }
        return nullptr;
    }

    Session *take(const void *native) {
        if (!native || !_lock.valid()) return nullptr;
        Guard guard(_lock);
        for (auto &e : _entries) if (e.native == native) {
            auto *session = e.session;
            e = Entry {};
            return session;
        }
        return nullptr;
    }

    Session *remove(Session *session) {
        if (!session || !_lock.valid()) return nullptr;
        Guard guard(_lock);
        for (auto &e : _entries) if (e.session == session) {
            auto *owned = e.session;
            e = Entry {};
            return owned;
        }
        return nullptr;
    }

    template <typename Predicate>
    size_t snapshot(Session **out, size_t capacity, Predicate matches) {
        if (!out || !_lock.valid()) return 0;
        Guard guard(_lock);
        size_t count = 0;
        for (auto &e : _entries) if (e.session && count < capacity && matches(e.session)) {
            e.session->retain();
            out[count++] = e.session;
        }
        return count;
    }
};
#endif

