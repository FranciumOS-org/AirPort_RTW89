/* SPDX-License-Identifier: GPL-2.0-only */
#include "OwlyNativeSessions.hpp"
#include "OwlyNativeOpen.hpp"
#include "OwlyNativeVTable.hpp"
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <thread>
#include <vector>
#include <algorithm>

namespace {
std::atomic<unsigned> alive {0};
struct Session {
    std::atomic<unsigned> refs {1};
    std::atomic<unsigned> closed {0};
    const unsigned id;
    explicit Session(unsigned n = 0) : id(n) { alive++; }
    void retain() { assert(refs.fetch_add(1) > 0); }
    void release() { if (refs.fetch_sub(1) == 1) { alive--; delete this; } }
};
struct TestLock {
    using Token = unsigned;
    std::mutex *mutex = nullptr;
    bool valid() const { return mutex != nullptr; }
    Token enter() { mutex->lock(); return 0; }
    void leave(Token) { mutex->unlock(); }
};
using Registry = OwlyNativeSessions<Session, 2, TestLock>;

void registryOwnership()
{
    std::mutex mutex;
    Registry registry {TestLock {&mutex}};
    Session *a = new Session(1), *b = new Session(2), *c = new Session(3);
    int nativeA = 1, nativeB = 2;
    assert(registry.add(a) && registry.add(b));
    assert(!registry.add(a) && !registry.add(c));
    assert(a->refs == 2 && b->refs == 2 && c->refs == 1);
    assert(registry.bind(a, &nativeA));
    assert(!registry.bind(b, &nativeA));
    assert(!registry.bind(a, &nativeB));
    assert(registry.bind(b, &nativeB));
    assert(!registry.find(nullptr) && !registry.take(nullptr));
    Session *found = registry.find(&nativeA);
    assert(found == a && a->refs == 3);
    found->release();
    Session *view[2] {};
    assert(registry.snapshot(view, 1, [](Session *) { return true; }) == 1);
    assert(view[0] == a); view[0]->release();
    assert(registry.snapshot(view, 2, [](Session *s) { return s->id == 2; }) == 1);
    assert(view[0] == b); view[0]->release();
    auto *taken = registry.take(&nativeA);
    assert(taken == a && !registry.find(&nativeA) && !registry.remove(a));
    taken->release();
    auto *removed = registry.remove(b);
    assert(removed == b && !registry.take(&nativeB)); removed->release();
    a->release(); b->release(); c->release();
    assert(alive == 0);
    Registry unavailable;
    a = new Session;
    assert(!unavailable.add(a) && !unavailable.bind(a, &nativeA));
    assert(!unavailable.find(&nativeA) && !unavailable.take(&nativeA));
    assert(!unavailable.remove(a) && unavailable.snapshot(view, 2, [](Session *) {return true;}) == 0);
    a->release();
}

void retainedCloseRace()
{
    std::mutex mutex;
    Registry registry {TestLock {&mutex}};
    int native = 1;
    Session *a = new Session(42);
    assert(registry.add(a) && registry.bind(a, &native));
    a->release();
    std::atomic<unsigned> heldReady {0}, winners {0};
    std::atomic<bool> mayRelease {false};
    std::vector<std::thread> workers;
    for (unsigned i = 0; i < 5; i++) workers.emplace_back([&, i] {
        Session *held = nullptr;
        if (i % 2) {
            Session *snapshot[2] {};
            assert(registry.snapshot(snapshot, 2, [](Session *) {return true;}) == 1);
            held = snapshot[0];
        } else {
            held = registry.find(&native);
        }
        assert(held && held->id == 42);
        heldReady.fetch_add(1, std::memory_order_release);
        while (!mayRelease.load(std::memory_order_acquire)) std::this_thread::yield();
        assert(held->closed == 1 && held->id == 42);
        held->release();
        for (unsigned j = 0; j < 6000; j++) {
            assert(!registry.find(&native));
            Session *snapshot[2] {};
            assert(registry.snapshot(snapshot, 2, [](Session *) {return true;}) == 0);
        }
    });
    while (heldReady.load(std::memory_order_acquire) != 5) std::this_thread::yield();
    std::vector<std::thread> closers;
    // Close, stop and free may all try cleanup; exactly one takes ownership.
    for (unsigned i = 0; i < 3; i++) closers.emplace_back([&] {
        auto *closing = registry.take(&native);
        if (closing) {
            assert(closing->closed.fetch_add(1) == 0);
            winners++;
            closing->release();
        }
    });
    for (auto &closer : closers) closer.join();
    assert(winners == 1 && !registry.find(&native) && alive == 1);
    // Lookup and event-snapshot references both outlive removal and cleanup.
    mayRelease.store(true, std::memory_order_release);
    for (auto &worker : workers) worker.join();
    assert(alive == 0);
}

struct Native { bool expected = true; };
struct Ops {
    using Session = ::Session;
    using Native = ::Native;
    using Status = int;
    static constexpr Status success = 0, notReady = 1, unsupported = 2;
    int prepareResult = 0, factoryResult = 0;
    bool nullSession = false, nullNative = false, expected = true, bindOK = true;
    Native *output = reinterpret_cast<Native *>(uintptr_t(1));
    unsigned sessionsMade = 0, sessionsDiscarded = 0, sessionsCommitted = 0;
    unsigned nativesMade = 0, nativesClosed = 0, factoryCalls = 0;
    unsigned binds = 0, published = 0;
    Session *bound = nullptr;
    Native *returned = nullptr;
    void clearOutput() { output = nullptr; }
    Status prepare(Session *&s) {
        if (!nullSession) { s = new Session; sessionsMade++; }
        return prepareResult;
    }
    Status openNative(Native *&n) {
        factoryCalls++;
        if (!nullNative) { n = new Native {expected}; nativesMade++; }
        return factoryResult;
    }
    bool expectedNative(Native *n) { return n->expected; }
    bool bind(Session *s, Native *) { binds++; if (bindOK) bound = s; return bindOK; }
    void discard(Session *s) { if (s) {sessionsDiscarded++; s->release();} }
    void disposeNative(Native *n) { if (n) {nativesClosed++; delete n;} }
    void publish(Native *n) { assert(bound); output = n; returned = n; published++; }
    void commit(Session *) { sessionsCommitted++; }
    void finish() { if (bound) {bound->release(); bound = nullptr;} if (returned) {delete returned; returned = nullptr;} }
};
void openTransactions()
{
    for (unsigned scenario = 0; scenario < 7; scenario++) {
        Ops ops;
        switch (scenario) {
            case 0: ops.prepareResult = 10; break;
            case 1: ops.nullSession = true; break;
            case 2: ops.factoryResult = 11; break; // Even anomalous nonnull failure is closed.
            case 3: ops.nullNative = true; break;
            case 4: ops.expected = false; break;
            case 5: ops.bindOK = false; break;
            default: break;
        }
        const int result = owlyOpenNative(ops);
        if (scenario < 6) {
            assert(result != 0 && !ops.output && !ops.published && !ops.sessionsCommitted);
            assert(ops.sessionsMade == ops.sessionsDiscarded);
            assert(ops.nativesMade == ops.nativesClosed);
        } else {
            assert(result == 0 && ops.output == ops.returned && ops.published == 1);
            assert(ops.binds == 1 && ops.sessionsCommitted == 1 && ops.factoryCalls == 1);
            // Simulated post-factory kernel rejection: tear down the bound session.
            ops.finish();
        }
        if (scenario < 2) assert(ops.factoryCalls == 0);
        else assert(ops.factoryCalls == 1);
        assert(alive == 0);
    }
}
struct Writer {
    uintptr_t *slot;
    unsigned enabled = 0, disabled = 0;
    bool allow = true, restore = true, race = false;
    bool enable() { enabled++; if (race) *slot = 33; return allow; }
    bool disable() {disabled++; return restore;}
};
void memorySlotTransaction()
{
    using R = OwlyNativeVTable::Result;
    uintptr_t words[] {91, 11, 92};
    Writer w {&words[1]};
    assert(OwlyNativeVTable::install(&words[1],11,22,w) == R::Installed);
    assert(words[0] == 91 && words[1] == 22 && words[2] == 92);
    assert(w.enabled == 1 && w.disabled == 1);
    assert(OwlyNativeVTable::install(&words[1],11,22,w) == R::Changed);
    assert(w.enabled == 1 && w.disabled == 1);
    assert(OwlyNativeVTable::install(nullptr,11,22,w) == R::Invalid);
    assert(OwlyNativeVTable::install(&words[1],0,22,w) == R::Invalid);
    assert(OwlyNativeVTable::install(&words[1],22,22,w) == R::Invalid);
    words[1] = 11; w = Writer {&words[1]}; w.allow = false;
    assert(OwlyNativeVTable::install(&words[1],11,22,w) == R::WriteDenied);
    assert(words[1] == 11 && w.enabled == 1 && w.disabled == 0);
    w = Writer {&words[1]}; w.race = true;
    assert(OwlyNativeVTable::install(&words[1],11,22,w) == R::Changed);
    assert(words[1] == 33 && w.enabled == 1 && w.disabled == 1);
    words[1] = 11; w = Writer {&words[1]}; w.restore = false;
    assert(OwlyNativeVTable::install(&words[1],11,22,w) == R::RestoreFailed);
    assert(words[1] == 22 && w.disabled == 1); // Caller must remain inactive.
}
}
int main()
{
    registryOwnership();
    std::puts("native adapter: capacity/duplicate/ownership/snapshot and unavailable registry passed");
    retainedCloseRace();
    std::puts("native adapter: retained lookup/snapshot versus close race passed");
    openTransactions();
    std::puts("native adapter: seven prepare/factory/identity/bind/commit failure paths passed");
    memorySlotTransaction();
    std::puts("native adapter: single-slot write, mismatch, race and protection failure paths passed");
    assert(alive == 0);
}

