/* Test the actual production descriptor array against the pinned consumer's
 * paths[0] requirement. Not a test of the real kernel/Lilu runtime. */
#include "OwlyTargets.hpp"
#include <cassert>
#include <cstring>
#include <iostream>

static unsigned consumerCalls;
static void guardedConsumer(const KernelPatcher::KextInfo *items, size_t count)
{
    if (!OwlyTargets::valid(items, count)) return;
    for (size_t i = 0; i < count; ++i) {
        // Same precondition as the observed KC branch: read paths[0] first.
        assert(std::strstr(items[i].paths[0], ".kext"));
        ++consumerCalls;
    }
}

int main()
{
    const size_t count = sizeof(OwlyTargets::entries) / sizeof(OwlyTargets::entries[0]);
    assert(count == 2 && OwlyTargets::valid(OwlyTargets::entries, count));
    assert(std::strcmp(OwlyTargets::entries[1].id, "com.rtw89.front") == 0);
    assert(OwlyTargets::entries[1].pathNum == 1 && OwlyTargets::entries[1].paths[0]);
    guardedConsumer(OwlyTargets::entries, count);
    assert(consumerCalls == 2);
    std::cout << "PASS actual production targets satisfy pinned KC consumer path requirement\n";

    auto bad = OwlyTargets::entries[1];
    bad.paths = nullptr; bad.pathNum = 0; // Exact0.1.3 producer defect.
    consumerCalls = 0;
    guardedConsumer(&bad, 1);
    assert(consumerCalls == 0);
    std::cout << "PASS exact predecessor null/zero descriptor cannot reach unsafe consumer\n";

    const char *invalid[] = {nullptr};
    bad = OwlyTargets::entries[1]; bad.paths = invalid;
    guardedConsumer(&bad, 1); assert(consumerCalls == 0);
    const char *empty[] = {""}; bad.paths = empty;
    guardedConsumer(&bad, 1); assert(consumerCalls == 0);
    const char *noKext[] = {"/System/Library/Extensions/not-a-bundle"}; bad.paths = noKext;
    guardedConsumer(&bad, 1); assert(consumerCalls == 0);
    assert(!OwlyTargets::valid(nullptr, 1) && !OwlyTargets::valid(OwlyTargets::entries, 0));
    std::cout << "PASS invalid path shapes and empty inputs rejected without consumer access\n";

    const char *shortPaths[] = {".", "/.", "/.k", "/.ke", "/.kex", "/", "/x.kext"};
    for (const char *path : shortPaths) {
        const bool expected = std::strcmp(path, "/x.kext") == 0;
        assert(OwlyTargets::kextPath(path) == expected);
    }
    const char *two[] = {OwlyTargets::frontendPaths[0], nullptr};
    bad = OwlyTargets::entries[1]; bad.paths = two; bad.pathNum = 2;
    guardedConsumer(&bad, 1); assert(consumerCalls == 0);
    std::cout << "PASS short strings and all path entries remain bounded under sanitizers\n";
    std::cout << "RESULT 4 target-descriptor regression groups passed; no native boot/AirDrop proof\n";
}
