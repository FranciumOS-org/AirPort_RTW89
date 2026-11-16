#pragma once
#include <stddef.h>
/* Public KextInfo ABI layout, modeled for the standalone producer test.
 * Actual offsets were also checked in the pinned Lilu binary. */
class KernelPatcher {
public:
    struct KextInfo {
        const char *id;
        const char **paths;
        size_t pathNum;
        bool sys[6];
        bool user[2];
        size_t loadIndex;
    };
};
static_assert(sizeof(KernelPatcher::KextInfo) == 40, "x86_64 KextInfo ABI");
static_assert(offsetof(KernelPatcher::KextInfo, paths) == 8, "path offset");
static_assert(offsetof(KernelPatcher::KextInfo, pathNum) == 16, "count offset");
static_assert(offsetof(KernelPatcher::KextInfo, loadIndex) == 32, "index offset");
