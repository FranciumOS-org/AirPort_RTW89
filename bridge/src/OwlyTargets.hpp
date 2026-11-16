/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OWLY_TARGETS_HPP
#define OWLY_TARGETS_HPP
#include <Headers/kern_patcher.hpp>
#include <stddef.h>

namespace OwlyTargets {
/* Actual Lilu1.7.3 MachInfo::init reads paths[0] in KC mode before checking
 * pathNum. A cache-only target still needs a non-null path string here. These are
 * descriptor paths; this module never installs files into /System. */
static const char *familyPaths[] = {
    "/System/Library/Extensions/IO80211FamilyLegacy.kext/Contents/MacOS/IO80211FamilyLegacy"
};
static const char *frontendPaths[] = {
    "/System/Library/Extensions/AirPortRTW89Front-ABI5EB.kext/Contents/MacOS/AirPortRTW89Front"
};
static KernelPatcher::KextInfo entries[] = {
    {"com.apple.iokit.IO80211FamilyLegacy", familyPaths, 1, {true}, {}, 0},
    {"com.rtw89.front", frontendPaths, 1, {true}, {}, 0}
};

inline bool kextPath(const char *path)
{
    if (!path || path[0] != '/') return false;
    for (const char *p = path; *p; ++p)
        if (p[0] == '.' && p[1] == 'k' && p[2] == 'e' &&
            p[3] == 'x' && p[4] == 't') return true;
    return false;
}

inline bool valid(const KernelPatcher::KextInfo *items, size_t count)
{
    if (!items || count == 0) return false;
    for (size_t i = 0; i < count; ++i) {
        const auto &item = items[i];
        if (!item.id || !item.id[0] || !item.paths || item.pathNum == 0) return false;
        for (size_t j = 0; j < item.pathNum; ++j)
            if (!kextPath(item.paths[j])) return false;
    }
    return true;
}
}
#endif
