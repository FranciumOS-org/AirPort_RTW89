// SPDX-License-Identifier: GPL-2.0
#pragma once
#include <stdint.h>
#include <stdbool.h>

// Generation zero means a cache reader. Directed requests must not present
// entries last heard before that request as fresh scan results.
static inline bool rtw89ScanObservedSince(uint32_t observed, uint32_t requested)
{
    return !requested || (int32_t)(observed - requested) >= 0;
}
