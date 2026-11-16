/* SPDX-License-Identifier: GPL-2.0-only */
#include <mach/mach_types.h>
#include <mach/kmod.h>
#include "ReleaseVersion.hpp"

extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);
extern kern_return_t OwlyAirLinkBridge_kern_start(kmod_info_t *, void *);
extern kern_return_t OwlyAirLinkBridge_kern_stop(kmod_info_t *, void *);

/* The verified libkmod stubs dispatch these pointers. Kernel loader handles C++ initialization. */
KMOD_EXPLICIT_DECL(com.owly.airlink.eventbridge, RTLAIRLINK_VERSION, _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = OwlyAirLinkBridge_kern_start;
__private_extern__ kmod_stop_func_t *_antimain = OwlyAirLinkBridge_kern_stop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__;
