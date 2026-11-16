/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OWLY_RUNTIME_HPP
#define OWLY_RUNTIME_HPP
class IOWorkLoop;
namespace OwlyRuntime {
/* Called once from IOService::start; never from module entry/Lilu API lock. */
bool initialize(IOWorkLoop *notificationLoop);
/* Terminal: trampolines forward to originals, and callbacks cannot re-arm. */
void deactivate();
}
#endif
