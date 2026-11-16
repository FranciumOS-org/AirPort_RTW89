/* SPDX-License-Identifier: GPL-2.0-only */
#include <Headers/plugin_start.hpp>
#include <IOKit/IOService.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimerEventSource.h>
#include "OwlyRuntime.hpp"
#include "OwlyStatus.hpp"
#include "OwlyStartupPlan.hpp"
#include "ReleaseVersion.hpp"

extern bool ADDPR(startSuccess);

class EXPORT OwlyAirLinkBridge : public IOService {
    OSDeclareDefaultStructors(OwlyAirLinkBridge)
public:
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    void free() override;
private:
    static void timerFired(OSObject *, IOTimerEventSource *);
    void publish();
    void closeResources();
    IOWorkLoop *_loop = nullptr;
    IOTimerEventSource *_timer = nullptr;
    bool _attempted = false;
    bool _ownsRuntime = false;
};

OSDefineMetaClassAndStructors(OwlyAirLinkBridge, IOService)

void OwlyAirLinkBridge::publish()
{
    OwlyStatus::flush(this);
    auto *resources = IOService::getResourceService();
    if (resources && resources != this) OwlyStatus::flush(resources);
}

bool OwlyAirLinkBridge::start(IOService *provider)
{
    if (_attempted) return false;
    _attempted = true;
    OwlyStatus::flag("OwlyEB1ServiceStartReached", true);
    const bool parent = IOService::start(provider);
    OwlyStatus::flag("OwlyEB1ServiceParentStarted", parent);
    if (!parent) { publish(); return false; }
    /* Modified 2026-11-15: display branding; service class/identity unchanged. */
    setProperty("VersionInfo", "RTLAirBridge " RTLAIRLINK_VERSION);
    publish();
    /* A refused/disabled bootstrap remains observable but allocates no loop,
     * registers no new callback and never exposes a modern client. */
    const bool runtimeRequested = ADDPR(startSuccess) && owlyStartupPlan.runtimeAllowed();
    OwlyStatus::flag("OwlyEB1RuntimeRequested", runtimeRequested);
    if (!runtimeRequested) { publish(); registerService(); return true; }

    _loop = IOWorkLoop::workLoop();
    OwlyStatus::flag("OwlyEB1WorkLoopAllocated", _loop != nullptr);
    if (!_loop) { publish(); return false; }

    _timer = IOTimerEventSource::timerEventSource(this, timerFired);
    if (_timer && _loop->addEventSource(_timer) != kIOReturnSuccess) {
        _timer->release();
        _timer = nullptr;
    }
    OwlyStatus::flag("OwlyEB1StatusTimerAvailable", _timer != nullptr);
    if (!_timer) { publish(); closeResources(); return false; }
    /* Runtime keeps one module-lifetime loop reference, because Lilu routes
     * and live clients can outlive this service's matching lifetime. */
    OwlyStatus::flag("OwlyEB1RuntimeInitAttempted", true);
    _ownsRuntime = OwlyRuntime::initialize(_loop);
    OwlyStatus::flag("OwlyEB1RuntimeInitSucceeded", _ownsRuntime);
    publish();
    if (!_ownsRuntime) { closeResources(); return false; }
    if (_timer->setTimeoutMS(1000) != kIOReturnSuccess) {
        OwlyStatus::flag("OwlyEB1StatusTimerAvailable", false);
        closeResources();
        publish();
        return false;
    }
    registerService();
    return true;
}

void OwlyAirLinkBridge::timerFired(OSObject *owner, IOTimerEventSource *sender)
{
    auto *self = OSDynamicCast(OwlyAirLinkBridge, owner);
    if (!self) return;
    self->publish();
    if (self->_timer == sender && sender->setTimeoutMS(1000) != kIOReturnSuccess) {
        OwlyRuntime::deactivate();
        OwlyStatus::flag("OwlyEB1StatusTimerAvailable", false);
        self->publish();
    }
}

void OwlyAirLinkBridge::closeResources()
{
    if (_ownsRuntime) {
        OwlyRuntime::deactivate();
        _ownsRuntime = false;
    }
    if (_timer) {
        _timer->cancelTimeout();
        if (_loop) _loop->removeEventSource(_timer);
        _timer->release();
        _timer = nullptr;
    }
    if (_loop) { _loop->release(); _loop = nullptr; }
}

void OwlyAirLinkBridge::stop(IOService *provider)
{
    closeResources();
    OwlyStatus::flag("OwlyEB1ServiceStopped", true);
    publish();
    IOService::stop(provider);
}

void OwlyAirLinkBridge::free()
{
    closeResources();
    IOService::free();
}
