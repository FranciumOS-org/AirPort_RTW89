/* SPDX-License-Identifier: GPL-2.0-only */
/* EB1 kernel integration candidate. Native compile/runtime qualification pending.
 * No activation without -owlyeb1, exact family UUID and both entry fingerprints.
 */
#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <Headers/kern_patcher.hpp>
#include <Headers/kern_util.hpp>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOLocks.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <mach-o/loader.h>
#include <mach/task.h>
#include <mach/vm_param.h>
#include <kern/task.h>
#include <sys/proc.h>
#include "owly_event_core.h"
#include "OwlyStatus.hpp"
#include "OwlyRuntime.hpp"
#include "OwlyReadiness.hpp"
#include "OwlyStartupPlan.hpp"
#include "OwlyTargets.hpp"
#include "OwlyEntitlement.hpp"
#include "OwlyNativeSessions.hpp"
#include "OwlyNativeOpen.hpp"
#include "OwlyNativeVTable.hpp"

extern bool ADDPR(startSuccess);

namespace {
constexpr unsigned kMaxClients = 8;
constexpr uint32_t kRingSize = 65536;
constexpr IOOptionBits kNotifyCanDrop = 0x1; // XNU kIOUserNotifyOptionCanDrop
constexpr uint8_t kFamilyUUID[16] = {
    0x4c,0x07,0x53,0x8b,0x62,0xeb,0x3d,0x6d,
    0xae,0xf9,0x93,0xbc,0xdc,0xf4,0x5f,0xab
};
constexpr uint8_t kFrontendUUID[16] = {
    0xc7,0x95,0x57,0xb8,0x3f,0x1c,0x39,0x98,0x91,0xbf,0x33,0xb3,0xf1,0xf4,0x8d,0x37
};
constexpr uint8_t kOpenPrefix[16] = {
    0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,
    0x41,0x55,0x41,0x54,0x53,0x50,0x4d,0x89
};
constexpr uint8_t kEventPrefix[16] = {
    0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,
    0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec
};
using OpenFn = IOReturn (*)(IOService *, task_t, void *, UInt32,
                            OSDictionary *, IOUserClient **);
// Legacy4C IO80211InterfacePostMessage returns IOReturn. postMessage is a
// different, void-returning hardware ingress and is not the user event sink.
using EventFn = IOReturn (*)(IOService *, unsigned int, void *, unsigned long);
OpenFn originalOpen = nullptr;
EventFn originalEvent = nullptr;
uint64_t eventCalls = 0, actionEventCalls = 0;
using MethodFn = IOReturn (*)(IOUserClient *, uint32_t, IOExternalMethodArguments *,
    IOExternalMethodDispatch *, OSObject *, void *);
using MemoryFn = IOReturn (*)(IOUserClient *, UInt32, IOOptionBits *, IOMemoryDescriptor **);
using CloseFn = IOReturn (*)(IOUserClient *);
using StopFn = void (*)(IOUserClient *, IOService *);
using FreeFn = void (*)(IOUserClient *);
MethodFn originalNativeMethod = nullptr;
MemoryFn originalNativeMemory = nullptr;
CloseFn originalNativeClose = nullptr;
StopFn originalNativeStop = nullptr;
FreeFn originalNativeFree = nullptr;
mach_vm_address_t nativeVTable = 0;
IOSimpleLock *registryLock = nullptr;
IOWorkLoop *notificationLoop = nullptr;
OwlyReadiness readiness;
uint32_t runtimeInitialization = 0;
bool routesAttempted = false;

bool sameBytes(const void *a, const void *b, size_t count)
{
    return memcmp(a, b, count) == 0;
}

bool loadedUUIDMatches(mach_vm_address_t address, size_t size, const uint8_t expected[16])
{
    if (!address || size < sizeof(mach_header_64)) return false;
    const auto *header = reinterpret_cast<const mach_header_64 *>(address);
    if (header->magic != MH_MAGIC_64 || header->sizeofcmds > size - sizeof(*header))
        return false;
    const uint8_t *p = reinterpret_cast<const uint8_t *>(header + 1);
    size_t left = header->sizeofcmds;
    if (header->ncmds > left / sizeof(load_command)) return false;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (left < sizeof(load_command)) return false;
        const auto *cmd = reinterpret_cast<const load_command *>(p);
        if (cmd->cmdsize < sizeof(*cmd) || cmd->cmdsize > left) return false;
        if (cmd->cmd == LC_UUID) {
            if (cmd->cmdsize != sizeof(uuid_command)) return false;
            return sameBytes(reinterpret_cast<const uuid_command *>(p)->uuid,
                             expected, 16);
        }
        p += cmd->cmdsize;
        left -= cmd->cmdsize;
    }
    return false;
}

bool scopeMatches(IOService *vif, char name[16], uint32_t *reason = nullptr)
{
    if (reason) *reason = 1;
    if (!vif || !vif->metaCast("IO80211P2PInterface")) return false;
    const auto *role = OSDynamicCast(OSString, vif->getProperty("IO80211VirtualInterfaceRole"));
    const auto *bsd = OSDynamicCast(OSString, vif->getProperty("IOInterfaceName"));
    if (reason) *reason = 2;
    if (!role || !role->isEqualTo("AirLink")) return false;
    if (reason) *reason = 3;
    if (!bsd || bsd->getLength() < 5 ||
        bsd->getLength() >= 16 || strncmp(bsd->getCStringNoCopy(), "awdl", 4)) return false;
    const char *s = bsd->getCStringNoCopy();
    for (unsigned i = 4; i < bsd->getLength(); i++)
        if (s[i] < '0' || s[i] > '9') return false;
    bool found = false;
    if (reason) *reason = 4;
    IOService *provider = vif;
    for (unsigned depth = 0; provider && depth < 8; depth++, provider = provider->getProvider()) {
        if (provider->metaCast("AirPortRTW89Front")) {
            if (reason) *reason = 5;
            const auto *ready = OSDynamicCast(OSNumber, provider->getProperty("OWLY C2 native_vif_ready"));
            found = ready && ready->unsigned32BitValue() == 1;
            break;
        }
    }
    if (!found) return false;
    bzero(name, 16);
    memcpy(name, s, bsd->getLength());
    if (reason) *reason = 0;
    return true;
}

IOReturn toIOReturn(owly_event_result r)
{
    switch (r) {
        case OWLY_EVENT_OK: return kIOReturnSuccess;
        case OWLY_EVENT_BAD_ARGUMENT: return kIOReturnBadArgument;
        case OWLY_EVENT_NOT_READY: return kIOReturnNotReady;
        case OWLY_EVENT_FULL: return kIOReturnNoSpace;
        case OWLY_EVENT_BUSY: return kIOReturnBusy;
        case OWLY_EVENT_CORRUPT: return kIOReturnBadArgument;
        default: return kIOReturnUnsupported;
    }
}
}

class OwlyAirLinkUserClient : public IOUserClient {
    OSDeclareDefaultStructors(OwlyAirLinkUserClient)
public:
    bool initWithTask(task_t task, void *securityID, UInt32 type,
                      OSDictionary *properties) override;
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    void free() override;
    IOReturn clientClose() override;
    IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *arguments,
        IOExternalMethodDispatch *dispatch = nullptr, OSObject *target = nullptr,
        void *reference = nullptr) override;
    IOReturn clientMemoryForType(UInt32 type, IOOptionBits *options,
                                 IOMemoryDescriptor **memory) override;
    bool matches(IOService *vif) const { return _vif == vif; }
    void nativeEvent(uint32_t event, const void *data, size_t length);
    void signalNativeEvent();
    void closeAdapter();
private:
    struct InputView { const void *bytes; IOMemoryDescriptor *descriptor; size_t size; };
    static int readInput(void *cookie, size_t offset, void *out, size_t size);
    static void notify(OSObject *owner, IOInterruptEventSource *, int);
    static void releaseIncoming(IOExternalMethodArguments *a);
    void teardown();
    void publishStats();
    IOReturn handle(uint32_t selector, IOExternalMethodArguments *a, bool &adopted);
    IOService *_vif = nullptr;
    IOBufferMemoryDescriptor *_data = nullptr;
    IOBufferMemoryDescriptor *_control = nullptr;
    IOInterruptEventSource *_notification = nullptr;
    IOSimpleLock *_ringLock = nullptr;
    IOLock *_referenceLock = nullptr;
    IOLock *_lifecycleLock = nullptr;
    OSAsyncReference64 _asyncReference {};
    bool _referenceValid = false;
    bool _onLoop = false;
    bool _registeredClient = false;
    bool _closing = false;
    bool _notifyPending = false;
    uint64_t _notifyFailures = 0;
    struct owly_event_core _core {};
    char _interfaceName[16] {};
};

OSDefineMetaClassAndStructors(OwlyAirLinkUserClient, IOUserClient)

namespace {
struct KernelRegistryLock {
    using Token = IOInterruptState;
    bool valid() const { return registryLock != nullptr; }
    Token enter() { return IOSimpleLockLockDisableInterrupt(registryLock); }
    void leave(Token token) { IOSimpleLockUnlockEnableInterrupt(registryLock, token); }
};
OwlyNativeSessions<OwlyAirLinkUserClient, kMaxClients, KernelRegistryLock> clients;

bool registerClient(OwlyAirLinkUserClient *client) { return clients.add(client); }

void unregisterClient(OwlyAirLinkUserClient *client)
{
    auto *owned = clients.remove(client);
    if (owned) owned->release(); // Never release under the registry spin lock.
}

void closeSessionForNative(IOUserClient *native)
{
    auto *session = clients.take(native); // Transfers the one registry reference.
    if (session) {
        session->closeAdapter();
        session->release();
    }
}

IOReturn hookedNativeMethod(IOUserClient *native, uint32_t selector,
    IOExternalMethodArguments *a, IOExternalMethodDispatch *dispatch, OSObject *target, void *reference)
{
    auto *session = clients.find(native);
    if (!session) return originalNativeMethod
        ? originalNativeMethod(native, selector, a, dispatch, target, reference) : kIOReturnNotReady;
    OwlyStatus::number("OwlyEB1NativeMethodSelector", selector);
    const IOReturn result = session->externalMethod(selector, a, dispatch, target, reference);
    session->release();
    return result;
}

IOReturn hookedNativeMemory(IOUserClient *native, UInt32 type,
    IOOptionBits *options, IOMemoryDescriptor **memory)
{
    auto *session = clients.find(native);
    if (!session) return originalNativeMemory
        ? originalNativeMemory(native, type, options, memory) : kIOReturnNotReady;
    const IOReturn result = session->clientMemoryForType(type, options, memory);
    session->release();
    return result;
}

IOReturn hookedNativeClose(IOUserClient *native)
{
    closeSessionForNative(native);
    return originalNativeClose ? originalNativeClose(native) : kIOReturnNotReady;
}

void hookedNativeStop(IOUserClient *native, IOService *provider)
{
    closeSessionForNative(native);
    if (originalNativeStop) originalNativeStop(native, provider);
}

void hookedNativeFree(IOUserClient *native)
{
    closeSessionForNative(native);
    if (originalNativeFree) originalNativeFree(native);
}

struct NativeOpenOps {
    using Session = OwlyAirLinkUserClient;
    using Native = IOUserClient;
    using Status = IOReturn;
    static constexpr Status success = kIOReturnSuccess;
    static constexpr Status notReady = kIOReturnNotReady;
    static constexpr Status unsupported = kIOReturnUnsupported;
    IOService *vif;
    task_t task;
    void *securityID;
    OSDictionary *properties;
    IOUserClient **output;

    void clearOutput() { *output = nullptr; }
    Status prepare(Session *&session) {
        session = OSTypeAlloc(OwlyAirLinkUserClient);
        OwlyStatus::flag("OwlyEB1ClientAllocated", session != nullptr);
        if (!session) return kIOReturnNoMemory;
        if (!session->initWithTask(task, securityID, 0, properties)) {
            OwlyStatus::text("OwlyEB1ClientPhase", "adapter-init-failed");
            return kIOReturnNotPermitted;
        }
        if (!session->attach(vif)) {
            OwlyStatus::text("OwlyEB1ClientPhase", "adapter-attach-failed");
            return kIOReturnError;
        }
        if (!session->start(vif)) {
            OwlyStatus::text("OwlyEB1ClientPhase", "adapter-start-failed");
            return notReady;
        }
        return success;
    }
    Status openNative(Native *&native) {
        /* Exact pinned factory: AirLink role6 uses connect type4 and its own
         * interface-type2 AWDL entitlement check. Keep task/security/properties.
         * No raw class allocation, class-layout guess or permission change. */
        const Status result = originalOpen(vif, task, securityID, 4, properties, &native);
        OwlyStatus::number("OwlyEB1NativeFactoryResult", static_cast<uint32_t>(result));
        return result;
    }
    bool expectedNative(Native *native) {
        const auto actual = *reinterpret_cast<const uintptr_t *>(native);
        return nativeVTable && actual == nativeVTable + 2 * sizeof(uintptr_t);
    }
    bool bind(Session *session, Native *native) {
        return clients.bind(session, native);
    }
    void discard(Session *session) {
        if (session) { session->closeAdapter(); session->release(); }
    }
    void disposeNative(Native *native) {
        if (native) { native->clientClose(); native->release(); }
    }
    void publish(Native *native) { *output = native; }
    void commit(Session *session) {
        session->setProperty("OwlyEB1NativeUserClient", "IO80211AsyncEventUserClient");
        session->setProperty("OwlyEB1AdapterBound", true);
        session->release(); // The registry retains it until native close/stop/free.
        OwlyStatus::flag("OwlyEB1NativeClientBound", true);
        OwlyStatus::text("OwlyEB1ClientPhase", "native-client-opened");
    }
};

IOReturn hookedOpen(IOService *vif, task_t task, void *securityID, UInt32 type,
                    OSDictionary *properties, IOUserClient **handler)
{
    if (!originalOpen) return kIOReturnNotReady;
    OwlyStatus::number("OwlyEB1LastOpenType", type);
    OwlyStatus::flag("OwlyEB1OpenHookReached", true);
    char name[16];
    if (!owlyStartupPlan.openRouteAllowed() || !readiness.ready() || type != 0)
        return originalOpen(vif, task, securityID, type, properties, handler);
    uint32_t scopeReason = 0;
    const bool eligible = scopeMatches(vif, name, &scopeReason);
    OwlyStatus::number("OwlyEB1LastScopeReason", scopeReason);
    if (!eligible) return originalOpen(vif, task, securityID, type, properties, handler);
    if (!handler) return kIOReturnBadArgument;

    /* airportd has no AWDL key in the supplied signed entitlements. A matching
     * interface/type alone does not make its open an event-monitor request.
     * Preserve the original dispatch for every caller without this exact key. */
    OwlyEntitlement::Result permission;
    if (!task || task == kernel_task || !OwlyEntitlement::authorize(task, permission)) {
        OwlyStatus::flag("OwlyEB1OpenForwardedWithoutAWDL", true);
        return originalOpen(vif, task, securityID, type, properties, handler);
    }
    OwlyStatus::flag("OwlyEB1EligibleOpenReached", true);
    OwlyStatus::number("OwlyEB1OpenCallerPID", static_cast<uint32_t>(proc_selfpid()));
    OwlyStatus::flag("OwlyEB1OpenTaskIsCurrent", task == current_task());
    OwlyStatus::flag("OwlyEB1OpenTaskIsKernel", task == kernel_task);
    NativeOpenOps ops {vif, task, securityID, properties, handler};
    const IOReturn result = owlyOpenNative(ops);
    if(result==kIOReturnSuccess) {
        /* The scoped native path may initialize Legacy's AWDL scratch and
         * call private ABI only after this plugin has verified both image
         * UUIDs, method prefixes, native table and the real entitled client. */
        IOService *provider=vif;
        for(unsigned depth=0;provider && depth<8;depth++,provider=provider->getProvider()) {
            if(provider->metaCast("AirPortRTW89Front")) {
                provider->setProperty("OwlyNativeABIReady",true);
                break;
            }
        }
    }
    IOLog("OwlyEB1: native adapter caller_pid=%d interface=%s result=0x%x\n",
        proc_selfpid(), name, static_cast<unsigned>(result));
    return result;
}

IOReturn hookedEvent(IOService *vif, unsigned int event, void *payload, unsigned long length)
{
    if (!originalEvent) return kIOReturnNotReady;
    if (!readiness.ready() || !registryLock) {
        return originalEvent(vif, event, payload, length);
    }
    OwlyAirLinkUserClient *snapshot[kMaxClients];
    const unsigned count = static_cast<unsigned>(clients.snapshot(snapshot, kMaxClients,
        [vif](OwlyAirLinkUserClient *client) { return client->matches(vif); }));
    if (count) {
        OwlyStatus::number("OwlyEB1UserEventCalls", __atomic_add_fetch(&eventCalls, 1ULL, __ATOMIC_RELAXED));
        if (event == 48)
            OwlyStatus::number("OwlyEB1ActionEventCalls", __atomic_add_fetch(&actionEventCalls, 1ULL, __ATOMIC_RELAXED));
    }
    for (unsigned i = 0; i < count; i++) {
        /* Copy the caller's borrowed payload while it is valid at entry.
         * Never dereference it after the original family handler returns. */
        snapshot[i]->nativeEvent(event, payload, length);
    }
    const IOReturn result = originalEvent(vif, event, payload, length);
    for (unsigned i = 0; i < count; i++) {
        snapshot[i]->signalNativeEvent();
        snapshot[i]->release();
    }
    return result;
}
}

bool OwlyAirLinkUserClient::initWithTask(task_t task, void *securityID, UInt32 type,
                                       OSDictionary *properties)
{
    OwlyStatus::text("OwlyEB1ClientInitPhase", "invalid-caller");
    OwlyStatus::flag("OwlyEB1EntitlementAllowed", false);
    OwlyStatus::flag("OwlyEB1ParentClientInitialized", false);
    if (!task || task == kernel_task || type != 0) return false;
    OwlyEntitlement::Result entitlement;
    const bool allowed = OwlyEntitlement::authorize(task, entitlement);
    OwlyStatus::text("OwlyEB1EntitlementSingleValue", OwlyEntitlement::valueName(entitlement.single));
    OwlyStatus::text("OwlyEB1EntitlementDictionaryValue",
        entitlement.source == OwlyEntitlement::Source::Dictionary
            ? OwlyEntitlement::valueName(entitlement.dictionary) : "not-queried");
    OwlyStatus::text("OwlyEB1EntitlementSource", OwlyEntitlement::sourceName(entitlement.source));
    OwlyStatus::flag("OwlyEB1EntitlementDictionaryAvailable", entitlement.dictionaryAvailable);
    OwlyStatus::flag("OwlyEB1EntitlementAllowed", allowed);
    /* One line keeps caller and lookup outcomes in the same attempt. Registry
     * slots are independent last-value observations and may mix concurrent opens. */
    IOLog("OwlyEB1: client init caller_pid=%d task_current=%d single=%s dictionary=%s source=%s allowed=%d\n",
        proc_selfpid(), task == current_task(), OwlyEntitlement::valueName(entitlement.single),
        entitlement.source == OwlyEntitlement::Source::Dictionary
            ? OwlyEntitlement::valueName(entitlement.dictionary) : "not-queried",
        OwlyEntitlement::sourceName(entitlement.source), allowed);
    if (!allowed) {
        OwlyStatus::text("OwlyEB1ClientInitPhase", "entitlement-denied");
        return false;
    }
    if (!IOUserClient::initWithTask(task, securityID, type, properties)) {
        OwlyStatus::text("OwlyEB1ClientInitPhase", "parent-init-failed");
        return false;
    }
    OwlyStatus::flag("OwlyEB1ParentClientInitialized", true);
    _ringLock = IOSimpleLockAlloc();
    _referenceLock = IOLockAlloc();
    _lifecycleLock = IOLockAlloc();
    const bool initialized = _ringLock && _referenceLock && _lifecycleLock;
    OwlyStatus::text("OwlyEB1ClientInitPhase", initialized ? "ready" : "lock-allocation-failed");
    return initialized;
}

bool OwlyAirLinkUserClient::start(IOService *provider)
{
    if (!scopeMatches(provider, _interfaceName) || !notificationLoop ||
        !IOUserClient::start(provider)) return false;
    _vif = provider;
    _vif->retain();
    _data = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
        kIOMemoryKernelUserShared | kIODirectionInOut, kRingSize, PAGE_SIZE);
    _control = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
        kIOMemoryKernelUserShared | kIODirectionInOut, PAGE_SIZE, PAGE_SIZE);
    if (!_data || !_control) { teardown(); return false; }
    bzero(_control->getBytesNoCopy(), PAGE_SIZE);
    if (owly_event_init(&_core, _data->getBytesNoCopy(), kRingSize,
        static_cast<owly_event_control *>(_control->getBytesNoCopy()), _interfaceName)
        != OWLY_EVENT_OK) { teardown(); return false; }
    _notification = IOInterruptEventSource::interruptEventSource(this, notify);
    if (!_notification || notificationLoop->addEventSource(_notification) != kIOReturnSuccess) {
        teardown(); return false;
    }
    _onLoop = true;
    _notification->enable();
    _registeredClient = registerClient(this);
    if (!_registeredClient) { teardown(); return false; }
    setProperty("OwlyEB1Protocol", "event-only IOUC; BSD ioctl control");
    setProperty("OwlyEB1SyntheticEvents", 0ULL, 32);
    return true;
}

void OwlyAirLinkUserClient::teardown()
{
    if (_lifecycleLock) IOLockLock(_lifecycleLock);
    if (_ringLock) {
        const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(_ringLock);
        _closing = true;
        owly_event_close(&_core);
        _notifyPending = false;
        IOSimpleLockUnlockEnableInterrupt(_ringLock, irq);
    }
    if (_registeredClient) {
        _registeredClient = false;
        unregisterClient(this);
    }
    /* removeEventSource serializes against its workloop action. Descriptors and
     * locks stay alive until free, including any retained postMessage snapshot. */
    if (_notification && _onLoop) {
        _notification->disable();
        notificationLoop->removeEventSource(_notification);
        _onLoop = false;
    }
    if (_referenceLock) {
        IOLockLock(_referenceLock);
        if (_referenceValid) {
            releaseAsyncReference64(_asyncReference);
            bzero(_asyncReference, sizeof(_asyncReference));
            _referenceValid = false;
        }
        IOLockUnlock(_referenceLock);
    }
    if (_lifecycleLock) IOLockUnlock(_lifecycleLock);
}

void OwlyAirLinkUserClient::closeAdapter()
{
    IOService *provider = getProvider();
    if (provider) {
        if (_vif == provider) stop(provider);
        else teardown();
        detach(provider);
    } else {
        teardown();
    }
}

void OwlyAirLinkUserClient::stop(IOService *provider)
{
    teardown();
    IOUserClient::stop(provider);
}

void OwlyAirLinkUserClient::free()
{
    teardown();
    OSSafeReleaseNULL(_notification);
    OSSafeReleaseNULL(_data);
    OSSafeReleaseNULL(_control);
    OSSafeReleaseNULL(_vif);
    if (_referenceLock) { IOLockFree(_referenceLock); _referenceLock = nullptr; }
    if (_lifecycleLock) { IOLockFree(_lifecycleLock); _lifecycleLock = nullptr; }
    if (_ringLock) { IOSimpleLockFree(_ringLock); _ringLock = nullptr; }
    IOUserClient::free();
}

IOReturn OwlyAirLinkUserClient::clientClose()
{
    teardown();
    terminate();
    return kIOReturnSuccess;
}

int OwlyAirLinkUserClient::readInput(void *cookie, size_t offset, void *out, size_t size)
{
    auto *view = static_cast<InputView *>(cookie);
    if (!view || offset > view->size || size > view->size - offset) return 0;
    if (view->descriptor) return view->descriptor->readBytes(offset, out, size) == size;
    if (!view->bytes) return 0;
    memcpy(out, static_cast<const uint8_t *>(view->bytes) + offset, size);
    return 1;
}

void OwlyAirLinkUserClient::releaseIncoming(IOExternalMethodArguments *a)
{
    if (a && a->asyncReference && a->asyncReferenceCount && a->asyncWakePort) {
        OSAsyncReference64 temporary {};
        temporary[0] = a->asyncReference[0];
        releaseAsyncReference64(temporary);
    }
}

IOReturn OwlyAirLinkUserClient::externalMethod(uint32_t selector,
    IOExternalMethodArguments *a, IOExternalMethodDispatch *, OSObject *, void *)
{
    bool adopted = false;
    const IOReturn result = handle(selector, a, adopted);
    if (!adopted) releaseIncoming(a);
    return result;
}

IOReturn OwlyAirLinkUserClient::handle(uint32_t selector,
    IOExternalMethodArguments *a, bool &adopted)
{
    if (!a || !_ringLock || !_referenceLock) return kIOReturnBadArgument;
    if (a->scalarInputCount || a->scalarOutputCount) return kIOReturnBadArgument;
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(_ringLock);
    const bool closing = _closing;
    IOSimpleLockUnlockEnableInterrupt(_ringLock, irq);
    if (closing) return kIOReturnNotOpen;
    const size_t inputSize = a->structureInputDescriptor
        ? a->structureInputDescriptor->getLength() : a->structureInputSize;
    if (selector == 0) {
        if (a->asyncWakePort || !a->structureOutput || a->structureOutputDescriptor)
            return kIOReturnBadArgument;
        InputView view {a->structureInput, a->structureInputDescriptor, inputSize};
        bool prepared = false;
        if (view.descriptor) {
            if (view.descriptor->prepare(kIODirectionOut) != kIOReturnSuccess)
                return kIOReturnVMError;
            prepared = true;
        }
        size_t outputSize = a->structureOutputSize;
        const auto result = owly_event_sanity(readInput, &view, inputSize,
            _interfaceName, a->structureOutput, &outputSize);
        if (prepared) view.descriptor->complete(kIODirectionOut);
        if (result == OWLY_EVENT_OK) a->structureOutputSize = static_cast<uint32_t>(outputSize);
        return toIOReturn(result);
    }
    if (inputSize || a->structureOutputDescriptor) return kIOReturnBadArgument;
    if (selector == 1 || selector == 5 || selector == 7) {
        if (a->asyncWakePort || !a->structureOutput || a->structureOutputSize < 1)
            return kIOReturnBadArgument;
        uint8_t answer = 0;
        const auto result = owly_event_query(selector,
            readiness.ready(), &answer);
        if (result == OWLY_EVENT_OK) {
            *static_cast<uint8_t *>(a->structureOutput) = answer;
            a->structureOutputSize = 1;
        }
        return toIOReturn(result);
    }
    if (a->structureOutputSize) return kIOReturnBadArgument;
    if (selector == 2) {
        if (!a->asyncWakePort || !a->asyncReference ||
            a->asyncReferenceCount != kOSAsyncRef64Count) return kIOReturnBadArgument;
        IOLockLock(_referenceLock);
        const IOInterruptState state = IOSimpleLockLockDisableInterrupt(_ringLock);
        const auto result = _closing ? OWLY_EVENT_NOT_READY : owly_event_register(&_core);
        IOSimpleLockUnlockEnableInterrupt(_ringLock, state);
        if (result == OWLY_EVENT_OK) {
            if (_referenceValid) releaseAsyncReference64(_asyncReference);
            memcpy(_asyncReference, a->asyncReference, sizeof(_asyncReference));
            _referenceValid = true;
            adopted = true; // one incoming wake-port reference, released at halt/close
        }
        IOLockUnlock(_referenceLock);
        IOLog("OwlyEB1: event monitor registration %s rc=%u\n", _interfaceName, static_cast<unsigned>(result));
        OwlyStatus::number("OwlyEB1EventRegisterResult", static_cast<uint64_t>(result));
        return toIOReturn(result);
    }
    if (a->asyncWakePort) return kIOReturnBadArgument;
    if (selector == 3) {
        const IOInterruptState state = IOSimpleLockLockDisableInterrupt(_ringLock);
        const auto result = _closing ? OWLY_EVENT_NOT_READY : owly_event_start(&_core);
        IOSimpleLockUnlockEnableInterrupt(_ringLock, state);
        return toIOReturn(result);
    }
    if (selector == 4) {
        IOLockLock(_referenceLock);
        const IOInterruptState state = IOSimpleLockLockDisableInterrupt(_ringLock);
        owly_event_halt(&_core);
        _notifyPending = false;
        IOSimpleLockUnlockEnableInterrupt(_ringLock, state);
        if (_referenceValid) {
            releaseAsyncReference64(_asyncReference);
            bzero(_asyncReference, sizeof(_asyncReference));
            _referenceValid = false;
        }
        IOLockUnlock(_referenceLock);
        return kIOReturnSuccess;
    }
    return kIOReturnUnsupported;
}

IOReturn OwlyAirLinkUserClient::clientMemoryForType(UInt32 type,
    IOOptionBits *options, IOMemoryDescriptor **memory)
{
    if (!options || !memory || !_ringLock) return kIOReturnBadArgument;
    *memory = nullptr;
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(_ringLock);
    IOBufferMemoryDescriptor *selected = nullptr;
    if (!_closing && _core.started) {
        if (type == 1) selected = _data;
        if (type == 2) selected = _control;
    }
    if (selected) selected->retain();
    IOSimpleLockUnlockEnableInterrupt(_ringLock, irq);
    if (!selected) return type == 1 || type == 2 ? kIOReturnNotReady : kIOReturnUnsupported;
    *options = type == 1 ? kIOMapReadOnly : 0;
    *memory = selected;
    return kIOReturnSuccess;
}

void OwlyAirLinkUserClient::nativeEvent(uint32_t event, const void *data, size_t length)
{
    if (!_ringLock) return;
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(_ringLock);
    const auto result = _closing ? OWLY_EVENT_NOT_READY : owly_event_push(&_core, event, data, length);
    if (result == OWLY_EVENT_OK) _notifyPending = true;
    IOSimpleLockUnlockEnableInterrupt(_ringLock, irq);
}

void OwlyAirLinkUserClient::signalNativeEvent()
{
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(_ringLock);
    /* Serialize scheduling with teardown's closing transition. A retained event
     * source alone is insufficient: removeEventSource clears its workLoop.
     * interruptOccurred only schedules work; it does not enter the action/gate. */
    if (!_closing && _notifyPending && _notification)
        _notification->interruptOccurred(nullptr, nullptr, 0);
    IOSimpleLockUnlockEnableInterrupt(_ringLock, irq);
}

void OwlyAirLinkUserClient::notify(OSObject *owner, IOInterruptEventSource *, int)
{
    auto *self = OSDynamicCast(OwlyAirLinkUserClient, owner);
    if (!self) return;
    IOLockLock(self->_referenceLock);
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(self->_ringLock);
    const bool send = !self->_closing && self->_core.started &&
        self->_core.registered && self->_notifyPending;
    self->_notifyPending = false;
    IOSimpleLockUnlockEnableInterrupt(self->_ringLock, irq);
    if (send && self->_referenceValid) {
        /* Coalesce notifications and fail on a full Mach queue. No payload or
         * user pointer is sent: Apple drains the separately mapped byte ring. */
        const IOReturn result = sendAsyncResult64WithOptions(self->_asyncReference,
            kIOReturnSuccess, nullptr, 0, kNotifyCanDrop);
        if (result != kIOReturnSuccess && ++self->_notifyFailures <= 4)
            IOLog("OwlyEB1: notification failed rc=0x%x\n", static_cast<unsigned>(result));
    }
    IOLockUnlock(self->_referenceLock);
    self->publishStats();
}

void OwlyAirLinkUserClient::publishStats()
{
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(_ringLock);
    const auto stats = _core.stats;
    IOSimpleLockUnlockEnableInterrupt(_ringLock, irq);
    setProperty("OwlyEB1EventsEnqueued", stats.enqueued, 64);
    setProperty("OwlyEB1EventsDroppedFull", stats.full, 64);
    setProperty("OwlyEB1Rejected", stats.rejected, 64);
    setProperty("OwlyEB1RingFaults", stats.corrupt, 64);
    setProperty("OwlyEB1NotificationFailures", _notifyFailures, 64);
    // The adapter is attached without registerService(). Also expose the last
    // session's counters through the existing deferred bridge status publisher.
    OwlyStatus::number("OwlyEB1EventsEnqueued", stats.enqueued);
    OwlyStatus::number("OwlyEB1EventsDroppedFull", stats.full);
    OwlyStatus::number("OwlyEB1Rejected", stats.rejected);
    OwlyStatus::number("OwlyEB1RingFaults", stats.corrupt);
    OwlyStatus::number("OwlyEB1NotificationFailures", _notifyFailures);
}

namespace {
auto &targets = OwlyTargets::entries;

/* Byte/relocation audit of Legacy4C07538B...:
 * vtable symbol 0x14f340; clientMemoryForType at symbol+0x930 is an
 * external relocation to the public IOUserClient implementation.
 * The compiled native0.1.5 override independently occupies the same slot.
 * The object's address point is symbol+0x10. No object vptr is changed. */
struct NativeTarget {
    const char *symbol;
    size_t vtableOffset;
    uint8_t prefix[16];
};
constexpr NativeTarget nativeTargets[] = {
    {"__ZN27IO80211AsyncEventUserClient14externalMethodEjP25IOExternalMethodArgumentsP24IOExternalMethodDispatchP8OSObjectPv",
     0x860, {0x55,0x48,0x89,0xe5,0x83,0xfe,0x01,0x77,0x23,0x4c,0x8b,0x1d,0x68,0x07,0x0a,0x00}},
    {"__ZN27IO80211AsyncEventUserClient11clientCloseEv",
     0x900, {0x55,0x48,0x89,0xe5,0x53,0x50,0x48,0x89,0xfb,0xe8,0x64,0xfe,0xff,0xff,0x48,0x89}},
    {"__ZN27IO80211AsyncEventUserClient4stopEP9IOService",
     0x5d8, {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x50,0x48,0x89}},
    {"__ZN27IO80211AsyncEventUserClient4freeEv",
     0xa0, {0x55,0x48,0x89,0xe5,0x53,0x50,0x48,0x89,0xfb,0x48,0x8b,0xbf,0xd8,0x00,0x00,0x00}}
};
struct LiluMemoryWriter {
    bool enable() {
        if (!KernelPatcher::kernelWriteLock) return false;
        return MachInfo::setKernelWriting(true, KernelPatcher::kernelWriteLock) == KERN_SUCCESS;
    }
    bool disable() {
        return MachInfo::setKernelWriting(false, KernelPatcher::kernelWriteLock) == KERN_SUCCESS;
    }
};

bool installNativeRoutes(KernelPatcher &patcher, size_t id,
                         mach_vm_address_t address, size_t size)
{
    if (!owlyStartupPlan.openRouteAllowed() || size < 0x938) return false;
    const auto table = patcher.solveSymbol(id, "__ZTV27IO80211AsyncEventUserClient");
    patcher.clearError();
    const auto memory = patcher.solveSymbol(KernelPatcher::KernelID,
        "__ZN12IOUserClient19clientMemoryForTypeEjPjPP18IOMemoryDescriptor");
    patcher.clearError();
    if (!table || table < address || table - address > size - 0x938 ||
        (table % alignof(uintptr_t)) || !memory) return false;

    for (const auto &target : nativeTargets) {
        const auto method = patcher.solveSymbol(id, target.symbol);
        patcher.clearError();
        if (method < address || method - address > size - sizeof(target.prefix) ||
            !sameBytes(reinterpret_cast<const void *>(method), target.prefix, sizeof(target.prefix)) ||
            *reinterpret_cast<const uintptr_t *>(table + target.vtableOffset) != method)
            return false;
    }
    auto *slot = reinterpret_cast<uintptr_t *>(table + 0x930);
    if (__atomic_load_n(slot, __ATOMIC_ACQUIRE) != memory) return false;
    /* Original target is published before any call can enter the replacement.
     * The class-wide hook forwards every client not in our bounded registry. */
    originalNativeMemory = reinterpret_cast<MemoryFn>(memory);
    nativeVTable = table;
    LiluMemoryWriter writer;
    const auto written = OwlyNativeVTable::install(slot, memory,
        reinterpret_cast<uintptr_t>(hookedNativeMemory), writer);
    OwlyStatus::number("OwlyEB1NativeMemoryInstallResult", static_cast<uint32_t>(written));
    if (written != OwlyNativeVTable::Result::Installed) return false;
    OwlyStatus::flag("OwlyEB1NativeMemoryRouteInstalled", true);

    KernelPatcher::RouteRequest nativeRoutes[] = {
        {nativeTargets[0].symbol, hookedNativeMethod, originalNativeMethod},
        {nativeTargets[1].symbol, hookedNativeClose, originalNativeClose},
        {nativeTargets[2].symbol, hookedNativeStop, originalNativeStop},
        {nativeTargets[3].symbol, hookedNativeFree, originalNativeFree}
    };
    const bool installed = patcher.routeMultiple(id, nativeRoutes, arrsize(nativeRoutes), address, size) &&
        originalNativeMethod && originalNativeClose && originalNativeStop && originalNativeFree;
    patcher.clearError();
    OwlyStatus::flag("OwlyEB1NativeClientRoutesInstalled", installed);
    return installed;
}

void updateReady()
{
    const auto bits = readiness.snapshot();
    const bool ready = OwlyReadiness::isReady(bits);
    OwlyStatus::flag("OwlyEB1RoutesInstalled", (bits & OwlyReadiness::Routes) != 0);
    OwlyStatus::flag("OwlyEB1FrontendVerified", (bits & OwlyReadiness::Frontend) != 0);
    OwlyStatus::flag("OwlyEB1HooksReady", ready);
    if (ready) IOLog("OwlyEB1: exact-family/exact-frontend hooks ready; scoped to Owly AirLink\n");
}

void loaded(void *, KernelPatcher &patcher, size_t id, mach_vm_address_t address, size_t size)
{
    if (id == targets[1].loadIndex) {
        OwlyStatus::flag("OwlyEB1FrontendCallback", true);
        /* Stage 1/2 callbacks record arrival only: do not dereference a target
         * header or ask the patcher to resolve or alter any target code. */
        if (!owlyStartupPlan.eventRouteAllowed()) return;
        const bool verified = loadedUUIDMatches(address, size, kFrontendUUID);
        readiness.frontend(verified);
        IOLog("OwlyEB1: frontend UUID %s\n", verified ? "matched" : "mismatch; inactive");
        updateReady();
        return;
    }
    if (id != targets[0].loadIndex) return;
    OwlyStatus::flag("OwlyEB1FamilyCallback", true);
    if (!owlyStartupPlan.eventRouteAllowed()) return;
    bool expected = false;
    if (!__atomic_compare_exchange_n(&routesAttempted, &expected, true, false,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return;
    const bool familyValid = loadedUUIDMatches(address, size, kFamilyUUID);
    OwlyStatus::flag("OwlyEB1FamilyVerified", familyValid);
    if (!familyValid) { IOLog("OwlyEB1: family UUID/header mismatch; inactive\n"); return; }
    const char *openName = "__ZN23IO80211VirtualInterface13newUserClientEP4taskPvjP12OSDictionaryPP12IOUserClient";
    // postAFToP2pd calls this endpoint directly for event48 (72-byte receive
    // metadata followed by the actual action body). The old postMessage hook
    // never saw that path. Install exactly one event hook at the delivery sink;
    // hooking both endpoints would duplicate events that traverse both.
    const char *eventName = "__ZN23IO80211VirtualInterface27IO80211InterfacePostMessageEjPvm";
    const auto openAddress = patcher.solveSymbol(id, openName);
    patcher.clearError();
    const auto eventAddress = patcher.solveSymbol(id, eventName);
    patcher.clearError();
    if (size < 16 || openAddress < address || eventAddress < address ||
        openAddress - address > size - 16 || eventAddress - address > size - 16 ||
        !sameBytes(reinterpret_cast<const void *>(openAddress), kOpenPrefix, sizeof(kOpenPrefix)) ||
        !sameBytes(reinterpret_cast<const void *>(eventAddress), kEventPrefix, sizeof(kEventPrefix))) {
        IOLog("OwlyEB1: family function fingerprint mismatch; inactive\n");
        OwlyStatus::flag("OwlyEB1FingerprintsVerified", false);
        return;
    }
    OwlyStatus::flag("OwlyEB1FingerprintsVerified", true);
    /* Install the event hook first. Partial routing never exposes a type-0
     * client: readiness also requires the deferred service resources. */
    KernelPatcher::RouteRequest eventRoute {eventName, hookedEvent, originalEvent};
    if (!patcher.routeMultiple(id, &eventRoute, 1, address, size) || !originalEvent) {
        OwlyStatus::flag("OwlyEB1EventRouteInstalled", false);
        patcher.clearError(); IOLog("OwlyEB1: event route failed; inactive\n"); return;
    }
    OwlyStatus::flag("OwlyEB1EventRouteInstalled", true);
    OwlyStatus::text("OwlyEB1EventSource", "IO80211VirtualInterface::IO80211InterfacePostMessage");
    if (!owlyStartupPlan.openRouteAllowed()) {
        updateReady(); // Event trampoline forwards; no modern client is exposed.
        return;
    }
    if (!installNativeRoutes(patcher, id, address, size)) {
        IOLog("OwlyEB1: native client contract/route mismatch; no adapted client exposed\n");
        return;
    }
    KernelPatcher::RouteRequest openRoute {openName, hookedOpen, originalOpen};
    if (!patcher.routeMultiple(id, &openRoute, 1, address, size) || !originalOpen || !originalEvent) {
        OwlyStatus::flag("OwlyEB1OpenRouteInstalled", false);
        patcher.clearError(); IOLog("OwlyEB1: client route failed; inactive\n"); return;
    }
    OwlyStatus::flag("OwlyEB1OpenRouteInstalled", true);
    readiness.routes();
    updateReady();
}

void startPlugin()
{
    OwlyStatus::flag("OwlyEB1PluginStartReached", true);
    if (!checkKernelArgument("-owlyeb1") || !owlyStartupPlan.registrationAllowed()) {
        IOLog("OwlyEB1: source candidate is opt-in; -owlyeb1 absent, inactive\n");
        return;
    }
    /* The loader phase registers callbacks only. The matched IOKit service
     * allocates notification resources after module initialization returns. */
    const bool descriptorsValid = OwlyTargets::valid(targets, arrsize(targets));
    OwlyStatus::flag("OwlyEB1KextDescriptorsValid", descriptorsValid);
    if (!descriptorsValid) {
        // No callback has been registered, so no runtime or unload pin is needed.
        ADDPR(startSuccess) = false;
        OwlyStatus::text("OwlyEB1BootstrapPhase", "invalid-kext-descriptor");
        return;
    }
    const auto result = lilu.onKextLoad(targets, arrsize(targets), loaded);
    OwlyStatus::number("OwlyEB1KextRegistrationResult", static_cast<uint64_t>(result));
    OwlyStatus::text("OwlyEB1BootstrapPhase", result == LiluAPI::Error::NoError
        ? "callbacks-registered" : "callback-registration-refused");
    if (result != LiluAPI::Error::NoError)
        IOLog("OwlyEB1: Lilu registration failed code=%u; inactive\n", static_cast<unsigned>(result));
}
const char *disableArguments[] = {"-owlyeb1off"};
const char *debugArguments[] = {"-owlyeb1dbg"};
}

bool OwlyRuntime::initialize(IOWorkLoop *loop)
{
    if (!loop || !owlyStartupPlan.runtimeAllowed()) return false;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&runtimeInitialization, &expected, 1, false,
                                   __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return false;
    registryLock = IOSimpleLockAlloc();
    if (!registryLock) {
        __atomic_store_n(&runtimeInitialization, 3, __ATOMIC_RELEASE);
        return false;
    }
    loop->retain();
    notificationLoop = loop;
    readiness.runtime();
    __atomic_store_n(&runtimeInitialization, 2, __ATOMIC_RELEASE);
    updateReady();
    return true;
}

void OwlyRuntime::deactivate()
{
    /* Retained clients and Lilu routes can still refer to these globals.
     * Leave the bounded module-lifetime lock/loop allocated; never re-arm. */
    readiness.stop();
    updateReady();
}

PluginConfiguration ADDPR(config) {
    xStringify(PRODUCT_NAME), parseModuleVersion(xStringify(MODULE_VERSION)),
    LiluAPI::AllowNormal,
    disableArguments, arrsize(disableArguments),
    debugArguments, arrsize(debugArguments),
    nullptr, 0,
    static_cast<KernelVersion>(25), static_cast<KernelVersion>(25), startPlugin
};
