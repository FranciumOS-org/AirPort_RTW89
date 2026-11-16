#!/usr/bin/env python3
"""Fail the build if the deferred startup boundary is accidentally crossed."""
import re
from pathlib import Path


def body(source, name):
    start = source.index(name)
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth and end < len(source):
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    if depth:
        raise ValueError('unbalanced function: ' + name)
    return source[opening + 1:end - 1]


def main():
    root = Path(__file__).resolve().parents[1]
    clean = {}
    for name in ['Bootstrap.cpp', 'Plugin.cpp', 'Status.cpp', 'Service.cpp']:
        text = (root / 'src' / name).read_text()
        clean[name] = re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)
    forbidden = re.compile(r'getResourceService\s*\(|setProperty\s*\(|workLoop\s*\(|'
                           r'IOSimpleLockAlloc\s*\(|timerEventSource\s*\(|\bnew\s|'
                           r'\b(?:malloc|IOMalloc|IOLockAlloc)\s*\(')
    checked = [('Bootstrap.cpp', 'ADDPR(kern_start)'),
               ('Plugin.cpp', 'void startPlugin()'),
               ('Status.cpp', 'void OwlyStatus::text('),
               ('Status.cpp', 'void OwlyStatus::number('),
               ('Status.cpp', 'void OwlyStatus::flag(')]
    for file, name in checked:
        if forbidden.search(body(clean[file], name)):
            raise SystemExit('EARLY_IOKIT_OR_ALLOCATION: ' + file + ':' + name)
    registered = dict(re.findall(r'\{"(OwlyEB1\w+)", (Text|Number|Flag),', clean['Status.cpp']))
    expected = {'text': 'Text', 'number': 'Number', 'flag': 'Flag'}
    for file, text in clean.items():
        for kind, key in re.findall(r'OwlyStatus::(text|number|flag)\("([^"]+)"', text):
            if registered.get(key) != expected[kind]:
                raise SystemExit('UNREGISTERED_OR_WRONG_STATUS_TYPE: ' + file + ':' + key)
    if 'OwlyStatus::flush(' in clean['Bootstrap.cpp'] or 'OwlyStatus::flush(' in clean['Plugin.cpp']:
        raise SystemExit('REGISTRY_PUBLICATION_OUTSIDE_SERVICE')
    if 'IOWorkLoop::workLoop()' not in body(clean['Service.cpp'], 'bool OwlyAirLinkBridge::start('):
        raise SystemExit('DEFERRED_WORKLOOP_MISSING')
    if 'LILU_CUSTOM_IOKIT_INIT=1' not in (root / 'build_macos.sh').read_text():
        raise SystemExit('CUSTOM_SERVICE_BUILD_FLAG_MISSING')
    bootstrap = body(clean['Bootstrap.cpp'], 'ADDPR(kern_start)')
    service = body(clean['Service.cpp'], 'bool OwlyAirLinkBridge::start(')
    callback = body(clean['Plugin.cpp'], 'void loaded(')
    initializer = body(clean['Plugin.cpp'], 'bool OwlyRuntime::initialize(')
    opened = body(clean['Plugin.cpp'], 'IOReturn hookedOpen(')
    if 'uint32_t requestedStage = 1;' not in bootstrap or 'owlyStartupPlan.registrationAllowed()' not in bootstrap:
        raise SystemExit('REGISTRATION_ONLY_DEFAULT_OR_BOOTSTRAP_GATE_MISSING')
    if 'if (!runtimeRequested)' not in service or 'owlyStartupPlan.runtimeAllowed()' not in service:
        raise SystemExit('SERVICE_RUNTIME_STAGE_GATE_MISSING')
    if service.index('if (!runtimeRequested)') > service.index('IOWorkLoop::workLoop()'):
        raise SystemExit('SERVICE_RUNTIME_ALLOCATED_BEFORE_STAGE_GATE')
    if callback.count('if (!owlyStartupPlan.eventRouteAllowed()) return;') != 2:
        raise SystemExit('HEADER_OR_ROUTE_STAGE_GATE_MISSING')
    if callback.index('if (!owlyStartupPlan.eventRouteAllowed()) return;') > callback.index('loadedUUIDMatches('):
        raise SystemExit('FRONTEND_HEADER_READ_BEFORE_STAGE_GATE')
    family = callback[callback.index('OwlyStatus::flag("OwlyEB1FamilyCallback"'):]
    if family.index('if (!owlyStartupPlan.eventRouteAllowed()) return;') > family.index('loadedUUIDMatches('):
        raise SystemExit('FAMILY_HEADER_READ_BEFORE_STAGE_GATE')
    if callback.index('if (!owlyStartupPlan.openRouteAllowed())') > callback.index('KernelPatcher::RouteRequest openRoute'):
        raise SystemExit('OPEN_ROUTE_BEFORE_STAGE_GATE')
    if 'owlyStartupPlan.runtimeAllowed()' not in initializer or 'owlyStartupPlan.openRouteAllowed()' not in opened:
        raise SystemExit('RUNTIME_OR_CLIENT_DEFENCE_GATE_MISSING')
    if callback.count('patcher.routeMultiple(') != 2 or '&routesAttempted' not in callback:
        raise SystemExit('ROUTE_COUNT_OR_ONE_ATTEMPT_BOUNDARY_CHANGED')
    registration = body(clean['Plugin.cpp'], 'void startPlugin()')
    if 'OwlyTargets::valid(targets, arrsize(targets))' not in registration:
        raise SystemExit('TARGET_DESCRIPTOR_GUARD_MISSING')
    if registration.index('if (!descriptorsValid)') > registration.index('lilu.onKextLoad('):
        raise SystemExit('TARGET_DESCRIPTOR_GUARD_TOO_LATE')
    invalid = body(registration, 'if (!descriptorsValid)')
    if 'ADDPR(startSuccess) = false;' not in invalid or 'return;' not in invalid:
        raise SystemExit('INVALID_DESCRIPTOR_CAN_REACH_RUNTIME_OR_REGISTRATION')
    native = body(clean['Plugin.cpp'], 'bool installNativeRoutes(')
    if 'owlyStartupPlan.openRouteAllowed()' not in native:
        raise SystemExit('NATIVE_ROUTES_BEFORE_STAGE4')
    if callback.index('if (!owlyStartupPlan.openRouteAllowed())') > callback.index('installNativeRoutes(patcher'):
        raise SystemExit('NATIVE_INSTALL_NOT_GATED')
    if callback.index('installNativeRoutes(patcher') > callback.index('KernelPatcher::RouteRequest openRoute'):
        raise SystemExit('FACTORY_EXPOSED_BEFORE_NATIVE_ROUTES')
    if 'OwlyEntitlement::authorize(task, permission)' not in opened or 'return originalOpen(vif, task, securityID, type, properties, handler)' not in opened:
        raise SystemExit('AUTHORIZATION_OR_ORIGINAL_DISPATCH_LOST')
    if opened.index('OwlyEntitlement::authorize(task, permission)') > opened.index('owlyOpenNative(ops)'):
        raise SystemExit('NATIVE_OPEN_BEFORE_AUTHORIZATION')
    if 'originalOpen(vif, task, securityID, 4, properties, &native)' not in clean['Plugin.cpp']:
        raise SystemExit('NATIVE_FACTORY_TASK_OR_ROLE_CHANGED')
    if 'nativeVTable + 2 * sizeof(uintptr_t)' not in clean['Plugin.cpp']:
        raise SystemExit('ACTUAL_NATIVE_CLASS_IDENTITY_GUARD_MISSING')
    if 'OwlyNativeVTable::install(slot, memory,' not in native or 'table + 0x930' not in native:
        raise SystemExit('PINNED_MEMORY_SLOT_MISSING')
    if 'target.prefix' not in native or 'target.vtableOffset' not in native:
        raise SystemExit('NATIVE_SYMBOL_PREFIX_OR_TABLE_GUARD_MISSING')
    for name in ['IOReturn hookedNativeClose(', 'void hookedNativeStop(', 'void hookedNativeFree(']:
        if 'closeSessionForNative(native)' not in body(clean['Plugin.cpp'], name):
            raise SystemExit('NATIVE_SESSION_TEARDOWN_HOOK_MISSING')
    if 'clients.find(native)' not in body(clean['Plugin.cpp'], 'IOReturn hookedNativeMethod(') or 'clients.find(native)' not in body(clean['Plugin.cpp'], 'IOReturn hookedNativeMemory('):
        raise SystemExit('UNSCOPED_NATIVE_METHOD_ROUTE')
    print('NATIVE_CLIENT_ADAPTER_AUDIT_PASSED: entitlement+original factory, exact class, gated routes and close/stop/free cleanup')
    print('LIFECYCLE_SOURCE_AUDIT_PASSED: no direct early IOKit/resource allocation; service owns publication')
    print('STAGE_BOUNDARY_AUDIT_PASSED: default1; stage1/2 callbacks never read target headers or route; runtime and modern open gated')
    print('TARGET_DESCRIPTOR_GATE_PASSED: rejects invalid targets before Lilu registration and runtime activation')


if __name__ == '__main__':
    main()
