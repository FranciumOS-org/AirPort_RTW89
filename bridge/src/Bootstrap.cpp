/* SPDX-License-Identifier: GPL-2.0-only */
/* Uses the public Lilu custom-kmod entry contract. Adapted from the Lilu BSD
 * startup flow (vit9696, 2016-2017); vendored license remains included.
 * Entry records only bounded static status. IOKit resources are created later
 * by Service.cpp after the loader/API registration phase has returned.
 */
#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <Headers/kern_util.hpp>
#include "OwlyStatus.hpp"
#include "OwlyStartupPlan.hpp"
#include "ReleaseVersion.hpp"

OwlyStartupPlan owlyStartupPlan;

extern PluginConfiguration ADDPR(config);
extern bool ADDPR(startSuccess);

EXPORT extern "C" kern_return_t ADDPR(kern_start)(kmod_info_t *, void *)
{
    ADDPR(startSuccess) = false;
    owlyStartupPlan.select(0);
    OwlyStatus::text("OwlyEB1Version", RTLAIRLINK_VERSION);
    OwlyStatus::text("OwlyEB1BootstrapPhase", "module-entry");
    OwlyStatus::flag("OwlyEB1ModuleEntryReached", true);
    const bool optedIn = checkKernelArgument("-owlyeb1");
    OwlyStatus::flag("OwlyEB1OptInPresent", optedIn);
    if (!optedIn) {
        OwlyStatus::text("OwlyEB1BootstrapPhase", "inactive-no-optin");
        return KERN_SUCCESS;
    }
    /* An opted-in 0.1.7 starts with registration only. Full activation now
     * requires the explicit owlyebstage=4 argument; it is never a default. */
    uint32_t requestedStage = 1;
    lilu_get_boot_args("owlyebstage", &requestedStage, sizeof(requestedStage));
    owlyStartupPlan.select(requestedStage);
    OwlyStatus::number("OwlyEB1RequestedStage", requestedStage);
    OwlyStatus::number("OwlyEB1StartupStage", owlyStartupPlan.stage());
    OwlyStatus::flag("OwlyEB1RoutesInstalled", false);
    OwlyStatus::flag("OwlyEB1EventRouteInstalled", false);
    OwlyStatus::flag("OwlyEB1OpenRouteInstalled", false);
    OwlyStatus::flag("OwlyEB1HooksReady", false);
    OwlyStatus::flag("OwlyEB1RuntimeInitAttempted", false);
    OwlyStatus::flag("OwlyEB1RuntimeInitSucceeded", false);
    lilu_get_boot_args("liludelay", &ADDPR(debugPrintDelay), sizeof(ADDPR(debugPrintDelay)));
    const auto access = lilu.requestAccess();
    OwlyStatus::number("OwlyEB1LiluAccessResult", static_cast<uint64_t>(access));
    if (access != LiluAPI::Error::NoError) {
        OwlyStatus::text("OwlyEB1BootstrapPhase", "api-access-refused");
        return KERN_SUCCESS; // no callback, route, client or fabricated readiness
    }
    const auto load = lilu.shouldLoad(ADDPR(config).product, ADDPR(config).version,
        ADDPR(config).runmode, ADDPR(config).disableArg, ADDPR(config).disableArgNum,
        ADDPR(config).debugArg, ADDPR(config).debugArgNum,
        ADDPR(config).betaArg, ADDPR(config).betaArgNum,
        ADDPR(config).minKernel, ADDPR(config).maxKernel, ADDPR(debugEnabled));
    OwlyStatus::number("OwlyEB1ShouldLoadResult", static_cast<uint64_t>(load));
    if (load == LiluAPI::Error::NoError && owlyStartupPlan.registrationAllowed()) {
        /* Refuse unloading once callbacks might reference module code. */
        ADDPR(startSuccess) = true;
        OwlyStatus::text("OwlyEB1BootstrapPhase", "plugin-start");
        ADDPR(config).pluginStart();
    } else if (load == LiluAPI::Error::NoError) {
        OwlyStatus::text("OwlyEB1BootstrapPhase", "invalid-stage-inactive");
    } else {
        OwlyStatus::text("OwlyEB1BootstrapPhase", "load-policy-refused");
    }
    lilu.releaseAccess();
    OwlyStatus::flag("OwlyEB1ApiAccessReleased", true);
    OwlyStatus::flag("OwlyEB1BootstrapAccepted", ADDPR(startSuccess));
    return KERN_SUCCESS;
}

EXPORT extern "C" kern_return_t ADDPR(kern_stop)(kmod_info_t *, void *)
{
    return ADDPR(startSuccess) ? KERN_FAILURE : KERN_SUCCESS;
}
