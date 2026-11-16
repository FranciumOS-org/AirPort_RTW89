/* Real bootstrap/journal/service sources, mocked kernel APIs. ioContext rejects
 * every registry/loop side effect before module return or under the API lock. */
#include "common.hpp"
#include "OwlyReadiness.hpp"
#include "OwlyStatus.hpp"
#include "OwlyRuntime.hpp"
#include <algorithm>
#include <iostream>
#include <thread>
#include "../src/Service.cpp"

uint32_t fakeStage=4;
bool fakeStagePresent=true;
bool fakeOptIn=true,fakeResource=true,apiHeld=false,moduleReturned=false;
bool fakeParent=true,fakeLoop=true,fakeTimer=true,fakeAdd=true,fakeArm=true,fakeRuntime=true;
int requested=0,loaded=0,released=0,started=0,registryCalls=0,resourceCalls=0;
int loopsMade=0,timersMade=0,liveLoops=0,liveTimers=0,runtimeCalls=0,deactivateCalls=0;
int addCalls=0,removeCalls=0,cancelCalls=0,registerCalls=0;
bool OwlyAirLinkBridge_startSuccess=false,OwlyAirLinkBridge_debugEnabled=false;
uint32_t OwlyAirLinkBridge_debugPrintDelay=0;
LiluAPI lilu;IOService root;IOTimerEventSource *lastTimer=nullptr;
IOWorkLoop *retainedRuntimeLoop=nullptr;
bool checkKernelArgument(const char *) { return fakeOptIn; }
void lilu_get_boot_args(const char *key,uint32_t *value,size_t) { if(fakeStagePresent&&std::strcmp(key,"owlyebstage")==0)*value=fakeStage; }
IOService *IOService::getResourceService() { ioContext();resourceCalls++;return fakeResource?&root:nullptr; }
static void startPluginModel() { assert(apiHeld && !moduleReturned);started++; }
PluginConfiguration OwlyAirLinkBridge_config {"OwlyAirLinkBridge",12,1,nullptr,0,nullptr,0,nullptr,0,KernelVersion::Target,KernelVersion::Target,startPluginModel};
extern "C" int OwlyAirLinkBridge_kern_start(kmod_info_t *,void *);
extern "C" int OwlyAirLinkBridge_kern_stop(kmod_info_t *,void *);
bool OwlyRuntime::initialize(IOWorkLoop *loop) {
 ioContext();runtimeCalls++;assert(loop);
 if(!fakeRuntime)return false;
 assert(!retainedRuntimeLoop);loop->retain();retainedRuntimeLoop=loop;return true;
}
void OwlyRuntime::deactivate() { ioContext();deactivateCalls++; }
static void reset() {
 if(retainedRuntimeLoop){retainedRuntimeLoop->release();retainedRuntimeLoop=nullptr;}
 assert(liveLoops==0&&liveTimers==0);
 fakeStage=4;fakeStagePresent=true;
 fakeOptIn=fakeResource=fakeParent=fakeLoop=fakeTimer=fakeAdd=fakeArm=fakeRuntime=true;
 apiHeld=moduleReturned=false;
 requested=loaded=released=started=registryCalls=resourceCalls=0;
 loopsMade=timersMade=runtimeCalls=deactivateCalls=0;
 addCalls=removeCalls=cancelCalls=registerCalls=0;
 OwlyAirLinkBridge_startSuccess=false;lilu=LiluAPI{};root.clear();
}
static void enter() {
 assert(OwlyAirLinkBridge_kern_start(nullptr,nullptr)==KERN_SUCCESS);
 assert(!apiHeld);
 assert(!registryCalls&&!resourceCalls&&!loopsMade&&!timersMade&&!runtimeCalls);
 moduleReturned=true;
}
static void cleanup(OwlyAirLinkBridge &s) { s.stop(&root);s.free(); }
int main() {
 reset();enter();assert(requested==1&&loaded==1&&released==1&&started==1);
 assert(OwlyAirLinkBridge_kern_stop(nullptr,nullptr)==KERN_FAILURE);
 {OwlyAirLinkBridge s;assert(s.start(&root));assert(loopsMade==1&&runtimeCalls==1);
  assert(root.strings["OwlyEB1Version"]=="0.1.0");assert(root.flags["OwlyEB1ApiAccessReleased"]);
  assert(root.flags["OwlyEB1RuntimeInitSucceeded"]);assert(lastTimer&&lastTimer->armed);
  assert(!s.start(&root));assert(loopsMade==1);
  OwlyStatus::flag("OwlyEB1HooksReady",true);lastTimer->fire();assert(root.flags["OwlyEB1HooksReady"]);
  cleanup(s);assert(deactivateCalls==1&&liveTimers==0);}
 std::cout<<"PASS deferred resources, periodic journal, single start and unload refusal\n";
 reset();fakeOptIn=false;enter();assert(!requested&&!started&&!OwlyAirLinkBridge_startSuccess);
 {OwlyAirLinkBridge s;assert(s.start(&root));assert(!loopsMade&&!runtimeCalls);assert(root.strings["OwlyEB1BootstrapPhase"]=="inactive-no-optin");cleanup(s);}
 assert(OwlyAirLinkBridge_kern_stop(nullptr,nullptr)==KERN_SUCCESS);
 std::cout<<"PASS no opt-in: no API or runtime allocation\n";
 reset();lilu.nextAccess=LiluAPI::Error::TooLate;enter();assert(requested==1&&!loaded&&!released&&!started);
 {OwlyAirLinkBridge s;assert(s.start(&root));assert(root.numbers["OwlyEB1LiluAccessResult"]==6);assert(!loopsMade);cleanup(s);}
 std::cout<<"PASS access refusal recorded, no retry, no unowned unlock\n";
 for(auto policy:{LiluAPI::Error::Disabled,LiluAPI::Error::IncompatibleOS}){
  reset();lilu.nextLoad=policy;enter();assert(requested==1&&loaded==1&&released==1&&!started);
  {OwlyAirLinkBridge s;assert(s.start(&root));assert(!runtimeCalls&&!loopsMade);cleanup(s);}
 }
 std::cout<<"PASS disabled and incompatible policy never allocate runtime\n";
 reset();enter();fakeParent=false;
 {OwlyAirLinkBridge s;assert(!s.start(&root));assert(!loopsMade&&!runtimeCalls);s.free();}
 std::cout<<"PASS parent start failure has no runtime side effects\n";
 reset();enter();fakeLoop=false;
 {OwlyAirLinkBridge s;assert(!s.start(&root));assert(!runtimeCalls&&liveLoops==0);assert(!root.flags["OwlyEB1WorkLoopAllocated"]);s.free();}
 std::cout<<"PASS workloop allocation failure stays inactive\n";
 for(bool addFailure:{false,true}){
  reset();enter();if(addFailure)fakeAdd=false;else fakeTimer=false;
  {OwlyAirLinkBridge s;assert(!s.start(&root));assert(!runtimeCalls&&!liveLoops&&!liveTimers);s.free();}
 }
 std::cout<<"PASS timer creation and add failure release partial resources\n";
 reset();enter();fakeRuntime=false;
 {OwlyAirLinkBridge s;assert(!s.start(&root));assert(runtimeCalls==1&&!liveLoops&&!liveTimers);assert(removeCalls==1&&cancelCalls==1);s.free();}
 std::cout<<"PASS runtime failure removes timer and releases service loop\n";
 reset();enter();fakeArm=false;
 {OwlyAirLinkBridge s;assert(!s.start(&root));assert(deactivateCalls==1&&!liveTimers);assert(!root.flags["OwlyEB1StatusTimerAvailable"]);s.free();}
 std::cout<<"PASS initial timer arm failure deactivates runtime\n";
 reset();enter();
 {OwlyAirLinkBridge s;assert(s.start(&root));fakeArm=false;lastTimer->fire();assert(deactivateCalls==1&&!lastTimer->armed);assert(!root.flags["OwlyEB1StatusTimerAvailable"]);cleanup(s);}
 std::cout<<"PASS timer re-arm failure cannot leave active unobserved runtime\n";
 reset();enter();fakeResource=false;
 {OwlyAirLinkBridge s;assert(s.start(&root));assert(s.strings["OwlyEB1Version"]=="0.1.0");cleanup(s);}
 std::cout<<"PASS unavailable IOResources still publishes on service\n";
 reset();moduleReturned=true;root.clear();
 OwlyStatus::number("unknown",99);OwlyStatus::flag(nullptr,true);OwlyStatus::text("OwlyEB1Version",nullptr);
 OwlyStatus::number("OwlyEB1HooksReady",99);OwlyStatus::number("OwlyEB1LastOpenType",123);
 OwlyStatus::flush(nullptr);OwlyStatus::flush(&root);
 assert(!root.numbers.count("unknown")&&!root.numbers.count("OwlyEB1HooksReady"));assert(root.numbers["OwlyEB1LastOpenType"]==123);
 std::thread writer([]{for(unsigned i=0;i<10000;i++)OwlyStatus::number("OwlyEB1LastOpenType",i);});
 for(unsigned i=0;i<100;i++)OwlyStatus::flush(&root);
 writer.join();OwlyStatus::flush(&root);assert(root.numbers["OwlyEB1LastOpenType"]==9999);
 std::cout<<"PASS bounded typed journal, null target and concurrent record/snapshot\n";
 int order[3]={0,1,2};unsigned permutations=0;
 do{
  for(unsigned stopAt=0;stopAt<=4;stopAt++){
   OwlyReadiness q;assert(!q.ready());
   for(unsigned i=0;i<3;i++){
    if(i==stopAt)q.stop();
    if(order[i]==0)q.routes();else if(order[i]==1)q.frontend(true);else q.runtime();
    assert(q.ready()==(i==2&&stopAt>2));
   }
   q.stop();q.frontend(false);q.frontend(true);q.routes();q.runtime();assert(!q.ready());
  }
  permutations++;
 }while(std::next_permutation(order,order+3));assert(permutations==6);
 {OwlyReadiness q;q.routes();q.frontend(true);assert(!q.ready());q.runtime();assert(q.ready());q.frontend(false);assert(!q.ready());}
 for(unsigned i=0;i<100;i++){
  OwlyReadiness q;std::thread a([&]{q.routes();});std::thread b([&]{q.frontend(true);});std::thread c([&]{q.runtime();q.stop();});
  a.join();b.join();c.join();assert(!q.ready());
 }
 std::cout<<"PASS all readiness orders, revocation and terminal stop under races\n";
 reset();fakeStage=1;enter();assert(started==1&&requested==1&&loaded==1&&released==1);
 {OwlyAirLinkBridge s;assert(s.start(&root));assert(!loopsMade&&!timersMade&&!runtimeCalls);assert(root.numbers["OwlyEB1StartupStage"]==1);assert(!root.flags["OwlyEB1RuntimeRequested"]);assert(!root.flags["OwlyEB1HooksReady"]);cleanup(s);}
 assert(owlyStartupPlan.registrationAllowed()&&!owlyStartupPlan.runtimeAllowed()&&!owlyStartupPlan.eventRouteAllowed()&&!owlyStartupPlan.openRouteAllowed());
 std::cout<<"PASS stage1 real bootstrap/service registers without runtime allocation\n";
 reset();fakeStage=2;enter();
 {OwlyAirLinkBridge s;assert(s.start(&root));assert(loopsMade==1&&runtimeCalls==1);assert(root.flags["OwlyEB1RuntimeRequested"]);assert(!owlyStartupPlan.eventRouteAllowed()&&!owlyStartupPlan.openRouteAllowed());cleanup(s);}
 std::cout<<"PASS stage2 runtime boundary stays separate from route permissions\n";
 reset();fakeStage=3;enter();assert(owlyStartupPlan.runtimeAllowed()&&owlyStartupPlan.eventRouteAllowed()&&!owlyStartupPlan.openRouteAllowed());
 {OwlyAirLinkBridge s;assert(s.start(&root));cleanup(s);}
 std::cout<<"PASS stage3 permits event route but excludes modern open route\n";
 for(uint32_t bad:{0U,5U,0xffffffffU}){
  reset();fakeStage=bad;enter();assert(requested==1&&loaded==1&&released==1&&!started);assert(!OwlyAirLinkBridge_startSuccess);assert(!owlyStartupPlan.registrationAllowed());
  {OwlyAirLinkBridge s;assert(s.start(&root));assert(!loopsMade&&!runtimeCalls);assert(root.strings["OwlyEB1BootstrapPhase"]=="invalid-stage-inactive");cleanup(s);}
 }
 std::cout<<"PASS invalid stages cannot reach callbacks or allocate runtime\n";
 reset();fakeStage=1;lilu.nextLoad=LiluAPI::Error::Disabled;enter();assert(!started&&!OwlyAirLinkBridge_startSuccess);
 {OwlyAirLinkBridge s;assert(s.start(&root));assert(!loopsMade&&!runtimeCalls);assert(root.numbers["OwlyEB1ShouldLoadResult"]==5);assert(root.flags["OwlyEB1ApiAccessReleased"]);cleanup(s);}
 std::cout<<"PASS policy off remains observable with stage1 and cannot start plugin\n";
 reset();fakeStagePresent=false;enter();assert(owlyStartupPlan.stage()==1&&started==1);
 {OwlyAirLinkBridge s;assert(s.start(&root));assert(!loopsMade&&!timersMade&&!runtimeCalls);assert(!root.flags["OwlyEB1RuntimeRequested"]);cleanup(s);}
 std::cout<<"PASS missing stage argument defaults to registration only, never full activation\n";
 reset();std::cout<<"RESULT 19 lifecycle/readiness groups passed; mocked kernel APIs, no native boot proof\n";
}
