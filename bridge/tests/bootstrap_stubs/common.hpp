#pragma once
#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#define EXPORT
#define ADDPR(x) OwlyAirLinkBridge_##x
#define OSDeclareDefaultStructors(X)
#define OSDefineMetaClassAndStructors(X,Y)
#define OSDynamicCast(X,p) dynamic_cast<X *>(p)
using kern_return_t = int;
using IOReturn = int;
struct kmod_info_t {};
constexpr int KERN_SUCCESS=0, KERN_FAILURE=5, kIOReturnSuccess=0, kIOReturnError=1;
enum class KernelVersion { Target=25 };
struct PluginConfiguration {
 const char *product; size_t version; uint32_t runmode;
 const char **disableArg; size_t disableArgNum;
 const char **debugArg; size_t debugArgNum;
 const char **betaArg; size_t betaArgNum;
 KernelVersion minKernel,maxKernel; void (*pluginStart)();
};
extern bool ADDPR(debugEnabled); extern uint32_t ADDPR(debugPrintDelay);
extern bool fakeOptIn,fakeResource,apiHeld,moduleReturned;
extern bool fakeParent,fakeLoop,fakeTimer,fakeAdd,fakeArm,fakeRuntime;
extern int requested,loaded,released,started,registryCalls,resourceCalls;
extern int loopsMade,timersMade,liveLoops,liveTimers,runtimeCalls,deactivateCalls;
extern int addCalls,removeCalls,cancelCalls,registerCalls;
inline void ioContext() { assert(moduleReturned && !apiHeld); }
bool checkKernelArgument(const char *);
void lilu_get_boot_args(const char *,uint32_t *,size_t);
class LiluAPI {
public:
 enum class Error {NoError,LockError,MemoryError,UnsupportedFeature,IncompatibleOS,Disabled,TooLate,Offline};
 Error nextAccess=Error::NoError,nextLoad=Error::NoError;
 Error requestAccess() { requested++; if(nextAccess==Error::NoError)apiHeld=true; return nextAccess; }
 Error shouldLoad(const char *,size_t,uint32_t,const char **,size_t,const char **,size_t,
                  const char **,size_t,KernelVersion,KernelVersion,bool &) {
  assert(apiHeld); loaded++; return nextLoad;
 }
 void releaseAccess() { assert(apiHeld); released++; apiHeld=false; }
};
extern LiluAPI lilu;
class OSObject {
public:
 virtual ~OSObject() = default;
 void retain() { references++; }
 void release() { assert(references>0); if(--references==0)delete this; }
private: unsigned references=1;
};
class IORegistryEntry : public OSObject {
public:
 std::map<std::string,std::string> strings;
 std::map<std::string,uint64_t> numbers;
 std::map<std::string,bool> flags;
 bool setProperty(const char *k,const char *v) { ioContext();registryCalls++;strings[k]=v;return true; }
 bool setProperty(const char *k,uint64_t v,unsigned) { ioContext();registryCalls++;numbers[k]=v;return true; }
 bool setProperty(const char *k,bool v) { ioContext();registryCalls++;flags[k]=v;return true; }
 void clear() { strings.clear();numbers.clear();flags.clear(); }
};
class IOService : public IORegistryEntry {
public:
 static IOService *getResourceService();
 virtual bool start(IOService *) { ioContext();return fakeParent; }
 virtual void stop(IOService *) { ioContext(); }
 virtual void free() { ioContext(); }
 void registerService() { ioContext();registerCalls++; }
};
class IOTimerEventSource;
extern IOTimerEventSource *lastTimer;
class IOTimerEventSource : public OSObject {
public:
 using Action=void (*)(OSObject *,IOTimerEventSource *);
 static IOTimerEventSource *timerEventSource(OSObject *owner,Action action) {
  ioContext();timersMade++;if(!fakeTimer)return nullptr;
  auto *s=new IOTimerEventSource;s->_owner=owner;s->_action=action;
  liveTimers++;lastTimer=s;return s;
 }
 IOReturn setTimeoutMS(unsigned ms) { ioContext();assert(ms==1000);armed=fakeArm;return fakeArm?0:1; }
 void cancelTimeout() { ioContext();armed=false;cancelCalls++; }
 void fire() { assert(armed);armed=false;_action(_owner,this); }
 ~IOTimerEventSource() override { if(lastTimer==this)lastTimer=nullptr;liveTimers--; }
 bool armed=false;
private: OSObject *_owner=nullptr;Action _action=nullptr;
};
class IOWorkLoop : public OSObject {
public:
 static IOWorkLoop *workLoop() {
  ioContext();loopsMade++;if(!fakeLoop)return nullptr;
  liveLoops++;return new IOWorkLoop;
 }
 IOReturn addEventSource(IOTimerEventSource *t) {
  ioContext();addCalls++;if(!fakeAdd)return 1;
  assert(_source==nullptr);_source=t;t->retain();return 0;
 }
 IOReturn removeEventSource(IOTimerEventSource *t) {
  ioContext();removeCalls++;assert(_source==t);_source=nullptr;t->release();return 0;
 }
 ~IOWorkLoop() override { assert(_source==nullptr);liveLoops--; }
private: IOTimerEventSource *_source=nullptr;
};
