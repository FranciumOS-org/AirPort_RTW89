#ifndef OWLY_TEST_IOUSERCLIENT_H
#define OWLY_TEST_IOUSERCLIENT_H
#include <cassert>
#include <cstring>
using task_t = void *;
class OSObject {
public:
    unsigned refs = 1, releases = 0;
    virtual ~OSObject() = default;
    void retain() { ++refs; }
    void release() { assert(refs > 1); --refs; ++releases; }
};
class OSDictionary;
class IOUserClient {
public:
    static OSObject *single;
    static OSDictionary *dictionary;
    static unsigned singleCalls, dictionaryCalls;
    static task_t singleTask, dictionaryTask;
    static OSObject *copyClientEntitlement(task_t task, const char *key);
    static OSDictionary *copyClientEntitlements(task_t task);
};
#endif
