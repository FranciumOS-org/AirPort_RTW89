#ifndef OWLY_TEST_OSDICTIONARY_H
#define OWLY_TEST_OSDICTIONARY_H
#include <IOKit/IOUserClient.h>
class OSDictionary : public OSObject {
public:
    OSObject *entry = nullptr;
    unsigned lookups = 0;
    OSObject *getObject(const char *key) {
        assert(std::strcmp(key, "com.apple.wifi_awdl.event_monitor") == 0);
        ++lookups;
        return entry; // Borrowed; callers must not release it.
    }
};
#endif
