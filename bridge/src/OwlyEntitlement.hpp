/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OWLY_ENTITLEMENT_HPP
#define OWLY_ENTITLEMENT_HPP
#include <IOKit/IOUserClient.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSDictionary.h>

/* The task and entitlement do not change between the two public IOKit lookups.
 * An explicit false or a non-boolean result is terminal. Only a missing result
 * permits a dictionary lookup; a borrowed dictionary entry is never released.
 * This is an unqualified compatibility candidate, not an AMFI policy bypass. */
namespace OwlyEntitlement {
constexpr const char *key = "com.apple.wifi_awdl.event_monitor";
enum class Value { Missing, True, False, Other };
enum class Source { None, Single, Dictionary };
struct Result {
    Value single = Value::Missing;
    Value dictionary = Value::Missing;
    Source source = Source::None;
    bool dictionaryAvailable = false;
    bool allowed = false;
};

inline Value classify(OSObject *value)
{
    if (!value) return Value::Missing;
    if (value == kOSBooleanTrue) return Value::True;
    if (value == kOSBooleanFalse) return Value::False;
    return Value::Other;
}

inline const char *valueName(Value value)
{
    switch (value) {
        case Value::True: return "true";
        case Value::False: return "false";
        case Value::Other: return "non-boolean";
        default: return "missing";
    }
}

inline const char *sourceName(Source source)
{
    switch (source) {
        case Source::Single: return "single";
        case Source::Dictionary: return "dictionary-after-missing-single";
        default: return "none";
    }
}

inline bool authorize(task_t task, Result &result)
{
    result = Result {};
    if (!task) return false;
    OSObject *value = IOUserClient::copyClientEntitlement(task, key);
    result.single = classify(value);
    if (value) value->release();
    if (result.single != Value::Missing) {
        result.source = Source::Single;
        result.allowed = result.single == Value::True;
        return result.allowed;
    }

    result.source = Source::Dictionary;
    OSDictionary *dictionary = IOUserClient::copyClientEntitlements(task);
    result.dictionaryAvailable = dictionary != nullptr;
    if (dictionary) {
        result.dictionary = classify(dictionary->getObject(key));
        dictionary->release();
    }
    result.allowed = result.dictionary == Value::True;
    return result.allowed;
}
}
#endif
