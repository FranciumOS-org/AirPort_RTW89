/* Exercise the real production lookup/ownership code with controlled IOKit
 * results. This cannot establish what the live AMFI APIs return on the LOQ. */
#include "OwlyEntitlement.hpp"
#include <iostream>

static OSBoolean yes, no;
OSBoolean * const kOSBooleanTrue = &yes;
OSBoolean * const kOSBooleanFalse = &no;
OSObject *IOUserClient::single = nullptr;
OSDictionary *IOUserClient::dictionary = nullptr;
unsigned IOUserClient::singleCalls = 0, IOUserClient::dictionaryCalls = 0;
task_t IOUserClient::singleTask = nullptr, IOUserClient::dictionaryTask = nullptr;

OSObject *IOUserClient::copyClientEntitlement(task_t task, const char *key)
{
    assert(std::strcmp(key, "com.apple.wifi_awdl.event_monitor") == 0);
    ++singleCalls; singleTask = task;
    if (single) single->retain();
    return single;
}
OSDictionary *IOUserClient::copyClientEntitlements(task_t task)
{
    ++dictionaryCalls; dictionaryTask = task;
    if (dictionary) dictionary->retain();
    return dictionary;
}

static void reset(OSObject *single, OSDictionary *dictionary)
{
    IOUserClient::single = single; IOUserClient::dictionary = dictionary;
    IOUserClient::singleCalls = IOUserClient::dictionaryCalls = 0;
    IOUserClient::singleTask = IOUserClient::dictionaryTask = nullptr;
}

int main()
{
    using namespace OwlyEntitlement;
    int taskStorage = 0;
    task_t task = &taskStorage;
    OSDictionary dictionary;
    OSObject nonBoolean;
    Result result;

    reset(&yes, &dictionary);
    assert(authorize(task, result) && result.single == Value::True);
    assert(result.source == Source::Single && IOUserClient::dictionaryCalls == 0);
    assert(yes.refs == 1 && yes.releases == 1);
    std::cout << "PASS true single lookup authorizes without a dictionary query\n";

    dictionary.entry = &yes;
    for (OSObject *denied : {static_cast<OSObject *>(&no), &nonBoolean}) {
        reset(denied, &dictionary);
        assert(!authorize(task, result));
        assert(result.source == Source::Single && IOUserClient::dictionaryCalls == 0);
        assert(denied->refs == 1 && denied->releases == 1);
    }
    std::cout << "PASS explicit false or non-boolean cannot be overridden by dictionary true\n";

    const auto borrowedReleases = yes.releases;
    reset(nullptr, &dictionary);
    assert(authorize(task, result) && result.source == Source::Dictionary);
    assert(result.single == Value::Missing && result.dictionary == Value::True);
    assert(IOUserClient::singleTask == task && IOUserClient::dictionaryTask == task);
    assert(IOUserClient::singleCalls == 1 && IOUserClient::dictionaryCalls == 1);
    assert(dictionary.refs == 1 && dictionary.releases == 1);
    assert(yes.refs == 1 && yes.releases == borrowedReleases);
    std::cout << "PASS missing single uses same-task exact-key dictionary true with balanced ownership\n";

    for (OSObject *denied : {static_cast<OSObject *>(nullptr), static_cast<OSObject *>(&no), &nonBoolean}) {
        dictionary.entry = denied;
        reset(nullptr, &dictionary);
        assert(!authorize(task, result) && result.source == Source::Dictionary);
        assert(result.dictionaryAvailable && result.dictionary != Value::True);
        assert(dictionary.refs == 1);
    }
    assert(no.releases == 1 && nonBoolean.releases == 1);
    std::cout << "PASS missing false and non-boolean borrowed dictionary values all deny\n";

    reset(nullptr, nullptr);
    assert(!authorize(task, result) && !result.dictionaryAvailable);
    assert(result.single == Value::Missing && result.dictionary == Value::Missing);
    std::cout << "PASS both APIs unavailable denies without fabricated entitlement\n";

    reset(&yes, &dictionary);
    result.allowed = true; result.dictionaryAvailable = true;
    assert(!authorize(nullptr, result) && !result.allowed && !result.dictionaryAvailable);
    assert(result.source == Source::None && !IOUserClient::singleCalls && !IOUserClient::dictionaryCalls);
    std::cout << "PASS invalid task resets prior result and invokes no API\n";
    std::cout << "RESULT 6 production entitlement regression groups passed; runtime behavior unproven\n";
}
