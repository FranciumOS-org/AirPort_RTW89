#ifndef OWLY_TEST_OSBOOLEAN_H
#define OWLY_TEST_OSBOOLEAN_H
#include <IOKit/IOUserClient.h>
class OSBoolean : public OSObject {};
extern OSBoolean * const kOSBooleanTrue;
extern OSBoolean * const kOSBooleanFalse;
#endif
