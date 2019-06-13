#ifndef ARGON2_HELPER
#define ARGON2_HELPER
#if defined (__arm__)
#include "blamka-round-ref.h"
#else
#include "blamka-round-opt.h"
#endif
#endif