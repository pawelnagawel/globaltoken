#ifndef ARGON2_HELPER
#define ARGON2_HELPER
#if defined (__SSE2__)
#include "blamka-round-opt.h"
#else
#include "blamka-round-ref.h"
#endif
#endif