#if defined (__SSE2__)
#include "opt.c"
#else
#include "ref.c"
#endif