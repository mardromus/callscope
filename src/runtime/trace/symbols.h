#ifndef CALLSCOPE_SYMBOLS_H
#define CALLSCOPE_SYMBOLS_H

#include "callscope/runtime.h"

/* Name for a function address; the returned pointer is thread-local and stays
 * valid until the same cache slot is reused. */
const char *cs_sym_name(void *addr) CS_NOINSTR;

#endif
