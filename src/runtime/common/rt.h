/* rt.h - internals shared by the function tracer and the network shim. */
#ifndef CALLSCOPE_RT_H
#define CALLSCOPE_RT_H

#include "callscope/event.h"
#include "callscope/runtime.h"

#define CS_RT_LINE_MAX 8192

/* Fill ts/pid/tid when unset, encode, and append one line to the trace. */
void cs_rt_emit(cs_event *ev) CS_NOINSTR;
/* Kernel thread id of the calling thread (cached per thread). */
int cs_rt_tid(void) CS_NOINSTR;
int cs_rt_pid(void) CS_NOINSTR;
/* Emit proc_start once per process (safe to call from several components). */
void cs_rt_proc_start(const char *component) CS_NOINSTR;
/* 1 when CALLSCOPE_DISABLE is not set. */
int cs_rt_enabled(void) CS_NOINSTR;

#endif
