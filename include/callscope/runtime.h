/* runtime.h - API for applications that link libcallscope_trace.
 *
 * Build your program with   -finstrument-functions -rdynamic
 * and link with             -lcallscope_trace
 * Every function entry/exit is then recorded automatically. These calls add
 * application-level context (errors, log lines) to the same trace.
 *
 * Environment:
 *   CALLSCOPE_LOG=path       trace file (default: callscope.jsonl, appended)
 *   CALLSCOPE_DISABLE=1      turn tracing off without rebuilding
 *   CALLSCOPE_MAX_DEPTH=n    stop recording calls deeper than n (default 4096) */
#ifndef CALLSCOPE_RUNTIME_H
#define CALLSCOPE_RUNTIME_H

#ifdef __cplusplus
extern "C" {
#endif

#define CS_NOINSTR __attribute__((no_instrument_function))

/* Record an application error, e.g. cs_error("PAYMENT_DECLINED", "order %d", id). */
void cs_error(const char *code, const char *fmt, ...) CS_NOINSTR
    __attribute__((format(printf, 2, 3)));

/* Record a log line at a level such as "info", "warn", "debug". */
void cs_log(const char *level, const char *fmt, ...) CS_NOINSTR
    __attribute__((format(printf, 2, 3)));

/* Is tracing active for this process? */
int cs_trace_enabled(void) CS_NOINSTR;

#ifdef __cplusplus
}
#endif
#endif
