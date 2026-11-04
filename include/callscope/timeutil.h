/* timeutil.h - clocks and human-friendly time formatting. */
#ifndef CALLSCOPE_TIMEUTIL_H
#define CALLSCOPE_TIMEUTIL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CS_NS_PER_US 1000LL
#define CS_NS_PER_MS 1000000LL
#define CS_NS_PER_S  1000000000LL

/* Wall-clock nanoseconds since the Unix epoch (CLOCK_REALTIME).
 * Used for every event so traces from different processes line up. */
int64_t cs_now_ns(void);
/* Monotonic nanoseconds, for measuring durations. */
int64_t cs_mono_ns(void);

/* "2026-11-04T14:32:05.123456Z" (UTC, microsecond precision). */
const char *cs_fmt_ts(int64_t ns, char *buf, size_t n);
/* "14:32:05.123" (UTC time of day, millisecond precision). */
const char *cs_fmt_clock(int64_t ns, char *buf, size_t n);
/* "850 ns", "12.4 us", "3.21 ms", "1.80 s". */
const char *cs_fmt_dur(int64_t ns, char *buf, size_t n);
/* "512 B", "4.0 KiB", "1.2 MiB". */
const char *cs_fmt_bytes(int64_t bytes, char *buf, size_t n);

#ifdef __cplusplus
}
#endif
#endif
