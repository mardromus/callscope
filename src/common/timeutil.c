#include "callscope/timeutil.h"

#include <stdio.h>
#include <time.h>

int64_t cs_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * CS_NS_PER_S + ts.tv_nsec;
}

int64_t cs_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * CS_NS_PER_S + ts.tv_nsec;
}

const char *cs_fmt_ts(int64_t ns, char *buf, size_t n) {
    time_t secs = (time_t)(ns / CS_NS_PER_S);
    long micros = (long)((ns % CS_NS_PER_S) / CS_NS_PER_US);
    struct tm tm;
    gmtime_r(&secs, &tm);
    snprintf(buf, n, "%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ", tm.tm_year + 1900, tm.tm_mon + 1,
             tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, micros);
    return buf;
}

const char *cs_fmt_clock(int64_t ns, char *buf, size_t n) {
    time_t secs = (time_t)(ns / CS_NS_PER_S);
    long millis = (long)((ns % CS_NS_PER_S) / CS_NS_PER_MS);
    struct tm tm;
    gmtime_r(&secs, &tm);
    snprintf(buf, n, "%02d:%02d:%02d.%03ld", tm.tm_hour, tm.tm_min, tm.tm_sec, millis);
    return buf;
}

const char *cs_fmt_dur(int64_t ns, char *buf, size_t n) {
    if (ns < 0) {
        snprintf(buf, n, "n/a");
    } else if (ns < CS_NS_PER_US) {
        snprintf(buf, n, "%lld ns", (long long)ns);
    } else if (ns < CS_NS_PER_MS) {
        snprintf(buf, n, "%.1f us", (double)ns / CS_NS_PER_US);
    } else if (ns < CS_NS_PER_S) {
        snprintf(buf, n, "%.2f ms", (double)ns / CS_NS_PER_MS);
    } else {
        snprintf(buf, n, "%.2f s", (double)ns / CS_NS_PER_S);
    }
    return buf;
}

const char *cs_fmt_bytes(int64_t bytes, char *buf, size_t n) {
    if (bytes < 1024) {
        snprintf(buf, n, "%lld B", (long long)bytes);
    } else if (bytes < 1024LL * 1024) {
        snprintf(buf, n, "%.1f KiB", (double)bytes / 1024.0);
    } else if (bytes < 1024LL * 1024 * 1024) {
        snprintf(buf, n, "%.1f MiB", (double)bytes / (1024.0 * 1024.0));
    } else {
        snprintf(buf, n, "%.2f GiB", (double)bytes / (1024.0 * 1024.0 * 1024.0));
    }
    return buf;
}
