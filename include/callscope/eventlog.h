/* eventlog.h - an in-memory, time-ordered collection of events. */
#ifndef CALLSCOPE_EVENTLOG_H
#define CALLSCOPE_EVENTLOG_H

#include <stdio.h>

#include "callscope/event.h"
#include "callscope/hashmap.h"
#include "callscope/vec.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cs_eventlog {
    cs_vec events;       /* cs_event, sorted by (ts, line) after cs_eventlog_finish */
    cs_hashmap strings;  /* interned strings; values unused */
    size_t malformed;    /* lines that could not be parsed */
    size_t first_bad_line;
    char source[256];    /* file the events came from */
    int64_t t_min, t_max;
    size_t n_pids, n_tids;
} cs_eventlog;

void cs_eventlog_init(cs_eventlog *log);
void cs_eventlog_free(cs_eventlog *log);

/* Return a stable interned copy of s (NULL stays NULL). */
const char *cs_eventlog_intern(cs_eventlog *log, const char *s);

/* Append a copy of ev, interning all of its strings. */
int cs_eventlog_add(cs_eventlog *log, const cs_event *ev);

/* Parse one JSONL line into the log. Returns 0, or -1 if malformed. */
int cs_eventlog_add_line(cs_eventlog *log, const char *line, size_t len, size_t lineno);

/* Load a whole JSONL stream / file. Returns 0 on success (malformed lines are
 * skipped and counted), -1 if the file cannot be read. */
int cs_eventlog_load_stream(cs_eventlog *log, FILE *fp);
int cs_eventlog_load_file(cs_eventlog *log, const char *path, char *err, size_t errlen);

/* Sort events and compute summary fields. Call after loading. */
void cs_eventlog_finish(cs_eventlog *log);

static inline size_t cs_eventlog_count(const cs_eventlog *log) { return log->events.len; }
static inline const cs_event *cs_eventlog_at(const cs_eventlog *log, size_t i) {
    return (const cs_event *)cs_vec_at(&log->events, i);
}

/* Write every event back out as JSONL. */
int cs_eventlog_write(const cs_eventlog *log, FILE *fp);

#ifdef __cplusplus
}
#endif
#endif
