/* import.h - turn traces from other tools into callscope events.
 *
 * strace works on any Linux program, including statically linked binaries
 * and programs you cannot rebuild:
 *
 *   strace -f -tt -T -e trace=network,read,write,close -o app.strace ./app
 *   callscope import strace app.strace -o app.jsonl
 *
 * -tt (wall-clock) or -ttt (epoch) timestamps and -T (durations) are
 * recommended; -yy fd annotations are understood when present. */
#ifndef CALLSCOPE_IMPORT_H
#define CALLSCOPE_IMPORT_H

#include <stdint.h>
#include <stdio.h>

#include "callscope/eventlog.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cs_strace_opts {
    /* Midnight (UTC, ns since epoch) of the day the trace was taken; used with
     * -tt timestamps that only carry the time of day. 0 = today. */
    int64_t base_day_ns;
    /* pid to use when strace ran without -f (lines have no pid column). */
    int32_t default_pid;
} cs_strace_opts;

typedef struct cs_import_stats {
    size_t lines;
    size_t events;
    size_t skipped; /* lines that were not network-relevant */
    size_t unparsed;
} cs_import_stats;

/* Parse a "YYYY-MM-DD" date into midnight UTC nanoseconds; -1 on error. */
int64_t cs_parse_date(const char *ymd);

int cs_import_strace(cs_eventlog *log, FILE *fp, const cs_strace_opts *opts,
                     cs_import_stats *stats);

/* Parse a single strace line (exposed for tests). Returns the number of
 * events added (0 or 1). State for unfinished calls and fd tracking lives in
 * the importer, so use the same importer for every line of one trace. */
typedef struct cs_strace_importer cs_strace_importer;
cs_strace_importer *cs_strace_importer_new(cs_eventlog *log, const cs_strace_opts *opts);
int cs_strace_importer_line(cs_strace_importer *imp, const char *line);
void cs_strace_importer_free(cs_strace_importer *imp);

#ifdef __cplusplus
}
#endif
#endif
