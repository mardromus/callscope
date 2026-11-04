#ifndef CALLSCOPE_CLI_H
#define CALLSCOPE_CLI_H

#include "callscope/analyze.h"
#include "callscope/eventlog.h"
#include "callscope/rca.h"

#ifndef CALLSCOPE_VERSION
#define CALLSCOPE_VERSION "dev"
#endif

typedef struct cli_common {
    const char *input;
    int json;
    int color;
    int ai;      /* 1 = use the LLM agent when configured */
    int verbose;
    cs_analyze_opts opts;
} cli_common;

/* Parse options shared by analyze/rca/report. Returns the index of the first
 * unrecognised argument, or -1 on error. */
int cli_parse_common(int argc, char **argv, int start, cli_common *c, const char *cmd);
int cli_load(const char *path, cs_eventlog *log);
/* Run the configured RCA engine (AI with fallback, or rules). */
void cli_rca(const cs_analysis *a, const cli_common *c, cs_rca_result *r);
int cli_write_file(const char *path, const char *data, size_t len);
void cli_die(const char *fmt, ...) __attribute__((format(printf, 1, 2), noreturn));

int cmd_analyze(int argc, char **argv);
int cmd_rca(int argc, char **argv);
int cmd_report(int argc, char **argv);
int cmd_record(int argc, char **argv);
int cmd_gen(int argc, char **argv);
int cmd_import(int argc, char **argv);

#endif
