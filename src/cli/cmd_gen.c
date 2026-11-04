/* gen and import commands. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "callscope/gen.h"
#include "callscope/import.h"
#include "cli.h"

static int write_log(const cs_eventlog *log, const char *out) {
    FILE *fp = (!out || !strcmp(out, "-")) ? stdout : fopen(out, "w");
    if (!fp) {
        perror(out);
        return -1;
    }
    int rc = cs_eventlog_write(log, fp);
    if (fp != stdout) fclose(fp);
    return rc;
}

int cmd_gen(int argc, char **argv) {
    cs_gen_opts o = {NULL, 0, 0, 0, 0};
    const char *out = NULL;
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--list")) {
            printf("%-17s %-26s %s\n", "SCENARIO", "EXPECTED ROOT CAUSE", "DESCRIPTION");
            for (const cs_gen_scenario_info *s = cs_gen_scenarios(); s->name; s++)
                printf("%-17s %-26s %s\n", s->name, s->expected_root ? s->expected_root : "-",
                       s->summary);
            return 0;
        }
        if (!strcmp(a, "-o") && i + 1 < argc) out = argv[++i];
        else if (!strcmp(a, "--requests") && i + 1 < argc) o.requests = atoi(argv[++i]);
        else if (!strcmp(a, "--seed") && i + 1 < argc) o.seed = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--threads") && i + 1 < argc) o.threads = atoi(argv[++i]);
        else if (a[0] == '-') cli_die("gen: unknown option %s", a);
        else o.scenario = a;
    }
    if (!o.scenario) cli_die("gen: missing scenario (try: callscope gen --list)");
    cs_eventlog log;
    cs_eventlog_init(&log);
    char err[200];
    if (cs_gen_run(&log, &o, err, sizeof err) != 0) cli_die("gen: %s", err);
    if (write_log(&log, out) != 0) return 2;
    if (out && strcmp(out, "-"))
        fprintf(stderr, "callscope: wrote %zu events (%s) to %s\n", cs_eventlog_count(&log),
                o.scenario, out);
    cs_eventlog_free(&log);
    return 0;
}

int cmd_import(int argc, char **argv) {
    if (argc < 4 || strcmp(argv[2], "strace") != 0)
        cli_die("usage: callscope import strace <file> [-o out.jsonl] [--date YYYY-MM-DD] [--pid N]");
    const char *in = argv[3], *out = NULL;
    cs_strace_opts so = {0, 0};
    for (int i = 4; i < argc; i++) {
        if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[++i];
        else if (!strcmp(argv[i], "--date") && i + 1 < argc) {
            so.base_day_ns = cs_parse_date(argv[++i]);
            if (so.base_day_ns < 0) cli_die("import: bad --date (expected YYYY-MM-DD)");
        } else if (!strcmp(argv[i], "--pid") && i + 1 < argc) so.default_pid = atoi(argv[++i]);
        else cli_die("import: unknown option %s", argv[i]);
    }
    FILE *fp = strcmp(in, "-") ? fopen(in, "r") : stdin;
    if (!fp) {
        perror(in);
        return 2;
    }
    cs_eventlog log;
    cs_eventlog_init(&log);
    cs_import_stats st;
    cs_import_strace(&log, fp, &so, &st);
    if (fp != stdin) fclose(fp);
    snprintf(log.source, sizeof log.source, "strace:%s", in);
    if (write_log(&log, out) != 0) return 2;
    fprintf(stderr, "callscope: %zu strace lines -> %zu network events%s%s\n", st.lines, st.events,
            out ? " in " : "", out ? out : "");
    cs_eventlog_free(&log);
    return 0;
}
