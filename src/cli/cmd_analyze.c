/* analyze / rca / report commands. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "callscope/report.h"
#include "callscope/timeutil.h"
#include "cli.h"

int cli_parse_common(int argc, char **argv, int start, cli_common *c, const char *cmd) {
    memset(c, 0, sizeof *c);
    cs_analyze_opts_default(&c->opts);
    c->color = isatty(STDOUT_FILENO) && !getenv("NO_COLOR");
    const char *ai_env = getenv("CALLSCOPE_AI");
    c->ai = ai_env && strcmp(ai_env, "1") == 0;
    int i = start;
    for (; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--json")) c->json = 1;
        else if (!strcmp(a, "--no-color")) c->color = 0;
        else if (!strcmp(a, "--ai")) c->ai = 1;
        else if (!strcmp(a, "--no-ai")) c->ai = 0;
        else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) c->verbose = 1;
        else if (!strcmp(a, "--slow-ms") && i + 1 < argc)
            c->opts.slow_min_ns = atoll(argv[++i]) * CS_NS_PER_MS;
        else if (!strcmp(a, "--net-slow-ms") && i + 1 < argc)
            c->opts.net_slow_ns = atoll(argv[++i]) * CS_NS_PER_MS;
        else if (a[0] == '-' && a[1] && strcmp(a, "-o") && strcmp(a, "--md") && strcmp(a, "--json-out")) {
            fprintf(stderr, "callscope %s: unknown option %s\n", cmd, a);
            return -1;
        } else if (!strcmp(a, "-o") || !strcmp(a, "--md") || !strcmp(a, "--json-out")) {
            i++; /* handled by the command itself */
        } else if (!c->input) {
            c->input = a;
        } else {
            fprintf(stderr, "callscope %s: unexpected argument %s\n", cmd, a);
            return -1;
        }
    }
    if (!c->input) {
        fprintf(stderr, "callscope %s: missing <trace> (a .jsonl file, or - for stdin)\n", cmd);
        return -1;
    }
    return i;
}

int cli_load(const char *path, cs_eventlog *log) {
    char err[512];
    cs_eventlog_init(log);
    if (cs_eventlog_load_file(log, path, err, sizeof err) != 0) {
        fprintf(stderr, "callscope: %s\n", err);
        return -1;
    }
    if (!cs_eventlog_count(log)) {
        fprintf(stderr, "callscope: %s contains no events%s\n", path,
                log->malformed ? " (every line was malformed)" : "");
        return -1;
    }
    return 0;
}

void cli_rca(const cs_analysis *a, const cli_common *c, cs_rca_result *r) {
    if (!c->ai) {
        cs_rca_rules(a, r);
        return;
    }
    cs_ai_config cfg;
    cs_ai_config_from_env(&cfg);
    cfg.verbose = c->verbose;
    char err[300] = "";
    if (c->verbose) fprintf(stderr, "callscope: asking %s at %s\n", cfg.model, cfg.base_url);
    if (cs_rca_ai(a, &cfg, r, err, sizeof err) != 0 && c->verbose)
        fprintf(stderr, "callscope: AI fallback: %s\n", err);
}

int cli_write_file(const char *path, const char *data, size_t len) {
    FILE *fp = strcmp(path, "-") == 0 ? stdout : fopen(path, "w");
    if (!fp) {
        perror(path);
        return -1;
    }
    size_t w = fwrite(data, 1, len, fp);
    if (fp != stdout) fclose(fp);
    return w == len ? 0 : -1;
}

static int run_common(int argc, char **argv, const char *cmd, cli_common *c, cs_eventlog *log,
                      cs_analysis *a) {
    if (cli_parse_common(argc, argv, 2, c, cmd) < 0) return -1;
    if (cli_load(c->input, log) != 0) return -1;
    if (cs_analyze(a, log, &c->opts) != 0) {
        fprintf(stderr, "callscope: analysis failed (out of memory?)\n");
        return -1;
    }
    return 0;
}

int cmd_analyze(int argc, char **argv) {
    cli_common c;
    cs_eventlog log;
    cs_analysis a;
    if (run_common(argc, argv, "analyze", &c, &log, &a) != 0) return 2;
    cs_rca_result r;
    cli_rca(&a, &c, &r);
    if (c.json) {
        cs_strbuf sb;
        cs_sb_init(&sb);
        cs_report_json(&sb, &a, &r);
        fwrite(sb.data, 1, sb.len, stdout);
        cs_sb_free(&sb);
    } else {
        cs_report_terminal(stdout, &a, &r, c.color);
    }
    int status = r.found && a.findings.len ? 1 : 0; /* non-zero when problems were found */
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
    return status;
}

int cmd_rca(int argc, char **argv) {
    cli_common c;
    cs_eventlog log;
    cs_analysis a;
    if (run_common(argc, argv, "rca", &c, &log, &a) != 0) return 2;
    cs_rca_result r;
    cli_rca(&a, &c, &r);
    if (c.json) {
        cs_strbuf sb;
        cs_sb_init(&sb);
        cs_rca_result_json(&r, &a, &sb);
        cs_sb_appendc(&sb, '\n');
        fwrite(sb.data, 1, sb.len, stdout);
        cs_sb_free(&sb);
    } else {
        printf("%s\n\n%s\n", r.summary, r.explanation);
        if (r.n_fixes) {
            printf("\nFix:\n");
            for (size_t i = 0; i < r.n_fixes; i++) printf("  %zu. %s\n", i + 1, r.fixes[i]);
        }
        if (r.n_checks) {
            printf("\nCheck next:\n");
            for (size_t i = 0; i < r.n_checks; i++) printf("  - %s\n", r.checks[i]);
        }
        printf("\n[%s, confidence %.0f%%, category %s]%s%s\n", r.source, r.confidence * 100,
               r.category, r.notes[0] ? "\n" : "", r.notes);
    }
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
    return r.found ? 1 : 0;
}

static const char *opt_value(int argc, char **argv, const char *name) {
    for (int i = 2; i + 1 < argc; i++)
        if (!strcmp(argv[i], name)) return argv[i + 1];
    return NULL;
}

int cmd_report(int argc, char **argv) {
    cli_common c;
    cs_eventlog log;
    cs_analysis a;
    if (run_common(argc, argv, "report", &c, &log, &a) != 0) return 2;
    const char *html = opt_value(argc, argv, "-o");
    const char *md = opt_value(argc, argv, "--md");
    const char *json = opt_value(argc, argv, "--json-out");
    if (!html && !md && !json) html = "callscope-report.html";

    cs_rca_result r;
    cli_rca(&a, &c, &r);
    cs_strbuf sb;
    cs_sb_init(&sb);
    int rc = 0;
    if (html) {
        cs_report_html(&sb, &a, &r);
        rc |= cli_write_file(html, sb.data, sb.len);
        if (strcmp(html, "-")) fprintf(stderr, "callscope: wrote %s\n", html);
    }
    if (md) {
        cs_sb_clear(&sb);
        cs_report_markdown(&sb, &a, &r);
        rc |= cli_write_file(md, sb.data, sb.len);
        if (strcmp(md, "-")) fprintf(stderr, "callscope: wrote %s\n", md);
    }
    if (json) {
        cs_sb_clear(&sb);
        cs_report_json(&sb, &a, &r);
        rc |= cli_write_file(json, sb.data, sb.len);
        if (strcmp(json, "-")) fprintf(stderr, "callscope: wrote %s\n", json);
    }
    if (strcmp(html ? html : "", "-") && !c.json)
        fprintf(stderr, "callscope: root cause (%s, %.0f%%): %s\n", r.source, r.confidence * 100,
                r.summary);
    cs_sb_free(&sb);
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
    return rc ? 2 : 0;
}
