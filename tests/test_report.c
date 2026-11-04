#include "cstest.h"

#include "callscope/gen.h"
#include "callscope/json.h"
#include "callscope/report.h"

#include <errno.h>
#include <stdlib.h>

static void prepare(const char *scenario, cs_eventlog *log, cs_analysis *a, cs_rca_result *r) {
    cs_eventlog_init(log);
    cs_gen_opts o = {scenario, 24, 3, 0, 2};
    cs_gen_run(log, &o, NULL, 0);
    cs_analyze(a, log, NULL);
    cs_rca_rules(a, r);
}

CS_TEST(report_html_is_self_contained_and_complete) {
    cs_eventlog log;
    cs_analysis a;
    cs_rca_result r;
    prepare("upstream-down", &log, &a, &r);
    cs_strbuf sb;
    cs_sb_init(&sb);
    cs_report_html(&sb, &a, &r);
    const char *h = cs_sb_cstr(&sb);
    CS_ASSERT(strncmp(h, "<!DOCTYPE html>", 15) == 0);
    CS_ASSERT(strstr(h, "Root cause") != NULL);
    CS_ASSERT(strstr(h, "class=\"flame\"") != NULL);
    CS_ASSERT(strstr(h, "class=\"timeline\"") != NULL);
    CS_ASSERT(strstr(h, "10.0.4.22:9102") != NULL);
    CS_ASSERT(strstr(h, "<script") == NULL);  /* static report, no scripts */
    CS_ASSERT(strstr(h, "http://") == NULL);  /* no external assets */
    CS_ASSERT(strstr(h, "</html>") != NULL);
    cs_sb_free(&sb);
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
}

CS_TEST(report_markdown_and_json) {
    cs_eventlog log;
    cs_analysis a;
    cs_rca_result r;
    prepare("dns-failure", &log, &a, &r);
    cs_strbuf sb;
    cs_sb_init(&sb);
    cs_report_markdown(&sb, &a, &r);
    CS_ASSERT(strstr(cs_sb_cstr(&sb), "## Root cause") != NULL);
    CS_ASSERT(strstr(cs_sb_cstr(&sb), "payments.internal") != NULL);
    CS_ASSERT(strstr(cs_sb_cstr(&sb), "- [ ] ") != NULL);
    cs_sb_clear(&sb);
    cs_report_json(&sb, &a, &r);
    cs_json *v = cs_json_parse(sb.data, sb.len, NULL, 0);
    CS_ASSERT(v != NULL);
    CS_ASSERT_EQ_STR(cs_json_as_str(cs_json_path(v, "rca.category"), NULL), "configuration");
    CS_ASSERT(cs_json_len(cs_json_get(v, "findings")) == a.findings.len);
    cs_json_free(v);
    cs_sb_free(&sb);
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
}

CS_TEST(report_terminal_writes_summary) {
    cs_eventlog log;
    cs_analysis a;
    cs_rca_result r;
    prepare("healthy", &log, &a, &r);
    char *buf = NULL;
    size_t len = 0;
    FILE *fp = open_memstream(&buf, &len);
    cs_report_terminal(fp, &a, &r, 0);
    fclose(fp);
    CS_ASSERT(strstr(buf, "ROOT CAUSE") != NULL);
    CS_ASSERT(strstr(buf, "healthy") != NULL);
    CS_ASSERT(strstr(buf, "\033[") == NULL); /* no colour when disabled */
    free(buf);
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
}

CS_TEST(event_describe_formats_lines) {
    cs_event ev;
    cs_event_init(&ev, CS_EV_NET_CONNECT);
    ev.ts = 1793750400LL * 1000000000LL + 5000000;
    ev.tid = 9;
    ev.fd = 4;
    ev.peer = "10.0.0.1:80";
    ev.rc = -1;
    ev.err_no = ECONNREFUSED;
    ev.dur = 1500;
    char line[256];
    cs_event_describe(&ev, line, sizeof line);
    CS_ASSERT_EQ_STR(line, "00:00:00.005  tid 9  connect fd 4 10.0.0.1:80  ECONNREFUSED (1.5 us)");
}
