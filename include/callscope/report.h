/* report.h - human and machine readable output of an analysis + RCA. */
#ifndef CALLSCOPE_REPORT_H
#define CALLSCOPE_REPORT_H

#include <stdio.h>

#include "callscope/analyze.h"
#include "callscope/rca.h"
#include "callscope/strbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Coloured summary for the terminal (color = use ANSI escapes). */
int cs_report_terminal(FILE *fp, const cs_analysis *a, const cs_rca_result *r, int color);

/* GitHub-flavoured Markdown, good for tickets and pull requests. */
int cs_report_markdown(cs_strbuf *out, const cs_analysis *a, const cs_rca_result *r);

/* Self-contained single-file HTML: verdict, causal chain, timeline,
 * flame graph, findings with evidence, function and peer tables. */
int cs_report_html(cs_strbuf *out, const cs_analysis *a, const cs_rca_result *r);

/* Everything as one JSON document (r may be NULL). */
int cs_report_json(cs_strbuf *out, const cs_analysis *a, const cs_rca_result *r);

/* Render one event as a short human line: "14:02:11.004 net_connect 10.0.4.22:9102 ECONNREFUSED". */
size_t cs_event_describe(const cs_event *ev, char *buf, size_t n);

#ifdef __cplusplus
}
#endif
#endif
