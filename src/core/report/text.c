/* Terminal and Markdown reports. */
#include <stdio.h>
#include <string.h>

#include "callscope/report.h"
#include "callscope/timeutil.h"

size_t cs_event_describe(const cs_event *ev, char *buf, size_t n) {
    char t[32], d[32];
    cs_fmt_clock(ev->ts, t, sizeof t);
    const char *err = ev->err ? ev->err : (ev->err_no ? cs_errno_name(ev->err_no) : NULL);
    int w = 0;
    switch (ev->kind) {
    case CS_EV_FN_ENTER: w = snprintf(buf, n, "%s  tid %d  enter %s", t, ev->tid, ev->fn); break;
    case CS_EV_FN_EXIT:
        w = snprintf(buf, n, "%s  tid %d  exit  %s after %s", t, ev->tid, ev->fn,
                     cs_fmt_dur(ev->dur, d, sizeof d));
        break;
    case CS_EV_NET_DNS:
        w = snprintf(buf, n, "%s  tid %d  dns   %s -> %s (%s)", t, ev->tid, ev->host ? ev->host : "?",
                     ev->rc ? (err ? err : "failed") : (ev->msg ? ev->msg : "ok"),
                     cs_fmt_dur(ev->dur, d, sizeof d));
        break;
    case CS_EV_NET_CONNECT:
    case CS_EV_NET_ACCEPT:
    case CS_EV_NET_SEND:
    case CS_EV_NET_RECV:
    case CS_EV_NET_CLOSE: {
        char extra[64] = "";
        if (ev->kind == CS_EV_NET_SEND || ev->kind == CS_EV_NET_RECV)
            snprintf(extra, sizeof extra, " %lld B", (long long)ev->bytes);
        else if (ev->kind == CS_EV_NET_CLOSE)
            snprintf(extra, sizeof extra, " sent %lld / recv %lld", (long long)ev->sent,
                     (long long)ev->recvd);
        w = snprintf(buf, n, "%s  tid %d  %-7s fd %d %s%s%s%s (%s)", t, ev->tid,
                     cs_event_kind_name(ev->kind) + 4, ev->fd, ev->peer ? ev->peer : "?", extra,
                     err ? "  " : "", err ? err : "", cs_fmt_dur(ev->dur, d, sizeof d));
        break;
    }
    case CS_EV_APP_ERROR:
        w = snprintf(buf, n, "%s  tid %d  ERROR %s: %s", t, ev->tid, ev->code ? ev->code : "",
                     ev->msg ? ev->msg : "");
        break;
    case CS_EV_APP_LOG:
        w = snprintf(buf, n, "%s  tid %d  log[%s] %s", t, ev->tid, ev->code ? ev->code : "",
                     ev->msg ? ev->msg : "");
        break;
    case CS_EV_SIGNAL:
        w = snprintf(buf, n, "%s  tid %d  SIGNAL %s", t, ev->tid,
                     cs_signal_name(ev->sig) ? cs_signal_name(ev->sig) : "?");
        break;
    case CS_EV_PROC_EXIT:
        w = snprintf(buf, n, "%s  pid %d  exit status %lld", t, ev->pid, (long long)ev->rc);
        break;
    default:
        w = snprintf(buf, n, "%s  tid %d  %s %s", t, ev->tid, cs_event_kind_name(ev->kind),
                     ev->msg ? ev->msg : "");
    }
    return w < 0 ? 0 : (size_t)w;
}

/* ---- terminal --------------------------------------------------------------- */

typedef struct {
    int on;
} tty;

static const char *C(const tty *t, const char *code) { return t->on ? code : ""; }
#define RESET "\033[0m"
#define BOLD "\033[1m"
#define DIM "\033[2m"

static const char *sev_color(cs_severity s) {
    switch (s) {
    case CS_SEV_CRITICAL: return "\033[1;97;41m";
    case CS_SEV_HIGH: return "\033[1;31m";
    case CS_SEV_MEDIUM: return "\033[33m";
    case CS_SEV_LOW: return "\033[36m";
    default: return "\033[2m";
    }
}

int cs_report_terminal(FILE *fp, const cs_analysis *a, const cs_rca_result *r, int color) {
    tty t = {color};
    char d1[32], d2[32], ts[40];
    fprintf(fp, "\n%scallscope%s  %s\n", C(&t, "\033[1;35m"), C(&t, RESET),
            a->log->source[0] ? a->log->source : "(stdin)");
    fprintf(fp, "%s%zu events over %s from %s | %zu process(es), %zu thread(s) | %zu fn, %zu net, "
                "%zu app errors%s%s\n",
            C(&t, DIM), cs_eventlog_count(a->log), cs_fmt_dur(a->span_ns, d1, sizeof d1),
            cs_fmt_ts(a->log->t_min, ts, sizeof ts), a->log->n_pids, a->log->n_tids,
            a->n_fn_events, a->n_net_events, a->n_app_errors, a->crashed ? " | CRASHED" : "",
            C(&t, RESET));
    if (a->log->malformed)
        fprintf(fp, "%s  warning: %zu malformed line(s) skipped (first at line %zu)%s\n",
                C(&t, "\033[33m"), a->log->malformed, a->log->first_bad_line, C(&t, RESET));

    if (r) {
        fprintf(fp, "\n%s ROOT CAUSE %s  %s%s%s  confidence %.0f%%  via %s\n", C(&t, "\033[1;97;45m"),
                C(&t, RESET), C(&t, BOLD), r->category, C(&t, RESET), r->confidence * 100.0,
                r->source);
        fprintf(fp, "  %s%s%s\n", C(&t, BOLD), r->summary, C(&t, RESET));
        if (r->found) {
            fprintf(fp, "\n  %scausal chain:%s ", C(&t, DIM), C(&t, RESET));
            for (size_t i = 0; i < r->n_chain; i++) {
                const cs_finding *f = cs_analysis_finding(a, r->chain[i]);
                fprintf(fp, "%s%s%s%s", i ? "\n    -> " : "", C(&t, i ? "" : BOLD), r->chain[i],
                        C(&t, RESET));
                if (f) fprintf(fp, " %s", f->title);
            }
            fprintf(fp, "\n");
        }
        if (r->n_fixes) {
            fprintf(fp, "\n  %sfix:%s\n", C(&t, "\033[32m"), C(&t, RESET));
            for (size_t i = 0; i < r->n_fixes; i++) fprintf(fp, "    %zu. %s\n", i + 1, r->fixes[i]);
        }
        if (r->n_checks) {
            fprintf(fp, "  %scheck next:%s\n", C(&t, "\033[34m"), C(&t, RESET));
            for (size_t i = 0; i < r->n_checks; i++) fprintf(fp, "    - %s\n", r->checks[i]);
        }
        if (r->notes[0]) fprintf(fp, "  %snote: %s%s\n", C(&t, DIM), r->notes, C(&t, RESET));
    }

    fprintf(fp, "\n%sFINDINGS%s (%zu)\n", C(&t, BOLD), C(&t, RESET), a->findings.len);
    for (size_t i = 0; i < a->findings.len && i < 12; i++) {
        const cs_finding *f = cs_vec_at(&a->findings, i);
        fprintf(fp, "  %s %s%-8s%s %s%-11s%s %s\n", f->id, C(&t, sev_color(f->sev)),
                cs_severity_name(f->sev), C(&t, RESET), C(&t, DIM), cs_level_name(f->level),
                C(&t, RESET), f->title);
        if (f->stack[0]) fprintf(fp, "      %sat %s%s\n", C(&t, DIM), f->stack, C(&t, RESET));
    }
    if (!a->findings.len) fprintf(fp, "  none - looks healthy\n");

    if (a->fns.stats.len) {
        fprintf(fp, "\n%sTOP FUNCTIONS%s (by exclusive time)\n", C(&t, BOLD), C(&t, RESET));
        fprintf(fp, "  %s%-28s %7s %11s %11s %11s %6s%s\n", C(&t, DIM), "function", "calls",
                "exclusive", "p95", "max", "net%", C(&t, RESET));
        for (size_t i = 0; i < a->fns.stats.len && i < 8; i++) {
            const cs_fnstat *st = cs_vec_at(&a->fns.stats, i);
            char d3[32];
            fprintf(fp, "  %-28.28s %7lld %11s %11s %11s %5lld%%\n", st->fn, (long long)st->calls,
                    cs_fmt_dur(st->excl_total, d1, sizeof d1), cs_fmt_dur(st->p95, d2, sizeof d2),
                    cs_fmt_dur(st->max, d3, sizeof d3),
                    (long long)(st->incl_total ? 100 * st->net_wait_total / st->incl_total : 0));
        }
    }
    if (a->net.peers.len) {
        fprintf(fp, "\n%sPEERS%s\n", C(&t, BOLD), C(&t, RESET));
        fprintf(fp, "  %s%-26s %8s %8s %-14s %11s %11s%s\n", C(&t, DIM), "peer", "connects",
                "failed", "top error", "connect max", "io max", C(&t, RESET));
        for (size_t i = 0; i < a->net.peers.len && i < 8; i++) {
            const cs_peerstat *p = cs_vec_at(&a->net.peers, i);
            const char *e = cs_peerstat_top_err(p, NULL);
            fprintf(fp, "  %-26.26s %8lld %s%8lld%s %-14s %11s %11s\n", p->peer,
                    (long long)(p->attempts + p->accepts),
                    C(&t, p->failures ? "\033[31m" : ""), (long long)p->failures, C(&t, RESET),
                    e ? e : "-", cs_fmt_dur(p->connect_max, d1, sizeof d1),
                    cs_fmt_dur(p->io_max, d2, sizeof d2));
        }
    }
    fprintf(fp, "\n");
    return 0;
}

/* ---- markdown --------------------------------------------------------------- */

static void md_escape(cs_strbuf *out, const char *s) {
    for (; s && *s; s++) {
        if (*s == '|') cs_sb_append(out, "\\|");
        else if (*s == '\n') cs_sb_appendc(out, ' ');
        else cs_sb_appendc(out, *s);
    }
}

int cs_report_markdown(cs_strbuf *out, const cs_analysis *a, const cs_rca_result *r) {
    char d1[32], d2[32], d3[32], ts[40];
    cs_sb_appendf(out, "# callscope report\n\n");
    cs_sb_appendf(out, "**Trace:** `%s` | %zu events over %s from %s | %zu process(es), %zu "
                       "thread(s)%s\n\n",
                  a->log->source[0] ? a->log->source : "stdin", cs_eventlog_count(a->log),
                  cs_fmt_dur(a->span_ns, d1, sizeof d1), cs_fmt_ts(a->log->t_min, ts, sizeof ts),
                  a->log->n_pids, a->log->n_tids, a->crashed ? " | **process crashed**" : "");
    if (r) {
        cs_sb_appendf(out, "## Root cause\n\n> **%s**\n\n", r->summary);
        cs_sb_appendf(out, "- Category: `%s`\n- Confidence: %.0f%%\n- Engine: %s\n\n", r->category,
                      r->confidence * 100.0, r->source);
        cs_sb_appendf(out, "%s\n\n", r->explanation);
        if (r->found && r->n_chain) {
            cs_sb_append(out, "### Causal chain\n\n");
            for (size_t i = 0; i < r->n_chain; i++) {
                const cs_finding *f = cs_analysis_finding(a, r->chain[i]);
                cs_sb_appendf(out, "%zu. **%s** %s\n", i + 1, r->chain[i], f ? f->title : "");
            }
            cs_sb_append(out, "\n");
        }
        if (r->n_fixes) {
            cs_sb_append(out, "### How to fix\n\n");
            for (size_t i = 0; i < r->n_fixes; i++) cs_sb_appendf(out, "- [ ] %s\n", r->fixes[i]);
            cs_sb_append(out, "\n");
        }
        if (r->n_checks) {
            cs_sb_append(out, "### What to check next\n\n");
            for (size_t i = 0; i < r->n_checks; i++) cs_sb_appendf(out, "- %s\n", r->checks[i]);
            cs_sb_append(out, "\n");
        }
        if (r->notes[0]) cs_sb_appendf(out, "_Note: %s_\n\n", r->notes);
    }
    cs_sb_appendf(out, "## Findings (%zu)\n\n", a->findings.len);
    if (a->findings.len) {
        cs_sb_append(out, "| ID | Severity | Level | Finding | Where |\n|---|---|---|---|---|\n");
        for (size_t i = 0; i < a->findings.len; i++) {
            const cs_finding *f = cs_vec_at(&a->findings, i);
            cs_sb_appendf(out, "| %s | %s | %s | ", f->id, cs_severity_name(f->sev),
                          cs_level_name(f->level));
            md_escape(out, f->title);
            cs_sb_append(out, " | `");
            md_escape(out, f->stack[0] ? f->stack : "-");
            cs_sb_append(out, "` |\n");
        }
        cs_sb_append(out, "\n");
        for (size_t i = 0; i < a->findings.len && i < 6; i++) {
            const cs_finding *f = cs_vec_at(&a->findings, i);
            cs_sb_appendf(out, "<details><summary><b>%s</b> %s</summary>\n\n%s\n\n", f->id, f->title,
                          f->detail);
            if (f->n_evidence) {
                cs_sb_append(out, "```\n");
                for (size_t k = 0; k < f->n_evidence; k++) {
                    char line[512];
                    cs_event_describe(cs_eventlog_at(a->log, f->evidence[k]), line, sizeof line);
                    cs_sb_appendf(out, "#%zu %s\n", f->evidence[k], line);
                }
                cs_sb_append(out, "```\n");
            }
            cs_sb_append(out, "</details>\n\n");
        }
    }
    if (a->fns.stats.len) {
        cs_sb_append(out, "## Top functions\n\n| Function | Calls | Exclusive | p95 | Max | Net wait |\n"
                          "|---|---:|---:|---:|---:|---:|\n");
        for (size_t i = 0; i < a->fns.stats.len && i < 10; i++) {
            const cs_fnstat *st = cs_vec_at(&a->fns.stats, i);
            cs_sb_appendf(out, "| `%s` | %lld | %s | %s | %s | %lld%% |\n", st->fn,
                          (long long)st->calls, cs_fmt_dur(st->excl_total, d1, sizeof d1),
                          cs_fmt_dur(st->p95, d2, sizeof d2), cs_fmt_dur(st->max, d3, sizeof d3),
                          (long long)(st->incl_total ? 100 * st->net_wait_total / st->incl_total : 0));
        }
        cs_sb_append(out, "\n");
    }
    if (a->net.peers.len) {
        cs_sb_append(out, "## Network peers\n\n| Peer | Connects | Failed | Top error | Connect max | I/O max |\n"
                          "|---|---:|---:|---|---:|---:|\n");
        for (size_t i = 0; i < a->net.peers.len && i < 10; i++) {
            const cs_peerstat *p = cs_vec_at(&a->net.peers, i);
            const char *e = cs_peerstat_top_err(p, NULL);
            cs_sb_appendf(out, "| `%s` | %lld | %lld | %s | %s | %s |\n", p->peer,
                          (long long)(p->attempts + p->accepts), (long long)p->failures, e ? e : "-",
                          cs_fmt_dur(p->connect_max, d1, sizeof d1), cs_fmt_dur(p->io_max, d2, sizeof d2));
        }
        cs_sb_append(out, "\n");
    }
    cs_sb_append(out, "_Generated by callscope._\n");
    return 0;
}
