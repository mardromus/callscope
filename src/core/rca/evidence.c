/* JSON views of an analysis: the evidence pack given to the AI agent, and the
 * serialized RCA result used by `callscope rca --json` and the reports. */
#include <stdio.h>
#include <string.h>

#include "callscope/json.h"
#include "callscope/rca.h"
#include "callscope/timeutil.h"

static double ms(int64_t ns) { return (double)ns / 1e6; }

static void finding_json(cs_jw *w, const cs_finding *f, int with_detail) {
    char ts[40];
    cs_jw_obj_begin(w);
    cs_jw_kv_str(w, "id", f->id);
    cs_jw_kv_str(w, "detector", f->detector);
    cs_jw_kv_str(w, "level", cs_level_name(f->level));
    cs_jw_kv_str(w, "severity", cs_severity_name(f->sev));
    cs_jw_kv_str(w, "title", f->title);
    if (with_detail) cs_jw_kv_str(w, "detail", f->detail);
    if (f->stack[0]) cs_jw_kv_str(w, "where", f->stack);
    if (f->fn) cs_jw_kv_str(w, "function", f->fn);
    if (f->peer) cs_jw_kv_str(w, "peer", f->peer);
    if (f->err) cs_jw_kv_str(w, "error", f->err);
    cs_jw_kv_i64(w, "count", f->count);
    if (f->first_ts) cs_jw_kv_str(w, "first_seen", cs_fmt_ts(f->first_ts, ts, sizeof ts));
    if (f->tid >= 0) cs_jw_kv_i64(w, "tid", f->tid);
    cs_jw_key(w, "evidence_events");
    cs_jw_arr_begin(w);
    for (size_t i = 0; i < f->n_evidence; i++) cs_jw_i64(w, (int64_t)f->evidence[i]);
    cs_jw_arr_end(w);
    cs_jw_obj_end(w);
}

int cs_rca_evidence_json(const cs_analysis *a, const cs_rca_result *prior, cs_strbuf *out) {
    cs_jw w;
    cs_jw_init(&w, out);
    char ts[40];
    cs_jw_obj_begin(&w);

    cs_jw_key(&w, "trace");
    cs_jw_obj_begin(&w);
    cs_jw_kv_str(&w, "source", a->log->source[0] ? a->log->source : "(stdin)");
    cs_jw_kv_i64(&w, "events", (int64_t)cs_eventlog_count(a->log));
    cs_jw_kv_str(&w, "start", cs_fmt_ts(a->log->t_min, ts, sizeof ts));
    cs_jw_kv_num(&w, "span_ms", ms(a->span_ns));
    cs_jw_kv_i64(&w, "processes", (int64_t)a->log->n_pids);
    cs_jw_kv_i64(&w, "threads", (int64_t)a->log->n_tids);
    cs_jw_kv_i64(&w, "function_events", (int64_t)a->n_fn_events);
    cs_jw_kv_i64(&w, "network_events", (int64_t)a->n_net_events);
    cs_jw_kv_i64(&w, "app_errors", (int64_t)a->n_app_errors);
    cs_jw_kv_bool(&w, "crashed", a->crashed);
    if (a->has_exit) cs_jw_kv_i64(&w, "exit_code", a->exit_code);
    cs_jw_obj_end(&w);

    cs_jw_key(&w, "top_functions");
    cs_jw_arr_begin(&w);
    for (size_t i = 0; i < a->fns.stats.len && i < 8; i++) {
        const cs_fnstat *st = cs_vec_at(&a->fns.stats, i);
        cs_jw_obj_begin(&w);
        cs_jw_kv_str(&w, "fn", st->fn);
        cs_jw_kv_i64(&w, "calls", st->calls);
        cs_jw_kv_num(&w, "inclusive_ms", ms(st->incl_total));
        cs_jw_kv_num(&w, "exclusive_ms", ms(st->excl_total));
        cs_jw_kv_num(&w, "p50_ms", ms(st->p50));
        cs_jw_kv_num(&w, "p95_ms", ms(st->p95));
        cs_jw_kv_num(&w, "max_ms", ms(st->max));
        cs_jw_kv_i64(&w, "network_wait_pct",
                     st->incl_total ? 100 * st->net_wait_total / st->incl_total : 0);
        cs_jw_obj_end(&w);
    }
    cs_jw_arr_end(&w);

    cs_jw_key(&w, "peers");
    cs_jw_arr_begin(&w);
    for (size_t i = 0; i < a->net.peers.len && i < 8; i++) {
        const cs_peerstat *p = cs_vec_at(&a->net.peers, i);
        int64_t ec;
        const char *top = cs_peerstat_top_err(p, &ec);
        cs_jw_obj_begin(&w);
        cs_jw_kv_str(&w, "peer", p->peer);
        cs_jw_kv_i64(&w, "connect_attempts", p->attempts);
        cs_jw_kv_i64(&w, "connect_failures", p->failures);
        if (p->accepts) cs_jw_kv_i64(&w, "accepted", p->accepts);
        if (top) cs_jw_kv_str(&w, "top_error", top);
        cs_jw_kv_i64(&w, "bytes_sent", p->sent);
        cs_jw_kv_i64(&w, "bytes_received", p->recvd);
        cs_jw_kv_num(&w, "connect_max_ms", ms(p->connect_max));
        cs_jw_kv_num(&w, "io_max_ms", ms(p->io_max));
        cs_jw_kv_i64(&w, "resets", p->resets);
        cs_jw_obj_end(&w);
    }
    cs_jw_arr_end(&w);

    cs_jw_key(&w, "dns");
    cs_jw_arr_begin(&w);
    for (size_t i = 0; i < a->net.dns.len && i < 8; i++) {
        const cs_dnsstat *d = cs_vec_at(&a->net.dns, i);
        cs_jw_obj_begin(&w);
        cs_jw_kv_str(&w, "host", d->host);
        cs_jw_kv_i64(&w, "lookups", d->lookups);
        cs_jw_kv_i64(&w, "failures", d->failures);
        if (d->last_err) cs_jw_kv_str(&w, "last_error", d->last_err);
        cs_jw_kv_num(&w, "max_ms", ms(d->max_dur));
        cs_jw_obj_end(&w);
    }
    cs_jw_arr_end(&w);

    cs_jw_key(&w, "findings");
    cs_jw_arr_begin(&w);
    for (size_t i = 0; i < a->findings.len && i < 15; i++)
        finding_json(&w, cs_vec_at(&a->findings, i), 1);
    cs_jw_arr_end(&w);

    if (prior) {
        cs_jw_key(&w, "rule_based_hypothesis");
        cs_jw_obj_begin(&w);
        cs_jw_kv_bool(&w, "found", prior->found);
        if (prior->found) cs_jw_kv_str(&w, "root_finding", prior->root_id);
        cs_jw_kv_str(&w, "category", prior->category);
        cs_jw_kv_str(&w, "summary", prior->summary);
        cs_jw_kv_num(&w, "confidence", prior->confidence);
        cs_jw_key(&w, "causal_chain");
        cs_jw_arr_begin(&w);
        for (size_t i = 0; i < prior->n_chain; i++) cs_jw_str(&w, prior->chain[i]);
        cs_jw_arr_end(&w);
        cs_jw_obj_end(&w);
    }
    cs_jw_obj_end(&w);
    return 0;
}

int cs_rca_result_json(const cs_rca_result *r, const cs_analysis *a, cs_strbuf *out) {
    cs_jw w;
    cs_jw_init(&w, out);
    cs_jw_obj_begin(&w);
    cs_jw_kv_str(&w, "source", r->source);
    cs_jw_kv_bool(&w, "found", r->found);
    cs_jw_kv_str(&w, "category", r->category);
    if (r->found) cs_jw_kv_str(&w, "root_finding", r->root_id);
    cs_jw_kv_str(&w, "summary", r->summary);
    cs_jw_kv_str(&w, "explanation", r->explanation);
    cs_jw_kv_num(&w, "confidence", r->confidence);
    cs_jw_key(&w, "causal_chain");
    cs_jw_arr_begin(&w);
    for (size_t i = 0; i < r->n_chain; i++) {
        const cs_finding *f = a ? cs_analysis_finding(a, r->chain[i]) : NULL;
        if (f)
            finding_json(&w, f, 0);
        else
            cs_jw_str(&w, r->chain[i]);
    }
    cs_jw_arr_end(&w);
    cs_jw_key(&w, "fixes");
    cs_jw_arr_begin(&w);
    for (size_t i = 0; i < r->n_fixes; i++) cs_jw_str(&w, r->fixes[i]);
    cs_jw_arr_end(&w);
    cs_jw_key(&w, "next_checks");
    cs_jw_arr_begin(&w);
    for (size_t i = 0; i < r->n_checks; i++) cs_jw_str(&w, r->checks[i]);
    cs_jw_arr_end(&w);
    if (r->notes[0]) cs_jw_kv_str(&w, "notes", r->notes);
    if (r->ai_steps) cs_jw_kv_i64(&w, "agent_tool_calls", r->ai_steps);
    cs_jw_obj_end(&w);
    return 0;
}
