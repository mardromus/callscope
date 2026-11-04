/* Analysis pipeline: call tree -> network time attribution -> stats ->
 * detectors (function, network, application, cross-level) -> ranking. */
#include <string.h>

#include "callscope/timeutil.h"
#include "internal.h"

void cs_findings_finalize(cs_analysis *a);

void cs_analyze_opts_default(cs_analyze_opts *o) {
    o->slow_min_ns = 50 * CS_NS_PER_MS;
    o->slow_factor = 5.0;
    o->recursion_limit = 128;
    o->net_slow_ns = 300 * CS_NS_PER_MS;
    o->retry_count = 4;
    o->retry_window_ns = 10 * CS_NS_PER_S;
    o->hotspot_share = 0.35;
    o->net_wait_share = 0.6;
    o->error_link_ns = 2 * CS_NS_PER_S;
    o->max_per_detector = 6;
}

static void count_events(cs_analysis *a) {
    size_t n = cs_eventlog_count(a->log);
    for (size_t i = 0; i < n; i++) {
        const cs_event *ev = cs_eventlog_at(a->log, i);
        if (cs_event_is_fn(ev->kind)) a->n_fn_events++;
        else if (cs_event_is_net(ev->kind)) a->n_net_events++;
        else if (ev->kind == CS_EV_APP_ERROR) a->n_app_errors++;
        else if (ev->kind == CS_EV_APP_LOG) a->n_app_logs++;
        else if (ev->kind == CS_EV_SIGNAL) a->n_signals++;
        if (ev->kind == CS_EV_PROC_EXIT) {
            a->has_exit = 1;
            a->exit_code = ev->rc;
            if (ev->sig) a->crashed = 1;
        }
    }
    if (a->n_signals) a->crashed = 1;
    a->span_ns = a->log->t_max - a->log->t_min;
}

int cs_analyze(cs_analysis *a, const cs_eventlog *log, const cs_analyze_opts *opts) {
    memset(a, 0, sizeof(*a));
    a->log = log;
    if (opts)
        a->opts = *opts;
    else
        cs_analyze_opts_default(&a->opts);
    cs_vec_init(&a->findings, sizeof(cs_finding));

    if (cs_calltree_build(&a->tree, log) != 0) return -1;
    cs_correlate_net_time(a);
    if (cs_fnstats_build(&a->fns, &a->tree) != 0) return -1;
    if (cs_netstats_build(&a->net, log) != 0) return -1;
    count_events(a);

    cs_detect_function(a);
    cs_detect_network(a);
    cs_detect_app(a);
    cs_detect_cross(a);
    cs_findings_finalize(a);
    return 0;
}

void cs_analysis_free(cs_analysis *a) {
    cs_calltree_free(&a->tree);
    cs_fnstats_free(&a->fns);
    cs_netstats_free(&a->net);
    cs_vec_free(&a->findings);
}
