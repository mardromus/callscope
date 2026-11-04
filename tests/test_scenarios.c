/* End-to-end detector tests: every synthetic fault must be found, ranked near
 * the top, and attributed to the right function. */
#include "cstest.h"

#include "callscope/analyze.h"
#include "callscope/gen.h"

static int run(const char *scenario, cs_eventlog *log, cs_analysis *a) {
    cs_eventlog_init(log);
    cs_gen_opts o = {scenario, 40, 7, 0, 2};
    if (cs_gen_run(log, &o, NULL, 0) != 0) return -1;
    return cs_analyze(a, log, NULL);
}

static const cs_finding *find_detector(const cs_analysis *a, const char *det, size_t top) {
    for (size_t i = 0; i < a->findings.len && i < top; i++) {
        const cs_finding *f = cs_vec_at(&a->findings, i);
        if (strcmp(f->detector, det) == 0) return f;
    }
    return NULL;
}

CS_TEST(scenario_healthy_has_no_serious_findings) {
    cs_eventlog log;
    cs_analysis a;
    CS_ASSERT_EQ_INT(run("healthy", &log, &a), 0);
    for (size_t i = 0; i < a.findings.len; i++)
        CS_ASSERT(CS_VEC_AT(&a.findings, cs_finding, i)->sev <= CS_SEV_LOW);
    CS_ASSERT(a.n_fn_events > 500);
    CS_ASSERT(a.n_net_events > 200);
    CS_ASSERT(!a.crashed);
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
}

CS_TEST(scenario_every_fault_is_detected) {
    for (const cs_gen_scenario_info *s = cs_gen_scenarios(); s->name; s++) {
        if (!s->expected_root) continue;
        cs_eventlog log;
        cs_analysis a;
        CS_ASSERT_EQ_INT(run(s->name, &log, &a), 0);
        const cs_finding *f = find_detector(&a, s->expected_root, 4);
        if (!f) fprintf(stderr, "    scenario %s: %s not in top findings\n", s->name, s->expected_root);
        CS_ASSERT(f != NULL);
        cs_analysis_free(&a);
        cs_eventlog_free(&log);
    }
}

CS_TEST(scenario_upstream_down_links_cause_and_effect) {
    cs_eventlog log;
    cs_analysis a;
    CS_ASSERT_EQ_INT(run("upstream-down", &log, &a), 0);
    const cs_finding *cf = find_detector(&a, "net.connect_failure", 10);
    CS_ASSERT(cf != NULL);
    CS_ASSERT_EQ_STR(cf->peer, "10.0.4.22:9102");
    CS_ASSERT_EQ_STR(cf->err, "ECONNREFUSED");
    CS_ASSERT_EQ_STR(cf->fn, "charge_payment");
    const cs_finding *prop = find_detector(&a, "cross.error_propagation", 10);
    CS_ASSERT(prop != NULL);
    CS_ASSERT(prop->count >= 10);
    CS_ASSERT(find_detector(&a, "net.retry_storm", 10) != NULL);
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
}

CS_TEST(scenario_slow_upstream_blames_network_not_code) {
    cs_eventlog log;
    cs_analysis a;
    CS_ASSERT_EQ_INT(run("slow-upstream", &log, &a), 0);
    const cs_finding *x = find_detector(&a, "cross.slow_because_network", 5);
    CS_ASSERT(x != NULL);
    CS_ASSERT_EQ_STR(x->fn, "charge_payment");
    CS_ASSERT_EQ_STR(x->peer, "10.0.4.22:9102");
    CS_ASSERT(x->value > 0.9);
    const cs_fnstat *st = cs_fnstats_find(&a.fns, "charge_payment");
    CS_ASSERT(st && st->net_wait_total > st->incl_total / 2);
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
}

CS_TEST(scenario_crashes_point_at_the_faulting_function) {
    cs_eventlog log;
    cs_analysis a;
    CS_ASSERT_EQ_INT(run("reset-crash", &log, &a), 0);
    CS_ASSERT(a.crashed);
    const cs_finding *c = find_detector(&a, "fn.crash", 5);
    CS_ASSERT(c != NULL);
    CS_ASSERT_EQ_STR(c->fn, "parse_payment_response");
    CS_ASSERT(strstr(c->stack, "charge_payment > parse_payment_response") != NULL);
    cs_analysis_free(&a);
    cs_eventlog_free(&log);

    CS_ASSERT_EQ_INT(run("recursion-crash", &log, &a), 0);
    const cs_finding *r = find_detector(&a, "fn.recursion", 3);
    CS_ASSERT(r != NULL);
    CS_ASSERT_EQ_STR(r->fn, "render_template");
    CS_ASSERT(strstr(r->stack, "render_template (x300)") != NULL);
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
}

CS_TEST(scenario_generator_is_deterministic) {
    cs_eventlog a, b;
    cs_eventlog_init(&a);
    cs_eventlog_init(&b);
    cs_gen_opts o = {"slow-upstream", 20, 99, 0, 2};
    cs_gen_run(&a, &o, NULL, 0);
    cs_gen_run(&b, &o, NULL, 0);
    CS_ASSERT_EQ_INT(cs_eventlog_count(&a), cs_eventlog_count(&b));
    for (size_t i = 0; i < cs_eventlog_count(&a); i++)
        CS_ASSERT_EQ_INT(cs_eventlog_at(&a, i)->ts, cs_eventlog_at(&b, i)->ts);
    char err[128];
    cs_gen_opts bad = {"no-such-scenario", 0, 0, 0, 0};
    CS_ASSERT(cs_gen_run(&a, &bad, err, sizeof err) != 0);
    cs_eventlog_free(&a);
    cs_eventlog_free(&b);
}
