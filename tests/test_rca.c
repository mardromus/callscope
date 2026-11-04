#include "cstest.h"

#include "callscope/gen.h"
#include "callscope/rca.h"

static void rca_for(const char *scenario, cs_eventlog *log, cs_analysis *a, cs_rca_result *r) {
    cs_eventlog_init(log);
    cs_gen_opts o = {scenario, 40, 11, 0, 2};
    cs_gen_run(log, &o, NULL, 0);
    cs_analyze(a, log, NULL);
    cs_rca_rules(a, r);
}

CS_TEST(rca_rules_finds_expected_root_for_every_scenario) {
    for (const cs_gen_scenario_info *s = cs_gen_scenarios(); s->name; s++) {
        cs_eventlog log;
        cs_analysis a;
        cs_rca_result r;
        rca_for(s->name, &log, &a, &r);
        if (!s->expected_root) {
            CS_ASSERT(!r.found);
            CS_ASSERT_EQ_STR(r.category, "healthy");
        } else {
            CS_ASSERT(r.found);
            const cs_finding *root = cs_analysis_finding(&a, r.root_id);
            CS_ASSERT(root != NULL);
            if (strcmp(root->detector, s->expected_root) != 0)
                fprintf(stderr, "    %s: root %s, expected %s\n", s->name, root->detector,
                        s->expected_root);
            CS_ASSERT_EQ_STR(root->detector, s->expected_root);
            CS_ASSERT(r.confidence >= 0.3 && r.confidence <= 0.95);
            CS_ASSERT(r.n_fixes > 0);
            CS_ASSERT_EQ_STR(r.chain[0], r.root_id);
        }
        cs_analysis_free(&a);
        cs_eventlog_free(&log);
    }
}

CS_TEST(rca_rules_builds_causal_chain_and_text) {
    cs_eventlog log;
    cs_analysis a;
    cs_rca_result r;
    rca_for("upstream-down", &log, &a, &r);
    CS_ASSERT_EQ_STR(r.category, "dependency-unavailable");
    CS_ASSERT(strstr(r.summary, "10.0.4.22:9102") != NULL);
    CS_ASSERT(strstr(r.summary, "ECONNREFUSED") != NULL);
    CS_ASSERT(r.n_chain >= 3); /* root + app errors + propagation + retry storm */
    CS_ASSERT(r.confidence >= 0.7);
    int has_backoff = 0;
    for (size_t i = 0; i < r.n_fixes; i++)
        if (strstr(r.fixes[i], "backoff")) has_backoff = 1;
    CS_ASSERT(has_backoff);
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
}

CS_TEST(kb_render_substitutes_placeholders) {
    cs_finding f;
    memset(&f, 0, sizeof f);
    f.peer = "db:5432";
    f.fn = "load_user";
    f.err = "ETIMEDOUT";
    f.count = 3;
    f.value = 2.5e9;
    char out[256];
    cs_kb_render("{fn} -> {peer} failed {count}x with {err} after {value_dur} {unknown}", &f, out,
                 sizeof out);
    CS_ASSERT_EQ_STR(out, "load_user -> db:5432 failed 3x with ETIMEDOUT after 2.50 s {unknown}");
    CS_ASSERT(cs_kb_lookup("net.connect_failure", "ECONNREFUSED") != NULL);
    CS_ASSERT(cs_kb_lookup("net.connect_failure", "EWHATEVER") ==
              cs_kb_lookup("net.connect_failure", NULL));
    char tiny[8];
    cs_kb_render("{peer}{peer}", &f, tiny, sizeof tiny);
    CS_ASSERT(strlen(tiny) == 7);
}
