/* AI agent tests with a scripted fake LLM (no network). */
#include "cstest.h"

#include "callscope/gen.h"
#include "callscope/json.h"
#include "callscope/rca.h"

typedef struct {
    const char *const *replies; /* successive response bodies */
    int n, next;
    int saw_tool_result; /* a later request contained our tool's output */
    long status;
} fake_llm;

static int fake_send(void *ctx, const char *url, const char *key, const char *body, int timeout,
                     cs_strbuf *resp, long *status, char *err, size_t errlen) {
    fake_llm *f = ctx;
    if (strstr(body, "\"role\":\"tool\"") && strstr(body, "connect_failures")) f->saw_tool_result = 1;
    if (f->next >= f->n) {
        snprintf(err, errlen, "fake: no more replies");
        return -1;
    }
    cs_sb_append(resp, f->replies[f->next++]);
    *status = f->status ? f->status : 200;
    return 0;
}

static void analyse(const char *scenario, cs_eventlog *log, cs_analysis *a) {
    cs_eventlog_init(log);
    cs_gen_opts o = {scenario, 30, 5, 0, 2};
    cs_gen_run(log, &o, NULL, 0);
    cs_analyze(a, log, NULL);
}

static const char *find_id(const cs_analysis *a, const char *detector) {
    for (size_t i = 0; i < a->findings.len; i++) {
        const cs_finding *f = cs_vec_at(&a->findings, i);
        if (strcmp(f->detector, detector) == 0) return f->id;
    }
    return "F99";
}

CS_TEST(ai_agent_uses_tools_then_accepts_valid_verdict) {
    cs_eventlog log;
    cs_analysis a;
    analyse("upstream-down", &log, &a);
    const char *root = find_id(&a, "net.connect_failure");
    char final[1024];
    snprintf(final, sizeof final,
             "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"```json\\n"
             "{\\\"root_finding\\\":\\\"%s\\\",\\\"category\\\":\\\"dependency-unavailable\\\","
             "\\\"confidence\\\":0.88,\\\"summary\\\":\\\"Payment service down\\\","
             "\\\"explanation\\\":\\\"see %s\\\",\\\"causal_chain\\\":[\\\"%s\\\",\\\"F77\\\"],"
             "\\\"fixes\\\":[\\\"restart payments\\\"],\\\"next_checks\\\":[\\\"check port\\\"]}"
             "\\n```\"}}]}",
             root, root, root);
    const char *replies[] = {
        "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":null,\"tool_calls\":[{"
        "\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_peer_stats\","
        "\"arguments\":\"{\\\"peer\\\":\\\"10.0.4.22:9102\\\"}\"}}]}}]}",
        final,
    };
    fake_llm fake = {replies, 2, 0, 0, 0};
    cs_ai_config cfg;
    memset(&cfg, 0, sizeof cfg);
    snprintf(cfg.base_url, sizeof cfg.base_url, "https://llm.test/v1");
    snprintf(cfg.model, sizeof cfg.model, "fake-model");
    cfg.max_steps = 4;
    cfg.transport = fake_send;
    cfg.transport_ctx = &fake;

    cs_rca_result r;
    char err[256] = "";
    CS_ASSERT_EQ_INT(cs_rca_ai(&a, &cfg, &r, err, sizeof err), 0);
    CS_ASSERT(fake.saw_tool_result);
    CS_ASSERT_EQ_STR(r.source, "ai:fake-model");
    CS_ASSERT_EQ_STR(r.root_id, root);
    CS_ASSERT_EQ_STR(r.summary, "Payment service down");
    CS_ASSERT_NEAR(r.confidence, 0.88, 1e-9);
    CS_ASSERT_EQ_INT(r.n_chain, 1); /* bogus F77 was dropped */
    CS_ASSERT_EQ_INT(r.ai_steps, 1);
    CS_ASSERT_EQ_STR(r.fixes[0], "restart payments");
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
}

CS_TEST(ai_agent_rejects_hallucinated_root_and_falls_back) {
    cs_eventlog log;
    cs_analysis a;
    analyse("dns-failure", &log, &a);
    const char *bad =
        "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"{\\\"root_finding\\\":"
        "\\\"F42\\\",\\\"summary\\\":\\\"made up\\\"}\"}}]}";
    const char *replies[] = {bad, bad};
    fake_llm fake = {replies, 2, 0, 0, 0};
    cs_ai_config cfg;
    memset(&cfg, 0, sizeof cfg);
    snprintf(cfg.base_url, sizeof cfg.base_url, "https://llm.test/v1");
    snprintf(cfg.model, sizeof cfg.model, "fake");
    cfg.transport = fake_send;
    cfg.transport_ctx = &fake;
    cs_rca_result r;
    char err[256] = "";
    CS_ASSERT_EQ_INT(cs_rca_ai(&a, &cfg, &r, err, sizeof err), 1);
    CS_ASSERT_EQ_INT(fake.next, 2); /* it asked the model to correct itself once */
    CS_ASSERT_EQ_STR(r.source, "rules");
    CS_ASSERT(strstr(r.notes, "F42") != NULL);
    CS_ASSERT(cs_analysis_finding(&a, r.root_id) != NULL);
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
}

CS_TEST(ai_agent_falls_back_on_http_error_and_missing_key) {
    cs_eventlog log;
    cs_analysis a;
    analyse("slow-upstream", &log, &a);
    const char *replies[] = {"{\"error\":{\"message\":\"invalid api key\"}}"};
    fake_llm fake = {replies, 1, 0, 0, 401};
    cs_ai_config cfg;
    memset(&cfg, 0, sizeof cfg);
    snprintf(cfg.base_url, sizeof cfg.base_url, "https://llm.test/v1");
    cfg.transport = fake_send;
    cfg.transport_ctx = &fake;
    cs_rca_result r;
    char err[256];
    CS_ASSERT_EQ_INT(cs_rca_ai(&a, &cfg, &r, err, sizeof err), 1);
    CS_ASSERT(strstr(err, "401") && strstr(err, "invalid api key"));

    cs_ai_config nokey;
    memset(&nokey, 0, sizeof nokey);
    snprintf(nokey.base_url, sizeof nokey.base_url, "https://api.example/v1");
    CS_ASSERT_EQ_INT(cs_rca_ai(&a, &nokey, &r, err, sizeof err), 1);
    CS_ASSERT(strstr(r.notes, "no API key") != NULL);
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
}

CS_TEST(evidence_pack_is_valid_json_with_findings) {
    cs_eventlog log;
    cs_analysis a;
    analyse("reset-crash", &log, &a);
    cs_rca_result prior;
    cs_rca_rules(&a, &prior);
    cs_strbuf sb;
    cs_sb_init(&sb);
    cs_rca_evidence_json(&a, &prior, &sb);
    cs_json *v = cs_json_parse(sb.data, sb.len, NULL, 0);
    CS_ASSERT(v != NULL);
    CS_ASSERT(cs_json_as_bool(cs_json_path(v, "trace.crashed"), 0));
    CS_ASSERT(cs_json_len(cs_json_get(v, "findings")) >= 3);
    CS_ASSERT_EQ_STR(cs_json_as_str(cs_json_path(v, "rule_based_hypothesis.root_finding"), NULL),
                     prior.root_id);
    cs_json_free(v);
    cs_sb_clear(&sb);
    cs_rca_result_json(&prior, &a, &sb);
    v = cs_json_parse(sb.data, sb.len, NULL, 0);
    CS_ASSERT(v != NULL);
    CS_ASSERT(cs_json_len(cs_json_get(v, "causal_chain")) == prior.n_chain);
    cs_json_free(v);
    cs_sb_free(&sb);
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
}
