/* AI root cause agent.
 *
 * The model gets the evidence pack (findings, top functions, peers, DNS and
 * the rule engine's hypothesis) and a set of read-only investigation tools
 * backed by the analysis. It may call tools for a few rounds, then must
 * answer with a JSON verdict. The verdict is validated: it has to point at
 * findings that really exist. If anything goes wrong (no key, HTTP error,
 * invalid answer) we fall back to the deterministic rules result. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "callscope/http.h"
#include "callscope/json.h"
#include "callscope/rca.h"
#include "callscope/timeutil.h"

#define TOOL_RESULT_MAX 7000

static const char *SYSTEM_PROMPT =
    "You are callscope's root cause analysis agent, an expert SRE and systems programmer. "
    "You are given an evidence pack produced by analysing a trace of a program at two levels: "
    "function calls (call stacks, durations) and network calls (connect/send/recv/close/DNS "
    "with errors and latencies), plus application errors and crashes.\n"
    "Your job: determine the single most likely ROOT CAUSE (not a symptom), the causal chain "
    "from cause to visible effects, concrete fixes and what to check next.\n"
    "Rules:\n"
    "- Base every claim on the evidence. Use the tools to inspect findings, events, call "
    "stacks, function stats and peers when something is ambiguous. Do not invent hosts, "
    "functions or numbers.\n"
    "- Application errors and exit codes are usually symptoms. Prefer causes such as a "
    "dependency failing, a misconfiguration, a resource leak or a code defect.\n"
    "- A rule-based hypothesis is included; confirm or overturn it with evidence.\n"
    "- When finished, reply with ONLY a JSON object, no prose, of this shape:\n"
    "{\"root_finding\": \"F01\" or \"none\", \"category\": \"dependency-unavailable|"
    "dependency-slow|dependency-unstable|configuration|resource-exhaustion|code-defect|"
    "network-path|retry-policy|performance|hang|healthy\", \"confidence\": 0.0-1.0, "
    "\"summary\": \"one sentence\", \"explanation\": \"a short paragraph citing finding ids "
    "and evidence\", \"causal_chain\": [\"F01\", \"F03\"], \"fixes\": [\"...\"], "
    "\"next_checks\": [\"...\"]}";

static const char *TOOLS_JSON =
    "["
    "{\"type\":\"function\",\"function\":{\"name\":\"get_finding\",\"description\":\"Full "
    "details of one finding including its evidence events and call stacks.\",\"parameters\":"
    "{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"string\",\"description\":"
    "\"Finding id such as F02\"}},\"required\":[\"id\"]}}},"
    "{\"type\":\"function\",\"function\":{\"name\":\"get_events\",\"description\":\"Raw "
    "events by index range (time ordered), optionally only one thread. Max 40.\","
    "\"parameters\":{\"type\":\"object\",\"properties\":{\"start\":{\"type\":\"integer\"},"
    "\"count\":{\"type\":\"integer\"},\"tid\":{\"type\":\"integer\"}},\"required\":"
    "[\"start\"]}}},"
    "{\"type\":\"function\",\"function\":{\"name\":\"search_events\",\"description\":\"Find "
    "events by kind (fn_enter, net_connect, net_recv, net_dns, app_error, signal, ...), "
    "peer, error name or enclosing function. Max 30 results.\",\"parameters\":{\"type\":"
    "\"object\",\"properties\":{\"kind\":{\"type\":\"string\"},\"peer\":{\"type\":"
    "\"string\"},\"error\":{\"type\":\"string\"},\"function\":{\"type\":\"string\"},"
    "\"limit\":{\"type\":\"integer\"}}}}},"
    "{\"type\":\"function\",\"function\":{\"name\":\"get_call_stack\",\"description\":"
    "\"Call stack (outermost first) that was active when an event happened.\","
    "\"parameters\":{\"type\":\"object\",\"properties\":{\"event_index\":{\"type\":"
    "\"integer\"}},\"required\":[\"event_index\"]}}},"
    "{\"type\":\"function\",\"function\":{\"name\":\"get_function_stats\",\"description\":"
    "\"Timing statistics for a function: calls, inclusive/exclusive time, percentiles, "
    "network wait.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":"
    "\"string\"}},\"required\":[\"name\"]}}},"
    "{\"type\":\"function\",\"function\":{\"name\":\"get_peer_stats\",\"description\":"
    "\"Statistics and individual connections for one remote peer (ip:port).\","
    "\"parameters\":{\"type\":\"object\",\"properties\":{\"peer\":{\"type\":\"string\"}},"
    "\"required\":[\"peer\"]}}}"
    "]";

int cs_ai_config_from_env(cs_ai_config *c) {
    memset(c, 0, sizeof(*c));
    const char *base = getenv("CALLSCOPE_LLM_BASE_URL");
    const char *model = getenv("CALLSCOPE_LLM_MODEL");
    const char *key = getenv("CALLSCOPE_LLM_API_KEY");
    int openai = 0;
    if (!key || !*key) key = getenv("GROQ_API_KEY");
    if (!key || !*key) {
        key = getenv("OPENAI_API_KEY");
        openai = key && *key;
    }
    snprintf(c->base_url, sizeof c->base_url, "%s",
             (base && *base) ? base
                             : (openai ? "https://api.openai.com/v1" : "https://api.groq.com/openai/v1"));
    snprintf(c->model, sizeof c->model, "%s",
             (model && *model) ? model : (openai ? "gpt-4o-mini" : "llama-3.3-70b-versatile"));
    if (key) snprintf(c->api_key, sizeof c->api_key, "%s", key);
    c->max_steps = 6;
    c->timeout_s = 60;
    const char *steps = getenv("CALLSCOPE_LLM_MAX_STEPS");
    if (steps && atoi(steps) > 0) c->max_steps = atoi(steps);
    int local = strstr(c->base_url, "localhost") || strstr(c->base_url, "127.0.0.1");
    return (c->api_key[0] || local) ? 1 : 0;
}

/* ---- tool implementations -------------------------------------------------- */

static void event_json(const cs_analysis *a, cs_jw *w, size_t i) {
    const cs_event *ev = cs_eventlog_at(a->log, i);
    char ts[32], stack[400];
    cs_jw_obj_begin(w);
    cs_jw_kv_i64(w, "index", (int64_t)i);
    cs_jw_kv_str(w, "time", cs_fmt_clock(ev->ts, ts, sizeof ts));
    cs_jw_kv_str(w, "kind", cs_event_kind_name(ev->kind));
    cs_jw_kv_i64(w, "tid", ev->tid);
    if (ev->fn) cs_jw_kv_str(w, "fn", ev->fn);
    if (ev->peer) cs_jw_kv_str(w, "peer", ev->peer);
    if (ev->host) cs_jw_kv_str(w, "host", ev->host);
    if (cs_event_is_net(ev->kind)) cs_jw_kv_i64(w, "rc", ev->rc);
    const char *err = ev->err ? ev->err : (ev->err_no ? cs_errno_name(ev->err_no) : NULL);
    if (err) cs_jw_kv_str(w, "error", err);
    if (ev->dur >= 0) cs_jw_kv_num(w, "dur_ms", (double)ev->dur / 1e6);
    if (ev->bytes) cs_jw_kv_i64(w, "bytes", ev->bytes);
    if (ev->sig) cs_jw_kv_i64(w, "signal", ev->sig);
    if (ev->code) cs_jw_kv_str(w, "code", ev->code);
    if (ev->msg) cs_jw_kv_str(w, "msg", ev->msg);
    size_t f = i < a->tree.n_events ? a->tree.ev_frame[i] : CS_NONE;
    if (f != CS_NONE && !cs_event_is_fn(ev->kind)) {
        cs_calltree_stack_str(&a->tree, f, stack, sizeof stack);
        cs_jw_kv_str(w, "inside", stack);
    }
    cs_jw_obj_end(w);
}

static int64_t arg_i64(const cs_json *args, const char *k, int64_t d) {
    return cs_json_as_i64(cs_json_get(args, k), d);
}
static const char *arg_str(const cs_json *args, const char *k) {
    return cs_json_as_str(cs_json_get(args, k), NULL);
}

static void tool_get_finding(const cs_analysis *a, const cs_json *args, cs_jw *w) {
    const char *id = arg_str(args, "id");
    const cs_finding *f = id ? cs_analysis_finding(a, id) : NULL;
    if (!f) {
        cs_jw_obj_begin(w);
        cs_jw_kv_str(w, "error", "no such finding");
        cs_jw_obj_end(w);
        return;
    }
    cs_jw_obj_begin(w);
    cs_jw_kv_str(w, "id", f->id);
    cs_jw_kv_str(w, "detector", f->detector);
    cs_jw_kv_str(w, "severity", cs_severity_name(f->sev));
    cs_jw_kv_str(w, "title", f->title);
    cs_jw_kv_str(w, "detail", f->detail);
    cs_jw_kv_str(w, "where", f->stack);
    cs_jw_kv_i64(w, "count", f->count);
    cs_jw_kv_num(w, "value", f->value);
    cs_jw_key(w, "evidence");
    cs_jw_arr_begin(w);
    for (size_t i = 0; i < f->n_evidence; i++) event_json(a, w, f->evidence[i]);
    cs_jw_arr_end(w);
    cs_jw_obj_end(w);
}

static void tool_get_events(const cs_analysis *a, const cs_json *args, cs_jw *w) {
    int64_t start = arg_i64(args, "start", 0), count = arg_i64(args, "count", 20);
    int64_t tid = arg_i64(args, "tid", -1);
    if (count > 40) count = 40;
    if (start < 0) start = 0;
    cs_jw_arr_begin(w);
    int64_t emitted = 0;
    for (size_t i = (size_t)start; i < cs_eventlog_count(a->log) && emitted < count; i++) {
        if (tid >= 0 && cs_eventlog_at(a->log, i)->tid != tid) continue;
        event_json(a, w, i);
        emitted++;
    }
    cs_jw_arr_end(w);
}

static void tool_search(const cs_analysis *a, const cs_json *args, cs_jw *w) {
    const char *kind = arg_str(args, "kind"), *peer = arg_str(args, "peer");
    const char *err = arg_str(args, "error"), *fn = arg_str(args, "function");
    int64_t limit = arg_i64(args, "limit", 20);
    if (limit > 30) limit = 30;
    cs_event_kind k = kind ? cs_event_kind_parse(kind) : CS_EV_UNKNOWN;
    cs_jw_arr_begin(w);
    int64_t found = 0;
    for (size_t i = 0; i < cs_eventlog_count(a->log) && found < limit; i++) {
        const cs_event *ev = cs_eventlog_at(a->log, i);
        if (k != CS_EV_UNKNOWN && ev->kind != k) continue;
        const char *p = ev->peer ? ev->peer : ev->host;
        if (peer && (!p || !strstr(p, peer))) continue;
        const char *e = ev->err ? ev->err : (ev->err_no ? cs_errno_name(ev->err_no) : ev->code);
        if (err && (!e || strcmp(e, err) != 0)) continue;
        if (fn) {
            size_t f = a->tree.ev_frame[i];
            const cs_frame *fr = cs_calltree_frame(&a->tree, f);
            if (!fr || strcmp(fr->fn, fn) != 0) continue;
        }
        event_json(a, w, i);
        found++;
    }
    cs_jw_arr_end(w);
}

static void tool_stack(const cs_analysis *a, const cs_json *args, cs_jw *w) {
    int64_t i = arg_i64(args, "event_index", -1);
    cs_jw_obj_begin(w);
    if (i < 0 || (size_t)i >= cs_eventlog_count(a->log)) {
        cs_jw_kv_str(w, "error", "event_index out of range");
    } else {
        char stack[1024];
        size_t f = a->tree.ev_frame[i];
        cs_calltree_stack_str(&a->tree, f, stack, sizeof stack);
        cs_jw_kv_str(w, "stack", f == CS_NONE ? "(no function trace for this thread)" : stack);
        cs_jw_key(w, "event");
        event_json(a, w, (size_t)i);
    }
    cs_jw_obj_end(w);
}

static void tool_fn(const cs_analysis *a, const cs_json *args, cs_jw *w) {
    const char *name = arg_str(args, "name");
    const cs_fnstat *st = name ? cs_fnstats_find(&a->fns, name) : NULL;
    cs_jw_obj_begin(w);
    if (!st) {
        cs_jw_kv_str(w, "error", "unknown function");
    } else {
        cs_jw_kv_str(w, "fn", st->fn);
        cs_jw_kv_i64(w, "calls", st->calls);
        cs_jw_kv_num(w, "inclusive_ms", (double)st->incl_total / 1e6);
        cs_jw_kv_num(w, "exclusive_ms", (double)st->excl_total / 1e6);
        cs_jw_kv_num(w, "network_wait_ms", (double)st->net_wait_total / 1e6);
        cs_jw_kv_num(w, "p50_ms", (double)st->p50 / 1e6);
        cs_jw_kv_num(w, "p95_ms", (double)st->p95 / 1e6);
        cs_jw_kv_num(w, "max_ms", (double)st->max / 1e6);
        cs_jw_kv_i64(w, "never_returned", st->open_frames);
        cs_jw_kv_i64(w, "max_depth", st->max_depth);
        char stack[400];
        cs_calltree_stack_str(&a->tree, st->slowest_frame, stack, sizeof stack);
        cs_jw_kv_str(w, "slowest_call_path", stack);
    }
    cs_jw_obj_end(w);
}

static void tool_peer(const cs_analysis *a, const cs_json *args, cs_jw *w) {
    const char *peer = arg_str(args, "peer");
    const cs_peerstat *p = peer ? cs_netstats_peer(&a->net, peer) : NULL;
    cs_jw_obj_begin(w);
    if (!p) {
        cs_jw_kv_str(w, "error", "unknown peer");
        cs_jw_obj_end(w);
        return;
    }
    cs_jw_kv_str(w, "peer", p->peer);
    cs_jw_kv_i64(w, "connect_attempts", p->attempts);
    cs_jw_kv_i64(w, "connect_failures", p->failures);
    cs_jw_key(w, "errors");
    cs_jw_obj_begin(w);
    for (int i = 0; i < CS_PEER_ERRS; i++)
        if (p->err_name[i]) cs_jw_kv_i64(w, p->err_name[i], p->err_count[i]);
    cs_jw_obj_end(w);
    cs_jw_kv_num(w, "connect_max_ms", (double)p->connect_max / 1e6);
    cs_jw_kv_num(w, "io_max_ms", (double)p->io_max / 1e6);
    cs_jw_kv_i64(w, "resets", p->resets);
    cs_jw_key(w, "connections");
    cs_jw_arr_begin(w);
    int shown = 0;
    for (size_t i = 0; i < a->net.conns.len && shown < 15; i++) {
        const cs_netconn *c = cs_vec_at(&a->net.conns, i);
        if (c->peer != p->peer) continue;
        char ts[32];
        cs_jw_obj_begin(w);
        cs_jw_kv_str(w, "opened", cs_fmt_clock(c->t_open, ts, sizeof ts));
        cs_jw_kv_i64(w, "fd", c->fd);
        cs_jw_kv_i64(w, "tid", c->tid);
        cs_jw_kv_bool(w, "connected", c->connected);
        if (c->connect_err) cs_jw_kv_str(w, "connect_error", cs_errno_name(c->connect_err));
        cs_jw_kv_i64(w, "sent", c->sent);
        cs_jw_kv_i64(w, "received", c->recvd);
        cs_jw_kv_num(w, "max_io_ms", (double)c->max_io / 1e6);
        cs_jw_kv_bool(w, "closed", c->closed);
        cs_jw_obj_end(w);
        shown++;
    }
    cs_jw_arr_end(w);
    cs_jw_obj_end(w);
}

static void run_tool(const cs_analysis *a, const char *name, const char *args_text,
                     cs_strbuf *out) {
    cs_json *args = cs_json_parse(args_text ? args_text : "{}", (size_t)-1, NULL, 0);
    cs_jw w;
    cs_jw_init(&w, out);
    if (!name)
        cs_sb_append(out, "{\"error\":\"missing tool name\"}");
    else if (strcmp(name, "get_finding") == 0)
        tool_get_finding(a, args, &w);
    else if (strcmp(name, "get_events") == 0)
        tool_get_events(a, args, &w);
    else if (strcmp(name, "search_events") == 0)
        tool_search(a, args, &w);
    else if (strcmp(name, "get_call_stack") == 0)
        tool_stack(a, args, &w);
    else if (strcmp(name, "get_function_stats") == 0)
        tool_fn(a, args, &w);
    else if (strcmp(name, "get_peer_stats") == 0)
        tool_peer(a, args, &w);
    else
        cs_sb_appendf(out, "{\"error\":\"unknown tool %s\"}", name);
    cs_json_free(args);
    if (out->len > TOOL_RESULT_MAX) { /* keep the conversation small */
        out->len = TOOL_RESULT_MAX;
        out->data[out->len] = '\0';
        cs_sb_append(out, "... (truncated)");
    }
}

/* ---- conversation helpers -------------------------------------------------- */

static void msg_add(cs_strbuf *msgs, const char *role, const char *content) {
    if (msgs->len) cs_sb_appendc(msgs, ',');
    cs_sb_appendf(msgs, "{\"role\":\"%s\",\"content\":", role);
    cs_json_append_str(msgs, content);
    cs_sb_appendc(msgs, '}');
}

static void msg_add_raw(cs_strbuf *msgs, const char *json) {
    if (msgs->len) cs_sb_appendc(msgs, ',');
    cs_sb_append(msgs, json);
}

static void msg_add_tool(cs_strbuf *msgs, const char *id, const char *content) {
    if (msgs->len) cs_sb_appendc(msgs, ',');
    cs_sb_append(msgs, "{\"role\":\"tool\",\"tool_call_id\":");
    cs_json_append_str(msgs, id ? id : "");
    cs_sb_append(msgs, ",\"content\":");
    cs_json_append_str(msgs, content);
    cs_sb_appendc(msgs, '}');
}

/* Pull the JSON object out of a reply that may be wrapped in ``` fences. */
static cs_json *extract_json(const char *text) {
    if (!text) return NULL;
    const char *lb = strchr(text, '{'), *rb = strrchr(text, '}');
    if (!lb || !rb || rb < lb) return NULL;
    return cs_json_parse(lb, (size_t)(rb - lb + 1), NULL, 0);
}

static void copy_list(const cs_json *arr, char (*dst)[300], size_t *n, size_t max) {
    *n = 0;
    for (size_t i = 0; i < cs_json_len(arr) && *n < max; i++) {
        const char *s = cs_json_as_str(cs_json_at(arr, i), NULL);
        if (s && *s) snprintf(dst[(*n)++], sizeof dst[0], "%s", s);
    }
}

/* Validate the model's verdict against the analysis and copy it into out. */
static int accept_verdict(const cs_analysis *a, const cs_json *v, cs_rca_result *out, char *why,
                          size_t wn) {
    const char *root = cs_json_as_str(cs_json_get(v, "root_finding"), NULL);
    const char *summary = cs_json_as_str(cs_json_get(v, "summary"), NULL);
    if (!root || !summary || !*summary) {
        snprintf(why, wn, "verdict is missing root_finding or summary");
        return -1;
    }
    int none = strcmp(root, "none") == 0;
    if (!none && !cs_analysis_finding(a, root)) {
        snprintf(why, wn, "verdict blames %s, which is not a finding", root);
        return -1;
    }
    out->found = !none;
    snprintf(out->root_id, sizeof out->root_id, "%s", none ? "" : root);
    snprintf(out->summary, sizeof out->summary, "%s", summary);
    snprintf(out->category, sizeof out->category, "%s",
             cs_json_as_str(cs_json_get(v, "category"), "unknown"));
    snprintf(out->explanation, sizeof out->explanation, "%s",
             cs_json_as_str(cs_json_get(v, "explanation"), summary));
    double c = cs_json_as_num(cs_json_get(v, "confidence"), 0.5);
    out->confidence = c < 0 ? 0 : c > 1 ? 1 : c;
    out->n_chain = 0;
    if (!none) snprintf(out->chain[out->n_chain++], sizeof out->chain[0], "%s", root);
    const cs_json *chain = cs_json_get(v, "causal_chain");
    for (size_t i = 0; i < cs_json_len(chain) && out->n_chain < CS_RCA_MAX_CHAIN; i++) {
        const char *id = cs_json_as_str(cs_json_at(chain, i), NULL);
        if (!id || !cs_analysis_finding(a, id) || strcmp(id, root) == 0) continue;
        snprintf(out->chain[out->n_chain++], sizeof out->chain[0], "%s", id);
    }
    copy_list(cs_json_get(v, "fixes"), out->fixes, &out->n_fixes, CS_RCA_MAX_FIXES);
    copy_list(cs_json_get(v, "next_checks"), out->checks, &out->n_checks, CS_RCA_MAX_CHECKS);
    return 0;
}

static int fallback(const cs_rca_result *prior, cs_rca_result *out, const char *reason, char *err,
                    size_t errlen) {
    *out = *prior;
    snprintf(out->notes, sizeof out->notes, "AI analysis unavailable (%s); showing the rule-based result.",
             reason);
    if (err && errlen) snprintf(err, errlen, "%s", reason);
    return 1;
}

int cs_rca_ai(const cs_analysis *a, const cs_ai_config *cfg, cs_rca_result *out, char *err,
              size_t errlen) {
    cs_rca_result prior;
    cs_rca_rules(a, &prior);
    if (!cfg || (!cfg->api_key[0] && !cfg->transport && !strstr(cfg->base_url, "localhost") &&
                 !strstr(cfg->base_url, "127.0.0.1")))
        return fallback(&prior, out, "no API key configured", err, errlen);

    cs_http_transport send = cfg->transport ? cfg->transport : cs_http_post_json;
    char url[400];
    snprintf(url, sizeof url, "%s/chat/completions", cfg->base_url);
    int max_steps = cfg->max_steps > 0 ? cfg->max_steps : 6;

    cs_strbuf msgs, evidence, body, resp, tool_out;
    cs_sb_init(&msgs);
    cs_sb_init(&evidence);
    cs_sb_init(&body);
    cs_sb_init(&resp);
    cs_sb_init(&tool_out);
    cs_rca_evidence_json(a, &prior, &evidence);
    msg_add(&msgs, "system", SYSTEM_PROMPT);
    cs_strbuf user;
    cs_sb_init(&user);
    cs_sb_append(&user, "Evidence pack (JSON):\n");
    cs_sb_append(&user, cs_sb_cstr(&evidence));
    cs_sb_append(&user, "\nInvestigate as needed, then give your verdict as the JSON object.");
    msg_add(&msgs, "user", cs_sb_cstr(&user));
    cs_sb_free(&user);

    int rc = 1, retried = 0, tool_calls = 0;
    char reason[300] = "agent did not produce a verdict";
    for (int step = 0; step <= max_steps + 1; step++) {
        int allow_tools = step < max_steps;
        cs_sb_clear(&body);
        cs_sb_appendf(&body, "{\"model\":");
        cs_json_append_str(&body, cfg->model);
        cs_sb_appendf(&body, ",\"temperature\":0.1,\"messages\":[%s]", cs_sb_cstr(&msgs));
        if (allow_tools) cs_sb_appendf(&body, ",\"tools\":%s,\"tool_choice\":\"auto\"", TOOLS_JSON);
        cs_sb_appendc(&body, '}');

        cs_sb_clear(&resp);
        long status = 0;
        char herr[256] = "";
        if (send(cfg->transport_ctx, url, cfg->api_key, cs_sb_cstr(&body), cfg->timeout_s, &resp,
                 &status, herr, sizeof herr) != 0) {
            snprintf(reason, sizeof reason, "%s", herr[0] ? herr : "HTTP request failed");
            break;
        }
        cs_json *root = cs_json_parse(cs_sb_cstr(&resp), resp.len, NULL, 0);
        if (status != 200 || !root) {
            const char *m = cs_json_as_str(cs_json_path(root, "error.message"), NULL);
            snprintf(reason, sizeof reason, "LLM API returned HTTP %ld%s%.200s", status,
                     m ? ": " : "", m ? m : "");
            cs_json_free(root);
            break;
        }
        cs_json *msg = cs_json_path(root, "choices.0.message");
        cs_json *calls = cs_json_get(msg, "tool_calls");
        if (cs_json_len(calls) > 0) {
            /* echo the assistant turn back, then answer every call */
            cs_strbuf echo;
            cs_sb_init(&echo);
            cs_sb_append(&echo, "{\"role\":\"assistant\",\"content\":null,\"tool_calls\":");
            cs_json_serialize(calls, &echo);
            cs_sb_appendc(&echo, '}');
            msg_add_raw(&msgs, cs_sb_cstr(&echo));
            cs_sb_free(&echo);
            for (size_t i = 0; i < cs_json_len(calls); i++) {
                cs_json *tc = cs_json_at(calls, i);
                const char *id = cs_json_as_str(cs_json_get(tc, "id"), "");
                const char *name = cs_json_as_str(cs_json_path(tc, "function.name"), NULL);
                const char *args = cs_json_as_str(cs_json_path(tc, "function.arguments"), "{}");
                cs_sb_clear(&tool_out);
                run_tool(a, name, args, &tool_out);
                if (cfg->verbose)
                    fprintf(stderr, "  [agent] %s(%s) -> %zu bytes\n", name ? name : "?", args,
                            tool_out.len);
                msg_add_tool(&msgs, id, cs_sb_cstr(&tool_out));
                tool_calls++;
            }
            cs_json_free(root);
            continue;
        }
        const char *content = cs_json_as_str(cs_json_get(msg, "content"), NULL);
        cs_json *verdict = extract_json(content);
        char why[200] = "reply was not a JSON object";
        if (verdict && accept_verdict(a, verdict, out, why, sizeof why) == 0) {
            snprintf(out->source, sizeof out->source, "ai:%.90s", cfg->model);
            out->ai_steps = tool_calls;
            if (out->n_fixes == 0) { /* keep the knowledge-base fixes if the model gave none */
                memcpy(out->fixes, prior.fixes, sizeof prior.fixes);
                out->n_fixes = prior.n_fixes;
            }
            out->notes[0] = '\0';
            rc = 0;
            cs_json_free(verdict);
            cs_json_free(root);
            break;
        }
        cs_json_free(verdict);
        snprintf(reason, sizeof reason, "%s", why);
        cs_json_free(root);
        if (retried) break;
        retried = 1;
        msg_add(&msgs, "assistant", content ? content : "");
        char fix[400];
        snprintf(fix, sizeof fix,
                 "That verdict was rejected: %s. Reply again with ONLY the JSON object, and "
                 "root_finding must be one of the finding ids in the evidence or \"none\".",
                 why);
        msg_add(&msgs, "user", fix);
    }

    cs_sb_free(&msgs);
    cs_sb_free(&evidence);
    cs_sb_free(&body);
    cs_sb_free(&resp);
    cs_sb_free(&tool_out);
    if (rc != 0) return fallback(&prior, out, reason, err, errlen);
    return 0;
}
