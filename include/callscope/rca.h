/* rca.h - root cause analysis on top of cs_analysis findings.
 *
 * Two engines produce the same cs_rca_result:
 *   cs_rca_rules()  deterministic: a causal graph between detectors plus a
 *                   knowledge base of failure modes. Always available, offline.
 *   cs_rca_ai()     an LLM agent (any OpenAI-compatible API: Groq, OpenAI,
 *                   Ollama, LM Studio...) that receives an evidence pack and
 *                   can call investigation tools (get events, call stacks,
 *                   function / peer stats) before answering. Its answer is
 *                   validated against the evidence; on any failure the rules
 *                   result is returned instead, with a note. */
#ifndef CALLSCOPE_RCA_H
#define CALLSCOPE_RCA_H

#include "callscope/analyze.h"
#include "callscope/strbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CS_RCA_MAX_CHAIN 8
#define CS_RCA_MAX_FIXES 6
#define CS_RCA_MAX_CHECKS 4

typedef struct cs_rca_result {
    char source[96];   /* "rules" or "ai:<model>" */
    int found;         /* 0 = nothing significant to explain */
    char root_id[8];   /* finding id of the root cause */
    char category[48]; /* dependency-unavailable, dependency-slow, code-defect, ... */
    char summary[400]; /* one-sentence root cause */
    char explanation[1600];
    double confidence; /* 0..1 */
    char chain[CS_RCA_MAX_CHAIN][8]; /* finding ids, cause first */
    size_t n_chain;
    char fixes[CS_RCA_MAX_FIXES][300];
    size_t n_fixes;
    char checks[CS_RCA_MAX_CHECKS][300];
    size_t n_checks;
    char notes[600]; /* e.g. why the AI result was not used */
    int ai_steps;    /* tool calls made by the agent */
} cs_rca_result;

/* ---- knowledge base ---------------------------------------------------- */

typedef struct cs_kb_entry {
    const char *detector; /* finding detector */
    const char *err;      /* specific error name, or NULL for any */
    const char *category;
    const char *cause;    /* template: {peer} {fn} {err} are substituted */
    const char *fixes[4];
    const char *checks[3];
} cs_kb_entry;

const cs_kb_entry *cs_kb_lookup(const char *detector, const char *err);
/* Expand {peer}/{fn}/{err}/{count} placeholders using a finding. */
void cs_kb_render(const char *tmpl, const cs_finding *f, char *out, size_t n);

/* ---- engines ----------------------------------------------------------- */

int cs_rca_rules(const cs_analysis *a, cs_rca_result *out);

typedef int (*cs_http_transport)(void *ctx, const char *url, const char *api_key,
                                 const char *body, int timeout_s, cs_strbuf *resp, long *status,
                                 char *err, size_t errlen);

typedef struct cs_ai_config {
    char base_url[256]; /* e.g. https://api.groq.com/openai/v1 */
    char api_key[256];
    char model[128];
    int max_steps;  /* tool-call rounds (default 6) */
    int timeout_s;  /* per request (default 60) */
    int verbose;    /* print the agent's steps to stderr */
    cs_http_transport transport; /* NULL = real HTTP; tests inject a fake */
    void *transport_ctx;
} cs_ai_config;

/* Fill from CALLSCOPE_LLM_BASE_URL / CALLSCOPE_LLM_API_KEY / CALLSCOPE_LLM_MODEL,
 * falling back to GROQ_API_KEY or OPENAI_API_KEY. Returns 1 when an LLM is
 * usable (a key is set, or the base URL is a local server). */
int cs_ai_config_from_env(cs_ai_config *c);

int cs_rca_ai(const cs_analysis *a, const cs_ai_config *cfg, cs_rca_result *out, char *err,
              size_t errlen);

/* Compact JSON the agent starts from (also useful for other tools). */
int cs_rca_evidence_json(const cs_analysis *a, const cs_rca_result *prior, cs_strbuf *out);
/* Serialize a result (with the chain's findings) as JSON. */
int cs_rca_result_json(const cs_rca_result *r, const cs_analysis *a, cs_strbuf *out);

#ifdef __cplusplus
}
#endif
#endif
