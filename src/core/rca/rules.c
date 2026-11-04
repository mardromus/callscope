/* Deterministic root cause engine.
 *
 * Findings are nodes; EDGES say which kind of finding can cause which other
 * kind. An edge only applies when the two findings are related (same peer,
 * same function, or the effect is process-wide like an exit status). Every
 * candidate is scored by how much it explains, weighted by how plausible
 * its kind is as a *root* (an app error is almost always a symptom; a
 * refused connection or runaway recursion is a cause). */
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "callscope/rca.h"

typedef struct {
    const char *cause, *effect;
} edge_t;

static const edge_t EDGES[] = {
    {"net.connect_failure", "app.error"},
    {"net.connect_failure", "cross.error_propagation"},
    {"net.connect_failure", "net.retry_storm"},
    {"net.connect_failure", "fn.slow_call"},
    {"net.connect_failure", "fn.hotspot"},
    {"net.connect_failure", "app.exit_status"},
    {"net.dns_failure", "app.error"},
    {"net.dns_failure", "cross.error_propagation"},
    {"net.dns_failure", "net.connect_failure"},
    {"net.slow_io", "fn.slow_call"},
    {"net.slow_io", "cross.slow_because_network"},
    {"net.slow_io", "fn.hang"},
    {"net.slow_connect", "fn.slow_call"},
    {"net.slow_connect", "cross.slow_because_network"},
    {"net.dns_slow", "fn.slow_call"},
    {"net.dns_slow", "cross.slow_because_network"},
    {"net.reset", "app.error"},
    {"net.reset", "fn.crash"},
    {"net.reset", "cross.error_propagation"},
    {"net.no_response", "app.error"},
    {"net.no_response", "cross.error_propagation"},
    {"net.no_response", "fn.crash"},
    {"net.conn_leak", "net.connect_failure"},
    {"net.conn_leak", "app.error"},
    {"net.conn_leak", "cross.error_propagation"},
    {"fn.recursion", "fn.crash"},
    {"fn.recursion", "app.exit_status"},
    {"cross.error_propagation", "fn.crash"},
    {"cross.error_propagation", "net.reset"},
    {"cross.error_propagation", "app.error"},
    {"cross.error_propagation", "app.exit_status"},
    {"fn.crash", "app.exit_status"},
    {"fn.hotspot", "fn.slow_call"},
    {"app.error", "app.exit_status"},
};

/* How plausible each kind of finding is as the root of a problem. */
static double rootability(const cs_finding *f) {
    const char *d = f->detector;
    if (strcmp(d, "cross.error_propagation") == 0)
        return f->sev == CS_SEV_CRITICAL ? 1.15 : 0.3; /* crash variant = broken error path */
    if (strcmp(d, "net.conn_leak") == 0) return 1.2;
    if (strncmp(d, "net.", 4) == 0) return strcmp(d, "net.retry_storm") == 0 ? 0.5 : 1.0;
    if (strcmp(d, "fn.recursion") == 0) return 1.1;
    if (strcmp(d, "fn.hang") == 0) return 0.8;
    if (strcmp(d, "fn.hotspot") == 0) return 0.8;
    if (strcmp(d, "fn.crash") == 0) return 0.6;
    if (strcmp(d, "fn.slow_call") == 0) return 0.5;
    if (strcmp(d, "cross.slow_because_network") == 0) return 0.4;
    if (strcmp(d, "app.error") == 0) return 0.25;
    return 0.1;
}

static double sev_weight(cs_severity s) {
    static const double w[] = {1.0, 2.0, 4.0, 7.0, 10.0};
    return w[s];
}

static int same(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }

static int related(const cs_finding *c, const cs_finding *e) {
    if (strcmp(e->detector, "app.exit_status") == 0) return 1;
    if (same(c->peer, e->peer)) return 1;
    if (same(c->fn, e->fn)) return 1;
    /* an error raised in a caller of the failing function */
    if (c->fn && e->stack[0] && strstr(e->stack, c->fn)) return 1;
    if (e->fn && c->stack[0] && strstr(c->stack, e->fn) && strcmp(e->detector, "fn.crash") == 0)
        return 1;
    return 0;
}

static int can_cause(const cs_finding *c, const cs_finding *e) {
    if (c == e) return 0;
    for (size_t i = 0; i < sizeof EDGES / sizeof EDGES[0]; i++)
        if (strcmp(EDGES[i].cause, c->detector) == 0 && strcmp(EDGES[i].effect, e->detector) == 0)
            return related(c, e);
    return 0;
}

static void add_line(char (*arr)[300], size_t *n, size_t max, const char *tmpl,
                     const cs_finding *f) {
    if (!tmpl || *n >= max) return;
    cs_kb_render(tmpl, f, arr[*n], sizeof arr[0]);
    for (size_t i = 0; i < *n; i++)
        if (strcmp(arr[i], arr[*n]) == 0) return; /* dedupe */
    (*n)++;
}

int cs_rca_rules(const cs_analysis *a, cs_rca_result *out) {
    memset(out, 0, sizeof(*out));
    snprintf(out->source, sizeof out->source, "rules");
    size_t n = a->findings.len;

    cs_severity max_sev = CS_SEV_INFO;
    for (size_t i = 0; i < n; i++) {
        const cs_finding *f = cs_vec_at(&a->findings, i);
        if (f->sev > max_sev) max_sev = f->sev;
    }
    if (!n || max_sev < CS_SEV_LOW) {
        snprintf(out->summary, sizeof out->summary,
                 "No failures or anomalies were detected in this trace.");
        snprintf(out->explanation, sizeof out->explanation,
                 "All %zu events were analysed: no failed network calls, crashes, runaway "
                 "recursion, slow dependencies or application errors were found.",
                 cs_eventlog_count(a->log));
        snprintf(out->category, sizeof out->category, "healthy");
        out->confidence = 0.9;
        return 0;
    }

    double best = -1, second = -1;
    size_t best_i = 0;
    int best_explained = 0;
    for (size_t i = 0; i < n; i++) {
        const cs_finding *c = cs_vec_at(&a->findings, i);
        int explained = 0;
        for (size_t j = 0; j < n; j++)
            if (can_cause(c, cs_vec_at(&a->findings, j))) explained++;
        double s = rootability(c) *
                   (sev_weight(c->sev) + 2.5 * explained + 0.3 * log2((double)c->count + 1.0));
        if (s > best) {
            second = best;
            best = s;
            best_i = i;
            best_explained = explained;
        } else if (s > second) {
            second = s;
        }
    }

    const cs_finding *root = cs_vec_at(&a->findings, best_i);
    out->found = 1;
    snprintf(out->root_id, sizeof out->root_id, "%s", root->id);

    /* causal chain: root, then everything it explains in time order */
    snprintf(out->chain[out->n_chain++], sizeof out->chain[0], "%s", root->id);
    size_t effects[CS_RCA_MAX_CHAIN];
    size_t ne = 0;
    for (size_t j = 0; j < n && ne < CS_RCA_MAX_CHAIN - 1; j++)
        if (can_cause(root, cs_vec_at(&a->findings, j))) effects[ne++] = j;
    for (size_t x = 1; x < ne; x++) /* insertion sort by first_ts */
        for (size_t y = x; y > 0; y--) {
            const cs_finding *p = cs_vec_at(&a->findings, effects[y - 1]);
            const cs_finding *q = cs_vec_at(&a->findings, effects[y]);
            if (q->first_ts >= p->first_ts) break;
            size_t t = effects[y];
            effects[y] = effects[y - 1];
            effects[y - 1] = t;
        }
    for (size_t k = 0; k < ne; k++)
        snprintf(out->chain[out->n_chain++], sizeof out->chain[0], "%s",
                 ((const cs_finding *)cs_vec_at(&a->findings, effects[k]))->id);

    const cs_kb_entry *kb = cs_kb_lookup(root->detector, root->err);
    char cause[1000];
    if (kb) {
        snprintf(out->category, sizeof out->category, "%s", kb->category);
        cs_kb_render(kb->cause, root, cause, sizeof cause);
        for (int k = 0; k < 4; k++) add_line(out->fixes, &out->n_fixes, CS_RCA_MAX_FIXES, kb->fixes[k], root);
        for (int k = 0; k < 3; k++) add_line(out->checks, &out->n_checks, CS_RCA_MAX_CHECKS, kb->checks[k], root);
    } else {
        snprintf(out->category, sizeof out->category, "unknown");
        snprintf(cause, sizeof cause, "%s", root->title);
    }
    /* fixes from the strongest effect too (e.g. backoff for a retry storm) */
    for (size_t k = 0; k < ne && out->n_fixes < CS_RCA_MAX_FIXES; k++) {
        const cs_finding *e = cs_vec_at(&a->findings, effects[k]);
        const cs_kb_entry *ekb = cs_kb_lookup(e->detector, e->err);
        /* symptoms' generic advice ("profile the slow function") would contradict the root */
        if (ekb && ekb != kb && strcmp(e->detector, "app.error") != 0 &&
            strncmp(e->detector, "fn.slow", 7) != 0 && strncmp(e->detector, "cross.", 6) != 0)
            add_line(out->fixes, &out->n_fixes, CS_RCA_MAX_FIXES, ekb->fixes[0], e);
    }

    /* summary = first sentence of the cause */
    const char *dot = strstr(cause, ". ");
    size_t slen = dot ? (size_t)(dot - cause + 1) : strlen(cause);
    if (slen >= sizeof out->summary) slen = sizeof out->summary - 1;
    memcpy(out->summary, cause, slen);
    out->summary[slen] = '\0';

    size_t len = (size_t)snprintf(out->explanation, sizeof out->explanation, "%s", cause);
    if (root->stack[0] && len < sizeof out->explanation)
        len += (size_t)snprintf(out->explanation + len, sizeof out->explanation - len,
                                " Where: %s.", root->stack);
    if (ne && len < sizeof out->explanation)
        len += (size_t)snprintf(out->explanation + len, sizeof out->explanation - len,
                                " It explains %zu other finding%s:", ne, ne == 1 ? "" : "s");
    for (size_t k = 0; k < ne && len < sizeof out->explanation; k++) {
        const cs_finding *e = cs_vec_at(&a->findings, effects[k]);
        len += (size_t)snprintf(out->explanation + len, sizeof out->explanation - len,
                                " [%s] %s;", e->id, e->title);
    }
    if (len >= sizeof out->explanation) out->explanation[sizeof out->explanation - 1] = '\0';

    double margin = second > 0 ? (best - second) / best : 1.0;
    double conf = 0.45 + 0.1 * (best_explained > 4 ? 4 : best_explained) +
                  (margin > 0.25 ? 0.1 : 0.0) + (kb && kb->err ? 0.05 : 0.0);
    if (root->sev <= CS_SEV_LOW) conf -= 0.15;
    if (conf > 0.95) conf = 0.95;
    if (conf < 0.3) conf = 0.3;
    out->confidence = conf;
    return 0;
}
