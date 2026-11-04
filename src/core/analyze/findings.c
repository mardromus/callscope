/* Finding bookkeeping shared by every detector. */
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "internal.h"

const char *cs_severity_name(cs_severity s) {
    static const char *const n[] = {"info", "low", "medium", "high", "critical"};
    return (s >= CS_SEV_INFO && s <= CS_SEV_CRITICAL) ? n[s] : "info";
}

const char *cs_level_name(cs_level l) {
    static const char *const n[] = {"function", "network", "application", "cross-level"};
    return (l >= CS_LEVEL_FUNCTION && l <= CS_LEVEL_CROSS) ? n[l] : "function";
}

static double sev_weight(cs_severity s) {
    static const double w[] = {1.0, 2.0, 4.0, 7.0, 10.0};
    return w[s];
}

cs_finding *cs_analysis_add_finding(cs_analysis *a, const char *detector, cs_level level,
                                    cs_severity sev) {
    cs_finding *f = cs_vec_push_slot(&a->findings);
    if (!f) return NULL;
    f->detector = detector;
    f->level = level;
    f->sev = sev;
    f->pid = f->tid = -1;
    f->count = 1;
    f->score = sev_weight(sev);
    return f;
}

void cs_finding_add_evidence(cs_finding *f, size_t ev_index) {
    if (ev_index == CS_NONE) return;
    for (size_t i = 0; i < f->n_evidence; i++)
        if (f->evidence[i] == ev_index) return;
    if (f->n_evidence < CS_MAX_EVIDENCE) f->evidence[f->n_evidence++] = ev_index;
}

void cs_finding_set_frame(const cs_analysis *a, cs_finding *f, size_t frame) {
    if (frame == CS_NONE) return;
    const cs_frame *fr = cs_calltree_frame(&a->tree, frame);
    if (!fr) return;
    f->fn = fr->fn;
    if (f->pid < 0) {
        f->pid = fr->pid;
        f->tid = fr->tid;
    }
    cs_calltree_stack_str(&a->tree, frame, f->stack, sizeof f->stack);
}

void cs_finding_set_context(const cs_analysis *a, cs_finding *f, size_t ev_index) {
    if (ev_index == CS_NONE || ev_index >= a->tree.n_events) return;
    const cs_event *ev = cs_eventlog_at(a->log, ev_index);
    if (f->pid < 0) {
        f->pid = ev->pid;
        f->tid = ev->tid;
    }
    cs_finding_set_frame(a, f, a->tree.ev_frame[ev_index]);
}

const cs_finding *cs_analysis_finding(const cs_analysis *a, const char *id) {
    for (size_t i = 0; i < a->findings.len; i++) {
        const cs_finding *f = cs_vec_at(&a->findings, i);
        if (strcmp(f->id, id) == 0) return f;
    }
    return NULL;
}

/* score = severity weight + log2(occurrences) + bonus for explanatory findings */
void cs_findings_finalize(cs_analysis *a);
static int cmp_score(const void *x, const void *y) {
    const cs_finding *a = x, *b = y;
    if (a->score != b->score) return a->score < b->score ? 1 : -1;
    if (a->first_ts != b->first_ts) return a->first_ts < b->first_ts ? -1 : 1;
    return strcmp(a->detector, b->detector);
}

void cs_findings_finalize(cs_analysis *a) {
    for (size_t i = 0; i < a->findings.len; i++) {
        cs_finding *f = cs_vec_at(&a->findings, i);
        f->score = sev_weight(f->sev) + log2((double)(f->count > 0 ? f->count : 1) + 1.0) * 0.5;
        if (f->level == CS_LEVEL_CROSS) f->score += 1.5;
    }
    cs_vec_sort(&a->findings, cmp_score);
    for (size_t i = 0; i < a->findings.len; i++) {
        cs_finding *f = cs_vec_at(&a->findings, i);
        snprintf(f->id, sizeof f->id, "F%02u", (unsigned)(i + 1));
    }
}
