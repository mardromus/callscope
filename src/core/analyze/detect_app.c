/* Application-level detectors: errors reported via cs_error() and abnormal
 * process exits. */
#include <stdio.h>
#include <string.h>

#include "internal.h"

#define MAX_CODES 32

void cs_detect_app(cs_analysis *a) {
    const char *codes[MAX_CODES];
    int64_t counts[MAX_CODES];
    size_t first[MAX_CODES], last[MAX_CODES];
    int nc = 0;
    size_t n = cs_eventlog_count(a->log);

    for (size_t i = 0; i < n; i++) {
        const cs_event *ev = cs_eventlog_at(a->log, i);
        if (ev->kind != CS_EV_APP_ERROR) continue;
        const char *code = ev->code ? ev->code : "ERROR";
        int k;
        for (k = 0; k < nc; k++)
            if (codes[k] == code || strcmp(codes[k], code) == 0) break;
        if (k == nc) {
            if (nc == MAX_CODES) continue;
            codes[nc] = code;
            counts[nc] = 0;
            first[nc] = i;
            nc++;
        }
        counts[k]++;
        last[k] = i;
    }

    for (int k = 0; k < nc; k++) {
        cs_finding *f = cs_analysis_add_finding(a, "app.error", CS_LEVEL_APP,
                                                counts[k] >= 5 ? CS_SEV_HIGH : CS_SEV_MEDIUM);
        if (!f) return;
        const cs_event *e0 = cs_eventlog_at(a->log, first[k]);
        cs_finding_set_context(a, f, first[k]);
        f->err = codes[k];
        f->count = counts[k];
        f->first_ts = e0->ts;
        f->last_ts = cs_eventlog_at(a->log, last[k])->ts;
        cs_finding_add_evidence(f, first[k]);
        cs_finding_add_evidence(f, last[k]);
        snprintf(f->title, sizeof f->title, "Application error %s reported %lld time%s", codes[k],
                 (long long)counts[k], counts[k] == 1 ? "" : "s");
        snprintf(f->detail, sizeof f->detail, "First message: \"%.400s\"",
                 e0->msg ? e0->msg : "");
    }

    for (size_t i = 0; i < n; i++) {
        const cs_event *ev = cs_eventlog_at(a->log, i);
        if (ev->kind != CS_EV_PROC_EXIT || ev->rc == 0 || ev->sig) continue;
        cs_finding *f = cs_analysis_add_finding(a, "app.exit_status", CS_LEVEL_APP, CS_SEV_HIGH);
        if (!f) return;
        f->pid = ev->pid;
        f->tid = ev->tid;
        f->value = (double)ev->rc;
        f->first_ts = f->last_ts = ev->ts;
        cs_finding_add_evidence(f, i);
        snprintf(f->title, sizeof f->title, "Process %d exited with status %lld", ev->pid,
                 (long long)ev->rc);
        snprintf(f->detail, sizeof f->detail,
                 "A non-zero exit status means the program reported failure. Look at the "
                 "highest-ranked findings before the exit for the reason.");
    }
}
