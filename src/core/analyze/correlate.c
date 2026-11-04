/* Cross-level analysis: where function-level and network-level evidence meet.
 *
 * 1. cs_correlate_net_time: every network call has a duration and (thanks to
 *    the call tree) an enclosing frame. We charge that time to the frame and
 *    all its ancestors, so each function knows how much of its time was
 *    spent waiting on the network.
 * 2. cs_detect_cross: turns those links into findings that explain *why*:
 *    "charge_payment is slow because 97% of its time is a recv from :9102",
 *    "ECONNREFUSED from :9102 propagated into PAYMENT_UNAVAILABLE errors". */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "callscope/timeutil.h"
#include "internal.h"

void cs_correlate_net_time(cs_analysis *a) {
    size_t n = cs_eventlog_count(a->log);
    for (size_t i = 0; i < n; i++) {
        const cs_event *ev = cs_eventlog_at(a->log, i);
        if (!cs_event_is_net(ev->kind) || ev->kind == CS_EV_NET_CLOSE || ev->dur <= 0) continue;
        size_t f = a->tree.ev_frame[i];
        if (f == CS_NONE) continue;
        cs_frame *inner = cs_vec_at(&a->tree.frames, f);
        inner->net_self += ev->dur;
        for (; f != CS_NONE; f = ((cs_frame *)cs_vec_at(&a->tree.frames, f))->parent) {
            cs_frame *fr = cs_vec_at(&a->tree.frames, f);
            fr->net_wait += ev->dur;
        }
    }
}

/* Is frame `anc` an ancestor of (or equal to) frame f? */
static int within(const cs_analysis *a, size_t f, size_t anc) {
    for (; f != CS_NONE; f = cs_calltree_frame(&a->tree, f)->parent)
        if (f == anc) return 1;
    return 0;
}

/* Which peer dominates the network time inside a frame? */
static const char *dominant_peer(const cs_analysis *a, size_t frame, int64_t *ns, size_t *ev_out) {
    const cs_frame *fr = cs_calltree_frame(&a->tree, frame);
    const char *peers[16];
    int64_t tot[16];
    size_t first[16];
    int np = 0;
    size_t lo = fr->enter_ev, hi = fr->exit_ev != CS_NONE ? fr->exit_ev : cs_eventlog_count(a->log);
    for (size_t i = lo; i < hi; i++) {
        const cs_event *ev = cs_eventlog_at(a->log, i);
        if (!cs_event_is_net(ev->kind) || ev->kind == CS_EV_NET_CLOSE || ev->dur <= 0) continue;
        if (ev->tid != fr->tid || !within(a, a->tree.ev_frame[i], frame)) continue;
        const char *p = ev->kind == CS_EV_NET_DNS ? ev->host : ev->peer;
        if (!p) continue;
        int k;
        for (k = 0; k < np; k++)
            if (peers[k] == p) break;
        if (k == np) {
            if (np == 16) continue;
            peers[np] = p;
            tot[np] = 0;
            first[np] = i;
            np++;
        }
        tot[k] += ev->dur;
    }
    int best = -1;
    for (int k = 0; k < np; k++)
        if (best < 0 || tot[k] > tot[best]) best = k;
    if (best < 0) return NULL;
    if (ns) *ns = tot[best];
    if (ev_out) *ev_out = first[best];
    return peers[best];
}

static void cross_slow_due_to_network(cs_analysis *a) {
    size_t n = a->findings.len;
    for (size_t i = 0; i < n; i++) {
        cs_finding *slow = cs_vec_at(&a->findings, i);
        if (strcmp(slow->detector, "fn.slow_call") != 0 || !slow->fn) continue;
        const cs_fnstat *st = cs_fnstats_find(&a->fns, slow->fn);
        if (!st) continue;
        const cs_frame *fr = cs_calltree_frame(&a->tree, st->slowest_frame);
        if (fr->incl <= 0) continue;
        double share = (double)fr->net_wait / (double)fr->incl;
        if (share < a->opts.net_wait_share) continue;
        int64_t peer_ns = 0;
        size_t ev = CS_NONE;
        const char *peer = dominant_peer(a, st->slowest_frame, &peer_ns, &ev);
        if (!peer) continue;
        cs_finding *f = cs_analysis_add_finding(a, "cross.slow_because_network", CS_LEVEL_CROSS,
                                                slow->sev);
        if (!f) return;
        slow = cs_vec_at(&a->findings, i); /* re-fetch: the vector may have moved */
        cs_finding_set_frame(a, f, st->slowest_frame);
        f->peer = peer;
        f->value = share;
        f->count = slow->count;
        f->first_ts = fr->start;
        f->last_ts = fr->end;
        cs_finding_add_evidence(f, fr->enter_ev);
        cs_finding_add_evidence(f, ev);
        cs_finding_add_evidence(f, fr->exit_ev);
        char d1[32], d2[32];
        snprintf(f->title, sizeof f->title,
                 "%s is slow because it waits on %s (%.0f%% of its time)", slow->fn, peer,
                 share * 100.0);
        snprintf(f->detail, sizeof f->detail,
                 "In its slowest call, %s ran for %s and %s of that was spent blocked in "
                 "network calls to %s. The code itself is fast; the dependency is slow. Fix the "
                 "dependency, add a timeout, or move the call off the critical path "
                 "(async/caching).",
                 slow->fn, cs_fmt_dur(fr->incl, d1, sizeof d1),
                 cs_fmt_dur(peer_ns, d2, sizeof d2), peer);
    }
}

typedef struct {
    const char *net_detector;
    const char *peer;
    const char *err;
    const char *effect; /* app error code or signal name */
    int is_crash;
    int64_t count;
    size_t cause_ev, effect_ev;
    int64_t gap;
} link_t;

static int net_failure(const cs_event *ev) {
    switch (ev->kind) {
    case CS_EV_NET_CONNECT: return ev->rc < 0;
    case CS_EV_NET_SEND:
    case CS_EV_NET_RECV: return ev->rc < 0 || (ev->kind == CS_EV_NET_RECV && ev->rc == 0 && ev->dur >= 0);
    case CS_EV_NET_DNS: return ev->rc != 0;
    default: return 0;
    }
}

static void cross_error_propagation(cs_analysis *a) {
    link_t links[32];
    int nl = 0;
    size_t n = cs_eventlog_count(a->log);
    for (size_t i = 0; i < n; i++) {
        const cs_event *eff = cs_eventlog_at(a->log, i);
        int is_crash = eff->kind == CS_EV_SIGNAL;
        if (eff->kind != CS_EV_APP_ERROR && !is_crash) continue;
        /* walk back on the same thread for the most recent network failure */
        size_t cause = CS_NONE;
        for (size_t j = i; j-- > 0;) {
            const cs_event *c = cs_eventlog_at(a->log, j);
            if (eff->ts - c->ts > a->opts.error_link_ns) break;
            if (c->pid != eff->pid || c->tid != eff->tid) continue;
            if (cs_event_is_net(c->kind) && net_failure(c)) {
                cause = j;
                break;
            }
        }
        if (cause == CS_NONE) continue;
        const cs_event *c = cs_eventlog_at(a->log, cause);
        const char *peer = c->kind == CS_EV_NET_DNS ? c->host : c->peer;
        const char *err = c->err ? c->err : (c->err_no ? cs_errno_name(c->err_no) : "EOF");
        const char *effect = is_crash ? (cs_signal_name(eff->sig) ? cs_signal_name(eff->sig) : "crash")
                                      : (eff->code ? eff->code : "error");
        int k;
        for (k = 0; k < nl; k++)
            if (links[k].peer == peer && strcmp(links[k].err, err) == 0 &&
                strcmp(links[k].effect, effect) == 0)
                break;
        if (k == nl) {
            if (nl == 32) continue;
            links[nl] = (link_t){NULL, peer, err, effect, is_crash, 0, cause, i, eff->ts - c->ts};
            nl++;
        }
        links[k].count++;
    }

    for (int k = 0; k < nl; k++) {
        link_t *l = &links[k];
        cs_finding *f = cs_analysis_add_finding(a, "cross.error_propagation", CS_LEVEL_CROSS,
                                                l->is_crash ? CS_SEV_CRITICAL : CS_SEV_HIGH);
        if (!f) return;
        f->peer = l->peer;
        f->err = l->err;
        f->count = l->count;
        f->value = (double)l->gap;
        f->first_ts = cs_eventlog_at(a->log, l->cause_ev)->ts;
        f->last_ts = cs_eventlog_at(a->log, l->effect_ev)->ts;
        cs_finding_add_evidence(f, l->cause_ev);
        cs_finding_add_evidence(f, l->effect_ev);
        cs_finding_set_context(a, f, l->effect_ev);
        char d[32];
        cs_fmt_dur(l->gap, d, sizeof d);
        if (l->is_crash) {
            snprintf(f->title, sizeof f->title, "%s from %s was followed by a %s crash %s later",
                     l->err, l->peer ? l->peer : "the network", l->effect, d);
            snprintf(f->detail, sizeof f->detail,
                     "The network call failed and the process crashed on the same thread "
                     "shortly after. The failure itself is expected occasionally; the crash "
                     "means the error-handling path is broken (e.g. a NULL response used "
                     "without a check). Fix the error path, then the dependency.");
        } else {
            snprintf(f->title, sizeof f->title, "%s from %s caused %lld %s error%s", l->err,
                     l->peer ? l->peer : "the network", (long long)l->count, l->effect,
                     l->count == 1 ? "" : "s");
            snprintf(f->detail, sizeof f->detail,
                     "Each %s application error was preceded on the same thread (within %s) "
                     "by a %s network failure talking to %s. The application error is a "
                     "symptom; the network dependency is the cause.",
                     l->effect, d, l->err, l->peer ? l->peer : "the network");
        }
    }
}

void cs_detect_cross(cs_analysis *a) {
    cross_slow_due_to_network(a);
    cross_error_propagation(a);
}
