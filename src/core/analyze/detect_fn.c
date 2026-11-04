/* Function-level detectors: crashes, hangs, runaway recursion, slow calls and
 * CPU hotspots. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "callscope/timeutil.h"
#include "internal.h"

static void detect_crash(cs_analysis *a) {
    size_t n = cs_eventlog_count(a->log);
    int reported = 0;
    for (size_t i = 0; i < n && reported < 3; i++) {
        const cs_event *ev = cs_eventlog_at(a->log, i);
        int is_sig = ev->kind == CS_EV_SIGNAL;
        int is_killed = ev->kind == CS_EV_PROC_EXIT && ev->sig > 0;
        if (!is_sig && !is_killed) continue;
        if (is_killed && a->n_signals) continue; /* already covered by the signal event */
        const char *sn = cs_signal_name(ev->sig);
        cs_finding *f = cs_analysis_add_finding(a, "fn.crash", CS_LEVEL_FUNCTION, CS_SEV_CRITICAL);
        if (!f) return;
        cs_finding_set_context(a, f, i);
        f->first_ts = f->last_ts = ev->ts;
        f->value = ev->sig;
        cs_finding_add_evidence(f, i);
        if (f->fn) {
            snprintf(f->title, sizeof f->title, "Process crashed with %s inside %s",
                     sn ? sn : "a fatal signal", f->fn);
            snprintf(f->detail, sizeof f->detail,
                     "Signal %d was delivered while the call path below was still on the stack. "
                     "The innermost frame is where the fault happened; frames above it are "
                     "the callers that led there.",
                     ev->sig);
        } else {
            snprintf(f->title, sizeof f->title, "Process was killed by %s",
                     sn ? sn : "a fatal signal");
            snprintf(f->detail, sizeof f->detail,
                     "No function-level trace was active, so the exact crash site is unknown. "
                     "Rebuild with -finstrument-functions to see the call path.");
        }
        reported++;
    }
}

/* Frames still open at the end of the trace without a crash may be a hang. */
static void detect_hang(cs_analysis *a) {
    if (a->crashed || !a->tree.n_open) return;
    size_t best = CS_NONE;
    int64_t best_open = 0;
    for (size_t i = 0; i < a->tree.frames.len; i++) {
        const cs_frame *fr = cs_calltree_frame(&a->tree, i);
        if (!fr->open || fr->n_children) continue; /* innermost open frames only */
        if (fr->incl > best_open) {
            best_open = fr->incl;
            best = i;
        }
    }
    if (best == CS_NONE || best_open < a->opts.slow_min_ns) return;
    const cs_frame *fr = cs_calltree_frame(&a->tree, best);
    cs_finding *f = cs_analysis_add_finding(a, "fn.hang", CS_LEVEL_FUNCTION,
                                            best_open >= CS_NS_PER_S ? CS_SEV_HIGH : CS_SEV_MEDIUM);
    if (!f) return;
    cs_finding_set_frame(a, f, best);
    f->first_ts = fr->start;
    f->last_ts = fr->end;
    f->value = (double)best_open;
    f->count = (int64_t)a->tree.n_open;
    cs_finding_add_evidence(f, fr->enter_ev);
    char d[32];
    snprintf(f->title, sizeof f->title, "%s never returned (open for %s when the trace ended)",
             fr->fn, cs_fmt_dur(best_open, d, sizeof d));
    snprintf(f->detail, sizeof f->detail,
             "%zu call(s) were still on the stack at the end of the trace and no crash was "
             "recorded. The process was probably blocked here (waiting on I/O, a lock, or an "
             "infinite loop) or was stopped externally.",
             a->tree.n_open);
}

static void detect_recursion(cs_analysis *a) {
    int limit = a->opts.recursion_limit;
    cs_hashmap deepest;
    cs_hm_init(&deepest);
    for (size_t i = 0; i < a->tree.frames.len; i++) {
        const cs_frame *fr = cs_calltree_frame(&a->tree, i);
        if (fr->depth < limit) continue;
        void **slot = cs_hm_slot(&deepest, fr->fn);
        if (!slot) break;
        size_t cur = (size_t)(uintptr_t)*slot;
        if (!cur || cs_calltree_frame(&a->tree, cur - 1)->depth < fr->depth)
            *slot = (void *)(uintptr_t)(i + 1);
    }
    size_t it = 0, reported = 0;
    cs_hm_entry *e;
    while (cs_hm_next(&deepest, &it, &e) && reported < 2) {
        size_t idx = (size_t)(uintptr_t)e->val - 1;
        const cs_frame *fr = cs_calltree_frame(&a->tree, idx);
        int same = 0;
        for (size_t p = idx; p != CS_NONE; p = cs_calltree_frame(&a->tree, p)->parent)
            if (cs_calltree_frame(&a->tree, p)->fn == fr->fn) same++;
        if (same < limit / 2) continue;
        cs_finding *f = cs_analysis_add_finding(a, "fn.recursion", CS_LEVEL_FUNCTION,
                                                (fr->open && a->crashed) ? CS_SEV_CRITICAL
                                                                         : CS_SEV_HIGH);
        if (!f) break;
        cs_finding_set_frame(a, f, idx);
        /* the full path is hundreds of frames of the same name: summarise it */
        snprintf(f->stack, sizeof f->stack, "%s > ... (%d nested calls) ... > %s", "...", same,
                 fr->fn);
        f->value = same;
        f->threshold = limit;
        f->count = same;
        f->first_ts = fr->start;
        f->last_ts = fr->end;
        cs_finding_add_evidence(f, fr->enter_ev);
        snprintf(f->title, sizeof f->title, "Runaway recursion: %s nested %d times (depth %d)",
                 fr->fn, same, fr->depth);
        snprintf(f->detail, sizeof f->detail,
                 "%s calls itself %d times on a single stack. This usually means a missing or "
                 "unreachable base case, or a cycle in the data being walked. Deep recursion "
                 "exhausts the stack and ends in SIGSEGV.",
                 fr->fn, same);
        reported++;
    }
    cs_hm_free(&deepest, NULL);
}

static int cmp_max_desc(const void *x, const void *y) {
    const cs_fnstat *a = *(const cs_fnstat *const *)x, *b = *(const cs_fnstat *const *)y;
    return (a->max < b->max) - (a->max > b->max);
}

/* A frame is "pass-through" when one child explains nearly all of its time:
 * report the child instead of every ancestor on the slow path. */
static int is_pass_through(const cs_analysis *a, size_t frame) {
    const cs_frame *fr = cs_calltree_frame(&a->tree, frame);
    if (!fr->n_children || fr->incl <= 0) return 0;
    int64_t best = 0;
    for (size_t i = frame + 1; i < a->tree.frames.len; i++) {
        const cs_frame *c = cs_calltree_frame(&a->tree, i);
        if (c->start > fr->end) break;
        if (c->parent == frame && c->incl > best) best = c->incl;
    }
    return best >= (fr->incl * 8) / 10;
}

static void detect_slow(cs_analysis *a) {
    size_t n = a->fns.stats.len;
    if (!n) return;
    const cs_fnstat **order = malloc(n * sizeof(*order));
    if (!order) return;
    for (size_t i = 0; i < n; i++) order[i] = cs_vec_at(&a->fns.stats, i);
    qsort(order, n, sizeof(*order), cmp_max_desc);

    int reported = 0;
    for (size_t i = 0; i < n && i < 25 && reported < a->opts.max_per_detector; i++) {
        const cs_fnstat *st = order[i];
        if (st->max < a->opts.slow_min_ns) break;
        int64_t limit = (int64_t)(a->opts.slow_factor * (double)st->p50);
        if (limit < a->opts.slow_min_ns) limit = a->opts.slow_min_ns;
        if (st->calls >= 3 && st->max < limit) continue;
        if (st->open_frames == st->calls) continue; /* covered by crash / hang */
        if (is_pass_through(a, st->slowest_frame)) continue;
        const cs_frame *sf = cs_calltree_frame(&a->tree, st->slowest_frame);
        /* aggregators (main loops) spread their time over many children */
        if (sf->n_children >= 2 && sf->excl * 5 < sf->incl) continue;

        int64_t slow_calls = 0;
        for (size_t k = 0; k < a->tree.frames.len; k++) {
            const cs_frame *fr = cs_calltree_frame(&a->tree, k);
            if (fr->fn == st->fn && !fr->open && fr->incl >= limit) slow_calls++;
        }
        if (!slow_calls) continue;
        const cs_frame *fr = cs_calltree_frame(&a->tree, st->slowest_frame);
        cs_severity sev = st->max >= CS_NS_PER_S ? CS_SEV_HIGH : CS_SEV_MEDIUM;
        cs_finding *f = cs_analysis_add_finding(a, "fn.slow_call", CS_LEVEL_FUNCTION, sev);
        if (!f) break;
        cs_finding_set_frame(a, f, st->slowest_frame);
        f->first_ts = fr->start;
        f->last_ts = fr->end;
        f->value = (double)st->max;
        f->threshold = (double)limit;
        f->count = slow_calls;
        cs_finding_add_evidence(f, fr->enter_ev);
        cs_finding_add_evidence(f, fr->exit_ev);
        char mx[32], p50[32], p95[32];
        cs_fmt_dur(st->max, mx, sizeof mx);
        cs_fmt_dur(st->p50, p50, sizeof p50);
        cs_fmt_dur(st->p95, p95, sizeof p95);
        snprintf(f->title, sizeof f->title, "%s is slow: up to %s (median %s), %lld slow call%s",
                 st->fn, mx, p50, (long long)slow_calls, slow_calls == 1 ? "" : "s");
        int share = st->incl_total ? (int)(100 * st->net_wait_total / st->incl_total) : 0;
        snprintf(f->detail, sizeof f->detail,
                 "%lld call(s) of %s took longer than %s. p50=%s p95=%s max=%s. "
                 "%d%% of its total time was spent waiting on network calls.",
                 (long long)st->calls, st->fn, cs_fmt_dur(limit, mx, sizeof mx), p50, p95,
                 cs_fmt_dur(st->max, mx, sizeof mx), share);
        reported++;
    }
    free(order);
}

static void detect_hotspot(cs_analysis *a) {
    if (!a->fns.stats.len || a->fns.total_excl <= 0) return;
    /* CPU-side time = exclusive time minus time blocked in network syscalls */
    int64_t total = 0;
    for (size_t i = 0; i < a->fns.stats.len; i++) {
        const cs_fnstat *st = cs_vec_at(&a->fns.stats, i);
        int64_t cpu = st->excl_total - st->net_self_total;
        if (cpu > 0) total += cpu;
    }
    if (total < 10 * CS_NS_PER_MS) return;
    for (size_t i = 0; i < a->fns.stats.len && i < 5; i++) {
        const cs_fnstat *st = cs_vec_at(&a->fns.stats, i);
        int64_t cpu = st->excl_total - st->net_self_total;
        double share = (double)cpu / (double)total;
        if (share < a->opts.hotspot_share) continue;
        cs_finding *f = cs_analysis_add_finding(a, "fn.hotspot", CS_LEVEL_FUNCTION, CS_SEV_LOW);
        if (!f) return;
        cs_finding_set_frame(a, f, st->slowest_frame);
        f->value = share;
        f->threshold = a->opts.hotspot_share;
        f->count = st->calls;
        char d[32];
        snprintf(f->title, sizeof f->title, "Hotspot: %s uses %.0f%% of compute time (%s)", st->fn,
                 share * 100.0, cs_fmt_dur(cpu, d, sizeof d));
        snprintf(f->detail, sizeof f->detail,
                 "%s ran %lld times and accounts for %.0f%% of the time spent executing code "
                 "(excluding time blocked on the network). Optimising or caching it gives the "
                 "biggest speed-up.",
                 st->fn, (long long)st->calls, share * 100.0);
        return;
    }
}

void cs_detect_function(cs_analysis *a) {
    detect_crash(a);
    detect_hang(a);
    detect_recursion(a);
    detect_slow(a);
    detect_hotspot(a);
}
