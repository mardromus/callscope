/* Rebuild per-thread call stacks from fn_enter / fn_exit events.
 *
 * Besides frames, we record for every event the innermost frame that was open
 * on its thread at that moment (ev_frame). That single array is what lets us
 * say "this ECONNREFUSED happened inside charge_payment, called from
 * process_order, called from main" - the bridge between the function level
 * and the network level. */
#include "callscope/analyze.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int32_t pid, tid;
    cs_vec stack; /* size_t frame indices */
    int64_t last_ts;
} thread_state;

static thread_state *thread_for(cs_hashmap *threads, int32_t pid, int32_t tid,
                                thread_state **cache, int32_t *cpid, int32_t *ctid) {
    if (*cache && *cpid == pid && *ctid == tid) return *cache;
    char key[32];
    snprintf(key, sizeof key, "%d:%d", pid, tid);
    void **slot = cs_hm_slot(threads, key);
    if (!slot) return NULL;
    if (!*slot) {
        thread_state *ts = calloc(1, sizeof(*ts));
        if (!ts) return NULL;
        ts->pid = pid;
        ts->tid = tid;
        cs_vec_init(&ts->stack, sizeof(size_t));
        *slot = ts;
    }
    *cache = *slot;
    *cpid = pid;
    *ctid = tid;
    return *cache;
}

static void free_thread(void *p) {
    thread_state *ts = p;
    if (!ts) return;
    cs_vec_free(&ts->stack);
    free(ts);
}

static cs_frame *frame_at(cs_calltree *t, size_t i) { return cs_vec_at(&t->frames, i); }

static size_t stack_top(const thread_state *ts) {
    return ts->stack.len ? *(size_t *)cs_vec_back(&ts->stack) : CS_NONE;
}

int cs_calltree_build(cs_calltree *t, const cs_eventlog *log) {
    memset(t, 0, sizeof(*t));
    cs_vec_init(&t->frames, sizeof(cs_frame));
    t->n_events = cs_eventlog_count(log);
    t->ev_frame = malloc((t->n_events ? t->n_events : 1) * sizeof(size_t));
    if (!t->ev_frame) return -1;

    cs_hashmap threads;
    cs_hm_init(&threads);
    thread_state *cache = NULL;
    int32_t cpid = 0, ctid = 0;

    for (size_t i = 0; i < t->n_events; i++) {
        const cs_event *ev = cs_eventlog_at(log, i);
        thread_state *ts = thread_for(&threads, ev->pid, ev->tid, &cache, &cpid, &ctid);
        if (!ts) goto oom;
        ts->last_ts = ev->ts;
        t->ev_frame[i] = stack_top(ts);

        if (ev->kind == CS_EV_FN_ENTER) {
            size_t parent = stack_top(ts);
            cs_frame *f = cs_vec_push_slot(&t->frames);
            if (!f) goto oom;
            size_t idx = t->frames.len - 1;
            f->fn = ev->fn ? ev->fn : "?";
            f->pid = ev->pid;
            f->tid = ev->tid;
            f->depth = (int32_t)ts->stack.len;
            f->start = ev->ts;
            f->parent = parent;
            f->enter_ev = i;
            f->exit_ev = CS_NONE;
            if (parent != CS_NONE) frame_at(t, parent)->n_children++;
            if (cs_vec_push(&ts->stack, &idx) != 0) goto oom;
            if (f->depth > t->max_depth) t->max_depth = f->depth;
            t->ev_frame[i] = idx;
        } else if (ev->kind == CS_EV_FN_EXIT) {
            /* find the matching frame, tolerating non-local exits */
            size_t match = CS_NONE, pos = 0;
            for (size_t k = ts->stack.len; k-- > 0;) {
                size_t fi = *CS_VEC_AT(&ts->stack, size_t, k);
                const char *fn = frame_at(t, fi)->fn;
                if (fn == ev->fn || (ev->fn && strcmp(fn, ev->fn) == 0)) {
                    match = fi;
                    pos = k;
                    break;
                }
            }
            if (match == CS_NONE) continue; /* exit of a call that began before tracing */
            while (ts->stack.len > pos + 1) {
                size_t fi = *(size_t *)cs_vec_back(&ts->stack);
                cs_frame *u = frame_at(t, fi);
                u->end = ev->ts;
                u->incl = u->end - u->start;
                u->unwound = 1;
                cs_vec_pop(&ts->stack);
            }
            cs_frame *f = frame_at(t, match);
            f->end = ev->ts;
            f->incl = ev->dur >= 0 ? ev->dur : ev->ts - f->start;
            f->exit_ev = i;
            cs_vec_pop(&ts->stack);
            t->ev_frame[i] = match;
        }
    }

    /* whatever is still on a stack never returned */
    size_t it = 0;
    cs_hm_entry *e;
    while (cs_hm_next(&threads, &it, &e)) {
        thread_state *ts = e->val;
        t->n_threads++;
        for (size_t k = 0; k < ts->stack.len; k++) {
            cs_frame *f = frame_at(t, *CS_VEC_AT(&ts->stack, size_t, k));
            f->open = 1;
            f->end = ts->last_ts;
            f->incl = f->end - f->start;
            t->n_open++;
        }
    }

    /* exclusive time = inclusive minus direct children */
    int64_t *child_incl = calloc(t->frames.len ? t->frames.len : 1, sizeof(int64_t));
    if (!child_incl) goto oom;
    for (size_t i = 0; i < t->frames.len; i++) {
        const cs_frame *f = frame_at(t, i);
        if (f->parent != CS_NONE) child_incl[f->parent] += f->incl;
    }
    for (size_t i = 0; i < t->frames.len; i++) {
        cs_frame *f = frame_at(t, i);
        f->excl = f->incl - child_incl[i];
        if (f->excl < 0) f->excl = 0;
    }
    free(child_incl);
    cs_hm_free(&threads, free_thread);
    return 0;

oom:
    cs_hm_free(&threads, free_thread);
    return -1;
}

void cs_calltree_free(cs_calltree *t) {
    cs_vec_free(&t->frames);
    free(t->ev_frame);
    t->ev_frame = NULL;
}

const cs_frame *cs_calltree_frame(const cs_calltree *t, size_t idx) {
    return idx == CS_NONE ? NULL : cs_vec_at(&t->frames, idx);
}

size_t cs_calltree_stack_str(const cs_calltree *t, size_t idx, char *buf, size_t n) {
    if (!n) return 0;
    buf[0] = '\0';
    /* collect run-length encoded names, innermost first:
     * deep recursion becomes "render_template (x300)" */
    enum { MAX_RUNS = 48 };
    const char *names[MAX_RUNS];
    size_t counts[MAX_RUNS];
    size_t k = 0;
    int truncated = 0;
    for (size_t f = idx; f != CS_NONE; f = cs_calltree_frame(t, f)->parent) {
        const char *fn = cs_calltree_frame(t, f)->fn;
        if (k && names[k - 1] == fn) {
            counts[k - 1]++;
            continue;
        }
        if (k == MAX_RUNS) {
            truncated = 1;
            break;
        }
        names[k] = fn;
        counts[k] = 1;
        k++;
    }
    size_t len = 0;
    if (truncated) len += (size_t)snprintf(buf, n, "... > ");
    for (size_t i = k; i-- > 0 && len < n;) {
        int w = counts[i] > 1
                    ? snprintf(buf + len, n - len, "%s (x%zu)%s", names[i], counts[i], i ? " > " : "")
                    : snprintf(buf + len, n - len, "%s%s", names[i], i ? " > " : "");
        if (w < 0) break;
        len += (size_t)w;
    }
    if (len >= n) {
        len = n - 1;
        if (n > 4) memcpy(buf + n - 4, "...", 3);
    }
    return len;
}
