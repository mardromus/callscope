/* Per-function statistics with exact percentiles of inclusive time. */
#include "callscope/analyze.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    cs_fnstat st;
    cs_vec durs; /* int64_t */
} acc_t;

static int cmp_i64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

static int cmp_excl_desc(const void *a, const void *b) {
    const cs_fnstat *x = a, *y = b;
    if (x->excl_total != y->excl_total) return x->excl_total < y->excl_total ? 1 : -1;
    return strcmp(x->fn, y->fn);
}

static int64_t pct(const int64_t *v, size_t n, double p) {
    if (!n) return 0;
    size_t idx = (size_t)(p * (double)(n - 1) + 0.5);
    if (idx >= n) idx = n - 1;
    return v[idx];
}

static void free_acc(void *p) {
    acc_t *a = p;
    if (!a) return;
    cs_vec_free(&a->durs);
    free(a);
}

int cs_fnstats_build(cs_fnstats *s, const cs_calltree *t) {
    memset(s, 0, sizeof(*s));
    cs_vec_init(&s->stats, sizeof(cs_fnstat));
    cs_hashmap m;
    cs_hm_init(&m);

    for (size_t i = 0; i < t->frames.len; i++) {
        const cs_frame *f = cs_calltree_frame(t, i);
        void **slot = cs_hm_slot(&m, f->fn);
        if (!slot) goto oom;
        if (!*slot) {
            acc_t *a = calloc(1, sizeof(*a));
            if (!a) goto oom;
            a->st.fn = f->fn;
            a->st.min = INT64_MAX;
            a->st.slowest_frame = i;
            cs_vec_init(&a->durs, sizeof(int64_t));
            *slot = a;
        }
        acc_t *a = *slot;
        a->st.calls++;
        a->st.incl_total += f->incl;
        a->st.excl_total += f->excl;
        a->st.net_wait_total += f->net_wait;
        if (f->open) a->st.open_frames++;
        if (f->depth > a->st.max_depth) a->st.max_depth = f->depth;
        if (f->incl < a->st.min) a->st.min = f->incl;
        if (f->incl > a->st.max) {
            a->st.max = f->incl;
            a->st.slowest_frame = i;
        }
        if (cs_vec_push(&a->durs, &f->incl) != 0) goto oom;
        s->total_excl += f->excl;
    }

    size_t it = 0;
    cs_hm_entry *e;
    while (cs_hm_next(&m, &it, &e)) {
        acc_t *a = e->val;
        cs_vec_sort(&a->durs, cmp_i64);
        const int64_t *v = a->durs.data;
        a->st.p50 = pct(v, a->durs.len, 0.50);
        a->st.p95 = pct(v, a->durs.len, 0.95);
        a->st.p99 = pct(v, a->durs.len, 0.99);
        if (a->st.min == INT64_MAX) a->st.min = 0;
        if (cs_vec_push(&s->stats, &a->st) != 0) goto oom;
    }
    cs_vec_sort(&s->stats, cmp_excl_desc);
    cs_hm_free(&m, free_acc);
    return 0;
oom:
    cs_hm_free(&m, free_acc);
    return -1;
}

void cs_fnstats_free(cs_fnstats *s) { cs_vec_free(&s->stats); }

const cs_fnstat *cs_fnstats_find(const cs_fnstats *s, const char *fn) {
    for (size_t i = 0; i < s->stats.len; i++) {
        const cs_fnstat *st = cs_vec_at(&s->stats, i);
        if (strcmp(st->fn, fn) == 0) return st;
    }
    return NULL;
}
