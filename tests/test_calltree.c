#include "cstest.h"

#include "callscope/analyze.h"

static void add(cs_eventlog *log, int64_t ts, int tid, cs_event_kind k, const char *fn,
                int64_t dur) {
    cs_event ev;
    cs_event_init(&ev, k);
    ev.ts = ts;
    ev.pid = 1;
    ev.tid = tid;
    ev.fn = fn;
    ev.dur = dur;
    cs_eventlog_add(log, &ev);
}

/* main(0..100) { a(10..40) { b(20..30) }  a(50..90) }  on tid 1
 * worker(5..?) never returns on tid 2 */
static void build_sample(cs_eventlog *log) {
    cs_eventlog_init(log);
    add(log, 0, 1, CS_EV_FN_ENTER, "main", -1);
    add(log, 5, 2, CS_EV_FN_ENTER, "worker", -1);
    add(log, 10, 1, CS_EV_FN_ENTER, "a", -1);
    add(log, 20, 1, CS_EV_FN_ENTER, "b", -1);
    add(log, 25, 1, CS_EV_APP_ERROR, NULL, -1);
    add(log, 30, 1, CS_EV_FN_EXIT, "b", 10);
    add(log, 40, 1, CS_EV_FN_EXIT, "a", 30);
    add(log, 50, 1, CS_EV_FN_ENTER, "a", -1);
    add(log, 60, 2, CS_EV_APP_LOG, NULL, -1);
    add(log, 90, 1, CS_EV_FN_EXIT, "a", 40);
    add(log, 100, 1, CS_EV_FN_EXIT, "main", 100);
    cs_eventlog_finish(log);
}

CS_TEST(calltree_rebuilds_frames_and_times) {
    cs_eventlog log;
    build_sample(&log);
    cs_calltree t;
    CS_ASSERT_EQ_INT(cs_calltree_build(&t, &log), 0);
    CS_ASSERT_EQ_INT(t.frames.len, 5);
    CS_ASSERT_EQ_INT(t.max_depth, 2);
    CS_ASSERT_EQ_INT(t.n_threads, 2);

    const cs_frame *main_f = cs_calltree_frame(&t, 0);
    CS_ASSERT_EQ_STR(main_f->fn, "main");
    CS_ASSERT_EQ_INT(main_f->incl, 100);
    CS_ASSERT_EQ_INT(main_f->excl, 100 - 30 - 40);
    CS_ASSERT_EQ_INT(main_f->n_children, 2);

    const cs_frame *b = cs_calltree_frame(&t, 3);
    CS_ASSERT_EQ_STR(b->fn, "b");
    CS_ASSERT_EQ_INT(b->depth, 2);
    CS_ASSERT_EQ_INT(b->incl, 10);

    /* the app error at ts=25 happened inside b */
    CS_ASSERT_EQ_INT(t.ev_frame[4], 3);
    char buf[128];
    cs_calltree_stack_str(&t, t.ev_frame[4], buf, sizeof buf);
    CS_ASSERT_EQ_STR(buf, "main > a > b");

    /* worker never returned */
    const cs_frame *w = cs_calltree_frame(&t, 1);
    CS_ASSERT_EQ_STR(w->fn, "worker");
    CS_ASSERT(w->open);
    CS_ASSERT_EQ_INT(w->incl, 55);
    CS_ASSERT_EQ_INT(t.n_open, 1);
    cs_calltree_free(&t);
    cs_eventlog_free(&log);
}

CS_TEST(calltree_handles_nonlocal_exit) {
    cs_eventlog log;
    cs_eventlog_init(&log);
    add(&log, 0, 1, CS_EV_FN_ENTER, "main", -1);
    add(&log, 10, 1, CS_EV_FN_ENTER, "parse", -1);
    add(&log, 20, 1, CS_EV_FN_ENTER, "deep", -1);
    /* longjmp from deep straight back to main: only main's exit is seen */
    add(&log, 50, 1, CS_EV_FN_EXIT, "main", 50);
    add(&log, 60, 1, CS_EV_FN_EXIT, "ghost", 5); /* exit without enter: ignored */
    cs_eventlog_finish(&log);
    cs_calltree t;
    CS_ASSERT_EQ_INT(cs_calltree_build(&t, &log), 0);
    CS_ASSERT_EQ_INT(t.frames.len, 3);
    CS_ASSERT(cs_calltree_frame(&t, 2)->unwound);
    CS_ASSERT(!cs_calltree_frame(&t, 2)->open);
    CS_ASSERT_EQ_INT(t.n_open, 0);
    cs_calltree_free(&t);
    cs_eventlog_free(&log);
}

CS_TEST(fnstats_aggregates_per_function) {
    cs_eventlog log;
    build_sample(&log);
    cs_calltree t;
    cs_calltree_build(&t, &log);
    cs_fnstats s;
    CS_ASSERT_EQ_INT(cs_fnstats_build(&s, &t), 0);
    const cs_fnstat *a = cs_fnstats_find(&s, "a");
    CS_ASSERT(a != NULL);
    CS_ASSERT_EQ_INT(a->calls, 2);
    CS_ASSERT_EQ_INT(a->incl_total, 70);
    CS_ASSERT_EQ_INT(a->excl_total, 60);
    CS_ASSERT_EQ_INT(a->min, 30);
    CS_ASSERT_EQ_INT(a->max, 40);
    CS_ASSERT_EQ_INT(a->slowest_frame, 4);
    /* sorted by exclusive time: a (60) first, then worker (55) */
    CS_ASSERT_EQ_STR(CS_VEC_AT(&s.stats, cs_fnstat, 0)->fn, "a");
    CS_ASSERT_EQ_STR(CS_VEC_AT(&s.stats, cs_fnstat, 1)->fn, "worker");
    CS_ASSERT(cs_fnstats_find(&s, "nope") == NULL);
    cs_fnstats_free(&s);
    cs_calltree_free(&t);
    cs_eventlog_free(&log);
}
