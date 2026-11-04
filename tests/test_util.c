#include "cstest.h"

#include "callscope/hashmap.h"
#include "callscope/strbuf.h"
#include "callscope/timeutil.h"
#include "callscope/vec.h"

#include <stdint.h>
#include <stdlib.h>

CS_TEST(strbuf_appends_and_formats) {
    cs_strbuf sb;
    cs_sb_init(&sb);
    CS_ASSERT_EQ_STR(cs_sb_cstr(&sb), "");
    cs_sb_append(&sb, "hello");
    cs_sb_appendc(&sb, ' ');
    cs_sb_appendf(&sb, "%s #%d", "world", 42);
    CS_ASSERT_EQ_STR(cs_sb_cstr(&sb), "hello world #42");
    CS_ASSERT_EQ_INT(sb.len, 15);
    cs_sb_clear(&sb);
    CS_ASSERT_EQ_STR(cs_sb_cstr(&sb), "");
    cs_sb_free(&sb);
}

CS_TEST(strbuf_grows_past_initial_capacity) {
    cs_strbuf sb;
    cs_sb_init(&sb);
    for (int i = 0; i < 1000; i++) cs_sb_append(&sb, "abcdefghij");
    CS_ASSERT_EQ_INT(sb.len, 10000);
    CS_ASSERT(sb.cap > sb.len);
    char *owned = cs_sb_steal(&sb);
    CS_ASSERT(owned[9999] == 'j');
    CS_ASSERT(sb.data == NULL);
    free(owned);
}

CS_TEST(strbuf_escapes_html) {
    cs_strbuf sb;
    cs_sb_init(&sb);
    cs_sb_append_html(&sb, "<a href=\"x\">Tom & 'Jerry'</a>");
    CS_ASSERT_EQ_STR(cs_sb_cstr(&sb),
                     "&lt;a href=&quot;x&quot;&gt;Tom &amp; &#39;Jerry&#39;&lt;/a&gt;");
    cs_sb_free(&sb);
}

static int cmp_int(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

CS_TEST(vec_push_sort_and_pop) {
    cs_vec v;
    cs_vec_init(&v, sizeof(int));
    int vals[] = {5, 3, 9, 1, 7};
    for (int i = 0; i < 5; i++) cs_vec_push(&v, &vals[i]);
    CS_ASSERT_EQ_INT(v.len, 5);
    cs_vec_sort(&v, cmp_int);
    CS_ASSERT_EQ_INT(*CS_VEC_AT(&v, int, 0), 1);
    CS_ASSERT_EQ_INT(*CS_VEC_AT(&v, int, 4), 9);
    cs_vec_pop(&v);
    CS_ASSERT_EQ_INT(*(int *)cs_vec_back(&v), 7);
    CS_ASSERT(cs_vec_at(&v, 99) == NULL);
    int *slot = cs_vec_push_slot(&v);
    CS_ASSERT(slot && *slot == 0);
    cs_vec_free(&v);
}

CS_TEST(hashmap_put_get_and_grow) {
    cs_hashmap m;
    cs_hm_init(&m);
    char key[32];
    for (intptr_t i = 0; i < 500; i++) {
        snprintf(key, sizeof key, "fn_%ld", (long)i);
        CS_ASSERT_EQ_INT(cs_hm_put(&m, key, (void *)(i + 1)), 0);
    }
    CS_ASSERT_EQ_INT(m.len, 500);
    CS_ASSERT((intptr_t)cs_hm_get(&m, "fn_0") == 1);
    CS_ASSERT((intptr_t)cs_hm_get(&m, "fn_499") == 500);
    CS_ASSERT(cs_hm_get(&m, "missing") == NULL);

    void **slot = cs_hm_slot(&m, "fn_10");
    CS_ASSERT((intptr_t)*slot == 11);
    *slot = (void *)77;
    CS_ASSERT((intptr_t)cs_hm_get(&m, "fn_10") == 77);
    CS_ASSERT_EQ_INT(m.len, 500);

    size_t it = 0, seen = 0;
    cs_hm_entry *e;
    while (cs_hm_next(&m, &it, &e)) seen++;
    CS_ASSERT_EQ_INT(seen, 500);
    cs_hm_free(&m, NULL);
}

CS_TEST(time_formatting) {
    char buf[64];
    CS_ASSERT_EQ_STR(cs_fmt_dur(850, buf, sizeof buf), "850 ns");
    CS_ASSERT_EQ_STR(cs_fmt_dur(12400, buf, sizeof buf), "12.4 us");
    CS_ASSERT_EQ_STR(cs_fmt_dur(3210000, buf, sizeof buf), "3.21 ms");
    CS_ASSERT_EQ_STR(cs_fmt_dur(1800000000LL, buf, sizeof buf), "1.80 s");
    CS_ASSERT_EQ_STR(cs_fmt_bytes(4096, buf, sizeof buf), "4.0 KiB");
    /* 2026-11-04T00:00:00Z */
    CS_ASSERT_EQ_STR(cs_fmt_ts(1793750400LL * CS_NS_PER_S + 123456000, buf, sizeof buf),
                     "2026-11-04T00:00:00.123456Z");
    CS_ASSERT(cs_now_ns() > 1700000000LL * CS_NS_PER_S);
}
