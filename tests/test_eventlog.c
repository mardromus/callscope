#include "cstest.h"

#include "callscope/eventlog.h"
#include "callscope/json.h"

#include <errno.h>
#include <stdlib.h>

CS_TEST(event_kind_names_roundtrip) {
    for (int k = 1; k < CS_EV__COUNT; k++)
        CS_ASSERT_EQ_INT(cs_event_kind_parse(cs_event_kind_name((cs_event_kind)k)), k);
    CS_ASSERT_EQ_INT(cs_event_kind_parse("nope"), CS_EV_UNKNOWN);
    CS_ASSERT(cs_event_is_net(CS_EV_NET_DNS));
    CS_ASSERT(!cs_event_is_net(CS_EV_FN_EXIT));
    CS_ASSERT_EQ_STR(cs_errno_name(ECONNREFUSED), "ECONNREFUSED");
    CS_ASSERT_EQ_INT(cs_errno_from_name("ETIMEDOUT"), ETIMEDOUT);
}

CS_TEST(event_jsonl_encoding_is_valid_json) {
    cs_event ev;
    cs_event_init(&ev, CS_EV_NET_CONNECT);
    ev.ts = 1793750400123456789LL;
    ev.pid = 42;
    ev.tid = 43;
    ev.fd = 5;
    ev.peer = "127.0.0.1:9102";
    ev.proto = "tcp";
    ev.rc = -1;
    ev.err_no = ECONNREFUSED;
    ev.dur = 1500;
    ev.msg = "quote \" and newline\n";
    char buf[1024];
    size_t n = cs_event_to_jsonl(&ev, buf, sizeof buf);
    CS_ASSERT(n > 0 && buf[n - 1] == '\n');
    cs_json *o = cs_json_parse(buf, n, NULL, 0);
    CS_ASSERT(o != NULL);
    CS_ASSERT_EQ_STR(cs_json_as_str(cs_json_get(o, "k"), NULL), "net_connect");
    CS_ASSERT_EQ_STR(cs_json_as_str(cs_json_get(o, "err"), NULL), "ECONNREFUSED");
    CS_ASSERT(cs_json_as_i64(cs_json_get(o, "ts"), 0) == 1793750400123456789LL);
    CS_ASSERT_EQ_STR(cs_json_as_str(cs_json_get(o, "msg"), NULL), "quote \" and newline\n");
    cs_json_free(o);
}

CS_TEST(event_jsonl_truncates_safely) {
    cs_event ev;
    cs_event_init(&ev, CS_EV_APP_LOG);
    ev.msg = "a fairly long message that will not fit";
    char buf[48];
    size_t n = cs_event_to_jsonl(&ev, buf, sizeof buf);
    CS_ASSERT(n < sizeof buf);
    CS_ASSERT(buf[n - 1] == '\n' && buf[n - 2] == '}');
}

CS_TEST(eventlog_loads_sorts_and_counts) {
    cs_eventlog log;
    cs_eventlog_init(&log);
    const char *lines[] = {
        "{\"ts\":300,\"pid\":1,\"tid\":2,\"k\":\"fn_exit\",\"fn\":\"main\",\"dur\":200}",
        "# comment line",
        "",
        "{\"ts\":100,\"pid\":1,\"tid\":1,\"k\":\"fn_enter\",\"fn\":\"main\",\"depth\":0}",
        "not json at all",
        "{\"ts\":200,\"pid\":1,\"tid\":1,\"k\":\"net_connect\",\"fd\":3,\"peer\":\"10.0.0.1:80\","
        "\"rc\":-1,\"err\":\"ECONNREFUSED\"}",
    };
    size_t bad = 0;
    for (size_t i = 0; i < sizeof lines / sizeof lines[0]; i++)
        if (cs_eventlog_add_line(&log, lines[i], strlen(lines[i]), i + 1) != 0) bad++;
    cs_eventlog_finish(&log);
    CS_ASSERT_EQ_INT(bad, 1);
    CS_ASSERT_EQ_INT(cs_eventlog_count(&log), 3);
    CS_ASSERT_EQ_INT(cs_eventlog_at(&log, 0)->ts, 100);
    CS_ASSERT_EQ_INT(cs_eventlog_at(&log, 2)->ts, 300);
    const cs_event *c = cs_eventlog_at(&log, 1);
    CS_ASSERT_EQ_INT(c->kind, CS_EV_NET_CONNECT);
    CS_ASSERT_EQ_INT(c->err_no, ECONNREFUSED);
    CS_ASSERT_EQ_STR(c->peer, "10.0.0.1:80");
    /* interning: both main strings share storage */
    CS_ASSERT(cs_eventlog_at(&log, 0)->fn == cs_eventlog_at(&log, 2)->fn);
    CS_ASSERT_EQ_INT(log.n_pids, 1);
    CS_ASSERT_EQ_INT(log.n_tids, 2);
    CS_ASSERT_EQ_INT(log.t_max - log.t_min, 200);
    cs_eventlog_free(&log);
}
