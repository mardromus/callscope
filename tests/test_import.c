#include "cstest.h"

#include "callscope/import.h"
#include "callscope/timeutil.h"

#include <errno.h>
#include <signal.h>

CS_TEST(strace_parse_date) {
    CS_ASSERT_EQ_INT(cs_parse_date("2026-11-04"), 1793750400LL * CS_NS_PER_S);
    CS_ASSERT_EQ_INT(cs_parse_date("garbage"), -1);
}

CS_TEST(strace_import_sample_trace) {
    FILE *fp = fopen(CS_TEST_DATA_DIR "/sample.strace", "r");
    CS_ASSERT(fp != NULL);
    cs_eventlog log;
    cs_eventlog_init(&log);
    cs_strace_opts opts = {cs_parse_date("2026-11-04"), 0};
    cs_import_stats st;
    CS_ASSERT_EQ_INT(cs_import_strace(&log, fp, &opts, &st), 0);
    fclose(fp);

    /* connect ok, send, recv, close, refused connect, close, timeout connect,
     * annotated read, SIGSEGV, exit = 10 events */
    CS_ASSERT_EQ_INT(cs_eventlog_count(&log), 11);
    CS_ASSERT_EQ_INT(st.lines, 18);

    const cs_event *e0 = cs_eventlog_at(&log, 0);
    CS_ASSERT_EQ_INT(e0->kind, CS_EV_NET_CONNECT);
    CS_ASSERT_EQ_STR(e0->peer, "127.0.0.1:9101");
    CS_ASSERT_EQ_INT(e0->rc, 0);
    CS_ASSERT_EQ_INT(e0->dur, 310000);
    CS_ASSERT_EQ_INT(e0->ts, 1793750400LL * CS_NS_PER_S + (14 * 3600 + 2 * 60 + 11) * CS_NS_PER_S + 200000);

    const cs_event *recv = cs_eventlog_at(&log, 2);
    CS_ASSERT_EQ_INT(recv->kind, CS_EV_NET_RECV);
    CS_ASSERT_EQ_INT(recv->bytes, 8);

    const cs_event *cl = cs_eventlog_at(&log, 3);
    CS_ASSERT_EQ_INT(cl->kind, CS_EV_NET_CLOSE);
    CS_ASSERT_EQ_INT(cl->sent, 15);
    CS_ASSERT_EQ_INT(cl->recvd, 8);

    /* the unfinished/resumed connect keeps the start timestamp */
    const cs_event *refused = cs_eventlog_at(&log, 4);
    CS_ASSERT_EQ_INT(refused->kind, CS_EV_NET_CONNECT);
    CS_ASSERT_EQ_STR(refused->peer, "127.0.0.1:9102");
    CS_ASSERT_EQ_INT(refused->err_no, ECONNREFUSED);

    const cs_event *v6 = cs_eventlog_at(&log, 6);
    CS_ASSERT_EQ_STR(v6->peer, "[::1]:443");
    CS_ASSERT_EQ_STR(v6->err, "ETIMEDOUT");
    CS_ASSERT_EQ_INT(v6->dur, 3000100000LL);

    const cs_event *annot = cs_eventlog_at(&log, 7);
    CS_ASSERT_EQ_INT(annot->kind, CS_EV_NET_RECV);
    CS_ASSERT_EQ_INT(annot->pid, 4102);
    CS_ASSERT_EQ_STR(annot->peer, "127.0.0.1:6379");

    CS_ASSERT_EQ_INT(cs_eventlog_at(&log, 8)->kind, CS_EV_SIGNAL);
    CS_ASSERT_EQ_INT(cs_eventlog_at(&log, 8)->sig, SIGSEGV);
    const cs_event *ex = cs_eventlog_at(&log, 9);
    CS_ASSERT_EQ_INT(ex->kind, CS_EV_PROC_EXIT);
    CS_ASSERT_EQ_INT(ex->rc, 128 + SIGSEGV);

    /* non-blocking connect resolved through getsockopt(SO_ERROR) */
    const cs_event *nb = cs_eventlog_at(&log, 10);
    CS_ASSERT_EQ_INT(nb->kind, CS_EV_NET_CONNECT);
    CS_ASSERT_EQ_STR(nb->peer, "10.9.9.9:80");
    CS_ASSERT_EQ_STR(nb->err, "ECONNREFUSED");
    CS_ASSERT_EQ_INT(nb->dur, 250000000);
    cs_eventlog_free(&log);
}

CS_TEST(strace_epoch_timestamps_without_pid) {
    cs_eventlog log;
    cs_eventlog_init(&log);
    cs_strace_opts opts = {0, 77};
    cs_strace_importer *imp = cs_strace_importer_new(&log, &opts);
    cs_strace_importer_line(imp, "1793750400.500000 socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 3");
    CS_ASSERT_EQ_INT(cs_strace_importer_line(
                         imp, "1793750400.600000 sendto(3, \"x\", 1, 0, {sa_family=AF_INET, "
                              "sin_port=htons(53), sin_addr=inet_addr(\"8.8.8.8\")}, 16) = 1"),
                     1);
    cs_strace_importer_free(imp);
    cs_eventlog_finish(&log);
    const cs_event *e = cs_eventlog_at(&log, 0);
    CS_ASSERT(e != NULL);
    CS_ASSERT_EQ_INT(e->pid, 77);
    CS_ASSERT_EQ_STR(e->peer, "8.8.8.8:53");
    CS_ASSERT_EQ_STR(e->proto, "udp");
    CS_ASSERT_EQ_INT(e->ts, 1793750400LL * CS_NS_PER_S + 600000000);
    cs_eventlog_free(&log);
}
