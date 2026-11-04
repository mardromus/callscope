#include "cstest.h"

#include "callscope/analyze.h"

#include <errno.h>

static void net(cs_eventlog *log, int64_t ts, cs_event_kind k, int fd, const char *peer,
                int64_t rc, int err, int64_t bytes, int64_t dur) {
    cs_event ev;
    cs_event_init(&ev, k);
    ev.ts = ts;
    ev.pid = ev.tid = 7;
    ev.fd = fd;
    ev.peer = peer;
    ev.rc = rc;
    ev.err_no = err;
    ev.err = err ? cs_errno_name(err) : NULL;
    ev.bytes = bytes;
    ev.dur = dur;
    if (k == CS_EV_NET_CLOSE) {
        ev.sent = bytes;
    }
    cs_eventlog_add(log, &ev);
}

CS_TEST(netstats_builds_sessions_and_peers) {
    cs_eventlog log;
    cs_eventlog_init(&log);
    const char *pay = "127.0.0.1:9102", *inv = "127.0.0.1:9101";
    /* healthy session to inventory */
    net(&log, 100, CS_EV_NET_CONNECT, 3, inv, 0, 0, 0, 50);
    net(&log, 200, CS_EV_NET_SEND, 3, inv, 12, 0, 12, 10);
    net(&log, 300, CS_EV_NET_RECV, 3, inv, 8, 0, 8, 4000);
    net(&log, 400, CS_EV_NET_RECV, 3, inv, 0, 0, 0, 20); /* peer closed */
    net(&log, 500, CS_EV_NET_CLOSE, 3, inv, 0, 0, 12, -1);
    /* three refused connects to payment, fd reused */
    for (int i = 0; i < 3; i++) {
        net(&log, 600 + i * 100, CS_EV_NET_CONNECT, 4, pay, -1, ECONNREFUSED, 0, 30);
        net(&log, 650 + i * 100, CS_EV_NET_CLOSE, 4, pay, 0, 0, 0, -1);
    }
    /* one reset on a connection we never saw open */
    net(&log, 1000, CS_EV_NET_RECV, 9, pay, -1, ECONNRESET, 0, 70);
    cs_event dns;
    cs_event_init(&dns, CS_EV_NET_DNS);
    dns.ts = 1100;
    dns.pid = dns.tid = 7;
    dns.host = "api.example.test";
    dns.rc = -2;
    dns.err = "EAI_NONAME";
    dns.dur = 5000;
    cs_eventlog_add(&log, &dns);
    cs_eventlog_finish(&log);

    cs_netstats s;
    CS_ASSERT_EQ_INT(cs_netstats_build(&s, &log), 0);
    CS_ASSERT_EQ_INT(s.conns.len, 5);
    const cs_netconn *c0 = cs_vec_at(&s.conns, 0);
    CS_ASSERT(c0->connected && c0->closed && c0->eof);
    CS_ASSERT_EQ_INT(c0->sent, 12);
    CS_ASSERT_EQ_INT(c0->recvd, 8);
    CS_ASSERT_EQ_INT(c0->max_io, 4000);

    const cs_peerstat *p = cs_netstats_peer(&s, pay);
    CS_ASSERT(p != NULL);
    CS_ASSERT_EQ_INT(p->attempts, 3);
    CS_ASSERT_EQ_INT(p->failures, 3);
    CS_ASSERT_EQ_INT(p->resets, 1);
    int64_t cnt;
    CS_ASSERT_EQ_STR(cs_peerstat_top_err(p, &cnt), "ECONNREFUSED");
    CS_ASSERT_EQ_INT(cnt, 3);
    /* peers sorted by attempts: payment (3) before inventory (1) */
    CS_ASSERT_EQ_STR(CS_VEC_AT(&s.peers, cs_peerstat, 0)->peer, pay);

    CS_ASSERT_EQ_INT(s.dns.len, 1);
    const cs_dnsstat *d = cs_vec_at(&s.dns, 0);
    CS_ASSERT_EQ_INT(d->failures, 1);
    CS_ASSERT_EQ_STR(d->last_err, "EAI_NONAME");
    cs_netstats_free(&s);
    cs_eventlog_free(&log);
}
