/* Deterministic simulator of an instrumented order service.
 *
 * Each worker thread has its own virtual clock. Requests are dispatched to
 * whichever worker is free first, so the threads' events interleave the way
 * they would in a real trace. Faults are injected per scenario. */
#include "callscope/gen.h"

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "callscope/timeutil.h"

static const cs_gen_scenario_info SCENARIOS[] = {
    {"healthy", "Normal traffic, all dependencies healthy", NULL},
    {"upstream-down", "Payment service stops accepting connections part-way through",
     "net.connect_failure"},
    {"slow-upstream", "Payment service starts answering in 1-2.5 s", "net.slow_io"},
    {"dns-failure", "payments.internal no longer resolves (bad config / missing record)",
     "net.dns_failure"},
    {"recursion-crash", "A malformed order sends the receipt renderer into infinite recursion",
     "fn.recursion"},
    {"reset-crash", "Payment resets connections and the error path dereferences NULL",
     "cross.error_propagation"},
    {"fd-leak", "Inventory error path forgets to close sockets until fds run out",
     "net.conn_leak"},
    {"cpu-hotspot", "A discount calculation burns CPU on every request", "fn.hotspot"},
    {NULL, NULL, NULL},
};

const cs_gen_scenario_info *cs_gen_scenarios(void) { return SCENARIOS; }

const cs_gen_scenario_info *cs_gen_find(const char *name) {
    for (const cs_gen_scenario_info *s = SCENARIOS; s->name; s++)
        if (strcmp(s->name, name) == 0) return s;
    return NULL;
}

enum { SC_HEALTHY, SC_DOWN, SC_SLOW, SC_DNS, SC_RECURSION, SC_RESET, SC_LEAK, SC_HOTSPOT };

#define INV_HOST "inventory.internal"
#define PAY_HOST "payments.internal"
#define INV_PEER "10.0.4.21:9101"
#define PAY_PEER "10.0.4.22:9102"
#define MAX_STACK 512

typedef struct {
    const char *fn;
    int64_t start;
} frame_t;

typedef struct sim {
    cs_eventlog *log;
    int pid, tid;
    int64_t now;
    frame_t stack[MAX_STACK];
    int depth;
    uint32_t *rng;
    int *next_fd;
} sim_t;

typedef struct {
    int scenario;
    int requests;
    int fault_from; /* first request affected */
    int open_fds;   /* leaked sockets (fd-leak) */
    int crashed;
    int64_t crash_ts;
    int crash_tid;
} world_t;

static uint32_t rnd(uint32_t *s) {
    uint32_t x = *s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return *s = x ? x : 0x9E3779B9u;
}

static int64_t between(sim_t *s, int64_t lo, int64_t hi) {
    return lo + (int64_t)(rnd(s->rng) % (uint32_t)(hi - lo + 1));
}

static void emit(sim_t *s, cs_event *ev) {
    ev->ts = s->now;
    ev->pid = s->pid;
    ev->tid = s->tid;
    cs_eventlog_add(s->log, ev);
}

static void enter(sim_t *s, const char *fn) {
    cs_event ev;
    cs_event_init(&ev, CS_EV_FN_ENTER);
    ev.fn = fn;
    ev.depth = s->depth;
    emit(s, &ev);
    if (s->depth < MAX_STACK) s->stack[s->depth] = (frame_t){fn, s->now};
    s->depth++;
    s->now += between(s, 200, 900); /* call overhead + prologue */
}

static void leave(sim_t *s) {
    if (s->depth <= 0) return;
    s->depth--;
    s->now += between(s, 100, 400);
    cs_event ev;
    cs_event_init(&ev, CS_EV_FN_EXIT);
    ev.fn = s->stack[s->depth].fn;
    ev.depth = s->depth;
    ev.dur = s->now - s->stack[s->depth].start;
    emit(s, &ev);
}

static void work(sim_t *s, int64_t lo, int64_t hi) { s->now += between(s, lo, hi); }

static int dns(sim_t *s, const char *host, const char *addr, int fail) {
    cs_event ev;
    cs_event_init(&ev, CS_EV_NET_DNS);
    int64_t d = fail ? between(s, 2 * CS_NS_PER_MS, 6 * CS_NS_PER_MS)
                     : between(s, 30 * CS_NS_PER_US, 180 * CS_NS_PER_US);
    s->now += d;
    ev.host = host;
    ev.dur = d;
    if (fail) {
        ev.rc = EAI_NONAME;
        ev.err = "EAI_NONAME";
        ev.msg = "Name or service not known";
    } else {
        ev.msg = addr;
    }
    emit(s, &ev);
    return fail ? -1 : 0;
}

static int net_connect(sim_t *s, const char *peer, int err, int64_t dur) {
    int fd = (*s->next_fd)++;
    if (*s->next_fd > 1000) *s->next_fd = 5;
    s->now += dur;
    cs_event ev;
    cs_event_init(&ev, CS_EV_NET_CONNECT);
    ev.fd = fd;
    ev.peer = peer;
    ev.proto = "tcp";
    ev.rc = err ? -1 : 0;
    ev.err_no = err;
    ev.dur = dur;
    emit(s, &ev);
    return fd;
}

static void net_io(sim_t *s, cs_event_kind k, int fd, const char *peer, int64_t bytes, int err,
                   int64_t dur) {
    s->now += dur;
    cs_event ev;
    cs_event_init(&ev, k);
    ev.fd = fd;
    ev.peer = peer;
    ev.proto = "tcp";
    ev.rc = err ? -1 : bytes;
    ev.bytes = err ? 0 : bytes;
    ev.err_no = err;
    ev.dur = dur;
    emit(s, &ev);
}

static void net_close(sim_t *s, int fd, const char *peer, int64_t sent, int64_t recvd) {
    s->now += between(s, 3000, 9000);
    cs_event ev;
    cs_event_init(&ev, CS_EV_NET_CLOSE);
    ev.fd = fd;
    ev.peer = peer;
    ev.proto = "tcp";
    ev.sent = sent;
    ev.recvd = recvd;
    emit(s, &ev);
}

static void app_error(sim_t *s, const char *code, const char *msg) {
    cs_event ev;
    cs_event_init(&ev, CS_EV_APP_ERROR);
    ev.code = code;
    ev.msg = msg;
    s->now += 2000;
    emit(s, &ev);
}

static void app_log(sim_t *s, const char *level, const char *msg) {
    cs_event ev;
    cs_event_init(&ev, CS_EV_APP_LOG);
    ev.code = level;
    ev.msg = msg;
    emit(s, &ev);
}

static void crash(sim_t *s, world_t *w, int sig) {
    cs_event ev;
    cs_event_init(&ev, CS_EV_SIGNAL);
    ev.sig = sig;
    ev.depth = s->depth;
    ev.msg = "fatal signal; open frames at this point are the crash site";
    s->now += 1500;
    emit(s, &ev);
    w->crashed = 1;
    w->crash_ts = s->now;
    w->crash_tid = s->tid;
}

/* returns -1 when the request must stop (error already reported) */
static int reserve_inventory(sim_t *s, world_t *w, int req) {
    enter(s, "reserve_inventory");
    enter(s, "resolve_service");
    dns(s, INV_HOST, INV_PEER, 0);
    leave(s);
    int emfile = w->scenario == SC_LEAK && w->open_fds >= 24;
    int fd = net_connect(s, INV_PEER, emfile ? EMFILE : 0,
                         emfile ? 4000 : between(s, 90 * CS_NS_PER_US, 260 * CS_NS_PER_US));
    if (emfile) {
        app_error(s, "INVENTORY_UNAVAILABLE", "socket: too many open files");
        leave(s);
        return -1;
    }
    net_io(s, CS_EV_NET_SEND, fd, INV_PEER, 42, 0, between(s, 8000, 30000));
    int bad = w->scenario == SC_LEAK && req >= w->fault_from && (rnd(s->rng) % 3 != 0);
    net_io(s, CS_EV_NET_RECV, fd, INV_PEER, bad ? 9 : 26, 0,
           between(s, 2 * CS_NS_PER_MS, 6 * CS_NS_PER_MS));
    enter(s, "parse_inventory_reply");
    work(s, 10000, 40000);
    leave(s);
    if (bad) { /* the buggy error path returns before closing the socket */
        app_error(s, "INVENTORY_REJECTED", "inventory replied ERR; retry later");
        w->open_fds++;
        leave(s);
        return -1;
    }
    net_close(s, fd, INV_PEER, 42, 26);
    leave(s);
    return 0;
}

static int charge_payment(sim_t *s, world_t *w, int req) {
    enter(s, "charge_payment");
    enter(s, "resolve_service");
    int dns_fail = w->scenario == SC_DNS && req >= w->fault_from;
    if (dns(s, PAY_HOST, PAY_PEER, dns_fail) != 0) {
        leave(s);
        app_error(s, "PAYMENT_CONFIG", "cannot resolve payments.internal");
        leave(s);
        return -1;
    }
    leave(s);
    int down = w->scenario == SC_DOWN && req >= w->fault_from;
    for (int attempt = 1; attempt <= 3; attempt++) {
        int emfile = w->scenario == SC_LEAK && w->open_fds >= 24;
        int err = emfile ? EMFILE : down ? ECONNREFUSED : 0;
        int fd = net_connect(s, PAY_PEER, err,
                             err ? between(s, 40 * CS_NS_PER_US, 110 * CS_NS_PER_US)
                                 : between(s, 120 * CS_NS_PER_US, 400 * CS_NS_PER_US));
        if (err) {
            net_close(s, fd, PAY_PEER, 0, 0);
            app_log(s, "warn", "payment connect failed, retrying");
            work(s, 100 * CS_NS_PER_MS, 100 * CS_NS_PER_MS + 50000); /* fixed sleep: no backoff */
            continue;
        }
        net_io(s, CS_EV_NET_SEND, fd, PAY_PEER, 96, 0, between(s, 10000, 40000));
        if (w->scenario == SC_RESET && req >= w->fault_from) {
            net_io(s, CS_EV_NET_RECV, fd, PAY_PEER, 0, ECONNRESET,
                   between(s, 3 * CS_NS_PER_MS, 9 * CS_NS_PER_MS));
            enter(s, "parse_payment_response");
            work(s, 3000, 8000);
            crash(s, w, SIGSEGV);
            return -1;
        }
        int slow = w->scenario == SC_SLOW && req >= w->fault_from && (rnd(s->rng) % 5 != 0);
        net_io(s, CS_EV_NET_RECV, fd, PAY_PEER, 38, 0,
               slow ? between(s, 1200 * CS_NS_PER_MS, 2500 * CS_NS_PER_MS)
                    : between(s, 6 * CS_NS_PER_MS, 18 * CS_NS_PER_MS));
        enter(s, "parse_payment_response");
        work(s, 15000, 60000);
        leave(s);
        net_close(s, fd, PAY_PEER, 96, 38);
        leave(s);
        return 0;
    }
    char msg[128];
    snprintf(msg, sizeof msg, "payment service unreachable after 3 attempts (order %d)", 1000 + req);
    app_error(s, w->scenario == SC_LEAK ? "PAYMENT_UNAVAILABLE" : "PAYMENT_UNAVAILABLE", msg);
    leave(s);
    return -1;
}

static void write_receipt(sim_t *s, world_t *w, int req) {
    enter(s, "write_receipt");
    if (w->scenario == SC_RECURSION && req == w->fault_from) {
        for (int i = 0; i < 300 && s->depth < MAX_STACK - 2; i++) {
            enter(s, "render_template");
            work(s, 500, 2000);
        }
        crash(s, w, SIGSEGV);
        return;
    }
    enter(s, "render_template");
    work(s, 30000, 90000);
    leave(s);
    leave(s);
}

static void handle_request(sim_t *s, world_t *w, int req) {
    enter(s, "handle_request");
    enter(s, "parse_order");
    work(s, 20000, 60000);
    leave(s);
    enter(s, "validate_order");
    work(s, 8000, 25000);
    leave(s);
    if (w->scenario == SC_HOTSPOT) {
        enter(s, "compute_discount");
        work(s, 9 * CS_NS_PER_MS, 16 * CS_NS_PER_MS);
        leave(s);
    }
    if (reserve_inventory(s, w, req) == 0 && !w->crashed) {
        if (charge_payment(s, w, req) == 0 && !w->crashed) write_receipt(s, w, req);
    }
    if (w->crashed) return;
    leave(s);
}

static int scenario_id(const char *name) {
    static const char *const ids[] = {"healthy",  "upstream-down", "slow-upstream", "dns-failure",
                                      "recursion-crash", "reset-crash", "fd-leak", "cpu-hotspot"};
    for (int i = 0; i < 8; i++)
        if (strcmp(ids[i], name) == 0) return i;
    return -1;
}

int cs_gen_run(cs_eventlog *log, const cs_gen_opts *opts, char *err, size_t errlen) {
    cs_gen_opts o = {"healthy", 40, 42, 0, 2};
    if (opts) {
        if (opts->scenario) o.scenario = opts->scenario;
        if (opts->requests > 0) o.requests = opts->requests;
        if (opts->seed) o.seed = opts->seed;
        if (opts->start_ns) o.start_ns = opts->start_ns;
        if (opts->threads > 0) o.threads = opts->threads;
    }
    if (!o.start_ns) o.start_ns = (1793750400LL + 9 * 3600 + 30 * 60) * CS_NS_PER_S;
    if (o.threads > 8) o.threads = 8;
    int sc = scenario_id(o.scenario);
    if (sc < 0) {
        if (err) snprintf(err, errlen, "unknown scenario '%s' (try: callscope gen --list)", o.scenario);
        return -1;
    }

    world_t w = {sc, o.requests, 0, 0, 0, 0, 0};
    w.fault_from = sc == SC_RECURSION ? o.requests / 2 : o.requests / 3;
    if (sc == SC_LEAK) w.fault_from = 4;

    uint32_t rng = o.seed ? o.seed : 42;
    int next_fd = 5;
    const int pid = 4242;
    sim_t sims[8];
    memset(sims, 0, sizeof sims);
    for (int t = 0; t < o.threads; t++) {
        sims[t] = (sim_t){log, pid, pid + t, o.start_ns + t * 350 * CS_NS_PER_US, {{0}}, 0, &rng,
                          &next_fd};
    }

    cs_event start;
    cs_event_init(&start, CS_EV_PROC_START);
    start.msg = "./orderservice --workers 2 (synthetic)";
    start.code = "gen";
    emit(&sims[0], &start);
    enter(&sims[0], "main");
    for (int t = 0; t < o.threads; t++) enter(&sims[t], "worker_loop");

    for (int req = 0; req < o.requests && !w.crashed; req++) {
        sim_t *s = &sims[0];
        for (int t = 1; t < o.threads; t++)
            if (sims[t].now < s->now) s = &sims[t];
        handle_request(s, &w, req);
        work(s, 4 * CS_NS_PER_MS, 18 * CS_NS_PER_MS); /* idle until next request */
    }

    if (!w.crashed) {
        for (int t = o.threads - 1; t >= 0; t--)
            while (sims[t].depth > 0) leave(&sims[t]);
        sim_t *last = &sims[0];
        for (int t = 1; t < o.threads; t++)
            if (sims[t].now > last->now) last = &sims[t];
        cs_event ex;
        cs_event_init(&ex, CS_EV_PROC_EXIT);
        ex.rc = 0;
        last->tid = pid;
        emit(last, &ex);
    } else {
        /* the process died: drop anything the other workers "did" after the crash */
        size_t keep = 0;
        for (size_t i = 0; i < log->events.len; i++) {
            cs_event *ev = cs_vec_at(&log->events, i);
            if (ev->ts > w.crash_ts) continue;
            if (keep != i) *(cs_event *)cs_vec_at(&log->events, keep) = *ev;
            keep++;
        }
        log->events.len = keep;
        cs_event ex;
        cs_event_init(&ex, CS_EV_PROC_EXIT);
        ex.ts = w.crash_ts + 200000;
        ex.pid = pid;
        ex.tid = pid;
        ex.rc = 128 + SIGSEGV;
        ex.sig = SIGSEGV;
        ex.msg = "killed by signal";
        cs_eventlog_add(log, &ex);
    }
    snprintf(log->source, sizeof log->source, "synthetic:%s", o.scenario);
    cs_eventlog_finish(log);
    return 0;
}
