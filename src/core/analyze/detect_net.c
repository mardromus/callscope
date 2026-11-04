/* Network-level detectors: failed connects, retry storms, DNS failures, slow
 * peers, resets / premature EOF and connection leaks. */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "callscope/timeutil.h"
#include "internal.h"

/* index of the first connect event to `peer` that failed (or any event if want_fail=0) */
static size_t first_connect(const cs_analysis *a, const char *peer, int want_fail,
                            cs_finding *collect) {
    size_t first = CS_NONE;
    for (size_t i = 0; i < a->net.conns.len; i++) {
        const cs_netconn *c = cs_vec_at(&a->net.conns, i);
        if (c->peer != peer || c->accepted) continue;
        if (want_fail && c->connect_rc >= 0) continue;
        if (first == CS_NONE) first = c->first_ev;
        if (collect) cs_finding_add_evidence(collect, c->first_ev);
    }
    return first;
}

static void detect_connect_failures(cs_analysis *a) {
    int reported = 0;
    for (size_t i = 0; i < a->net.peers.len && reported < a->opts.max_per_detector; i++) {
        const cs_peerstat *p = cs_vec_at(&a->net.peers, i);
        if (!p->failures) continue;
        int64_t ecount;
        const char *err = cs_peerstat_top_err(p, &ecount);
        /* glibc probes the optional nscd socket on every lookup: not a failure */
        if (strstr(p->peer, "nscd") && err && strcmp(err, "ENOENT") == 0) continue;
        cs_severity sev = (p->failures == p->attempts && p->attempts >= 3) ? CS_SEV_CRITICAL
                                                                          : CS_SEV_HIGH;
        cs_finding *f = cs_analysis_add_finding(a, "net.connect_failure", CS_LEVEL_NETWORK, sev);
        if (!f) return;
        f->peer = p->peer;
        f->err = err;
        f->count = p->failures;
        f->value = p->attempts ? (double)p->failures / (double)p->attempts : 0;
        f->first_ts = p->first_ts;
        f->last_ts = p->last_ts;
        size_t ev = first_connect(a, p->peer, 1, f);
        cs_finding_set_context(a, f, ev);
        snprintf(f->title, sizeof f->title, "%lld of %lld connections to %s failed (%s)",
                 (long long)p->failures, (long long)p->attempts, p->peer, err ? err : "error");
        const char *why = "";
        if (err && strcmp(err, "ECONNREFUSED") == 0)
            why = "Nothing was listening on that address and port: the service is down, "
                  "restarting, or the port/host is misconfigured.";
        else if (err && strcmp(err, "ETIMEDOUT") == 0)
            why = "The SYN was never answered: the host is unreachable, a firewall drops the "
                  "traffic, or the service is overloaded.";
        else if (err && (strcmp(err, "ENETUNREACH") == 0 || strcmp(err, "EHOSTUNREACH") == 0))
            why = "There is no route to that host from this machine.";
        else if (err && strcmp(err, "EMFILE") == 0)
            why = "The process ran out of file descriptors.";
        snprintf(f->detail, sizeof f->detail, "%s Failed attempts: %lld, most common error %s "
                 "(%lld times).",
                 why, (long long)p->failures, err ? err : "unknown", (long long)ecount);
        reported++;
    }
}

static void detect_retry_storm(cs_analysis *a) {
    int reported = 0;
    for (size_t pi = 0; pi < a->net.peers.len && reported < 3; pi++) {
        const cs_peerstat *p = cs_vec_at(&a->net.peers, pi);
        if (p->failures < a->opts.retry_count) continue;
        /* sliding window over failed connect timestamps */
        int64_t ts[256];
        size_t idx[256];
        size_t n = 0;
        for (size_t i = 0; i < a->net.conns.len && n < 256; i++) {
            const cs_netconn *c = cs_vec_at(&a->net.conns, i);
            if (c->peer != p->peer || c->accepted || c->connect_rc >= 0) continue;
            ts[n] = c->t_open;
            idx[n++] = c->first_ev;
        }
        size_t best_lo = 0, best_len = 0, lo = 0;
        for (size_t hi = 0; hi < n; hi++) {
            while (ts[hi] - ts[lo] > a->opts.retry_window_ns) lo++;
            if (hi - lo + 1 > best_len) {
                best_len = hi - lo + 1;
                best_lo = lo;
            }
        }
        if ((int)best_len < a->opts.retry_count) continue;
        /* backoff = gaps that keep growing (each at least 1.6x the previous one) */
        int backoff = 0;
        for (size_t k = best_lo; k + 3 < best_lo + best_len && !backoff; k++) {
            int64_t g0 = ts[k + 1] - ts[k], g1 = ts[k + 2] - ts[k + 1], g2 = ts[k + 3] - ts[k + 2];
            if (g0 > 0 && g1 * 10 > g0 * 16 && g2 * 10 > g1 * 16) backoff = 1;
        }
        int64_t span = ts[best_lo + best_len - 1] - ts[best_lo];
        cs_finding *f = cs_analysis_add_finding(a, "net.retry_storm", CS_LEVEL_NETWORK,
                                                backoff ? CS_SEV_LOW : CS_SEV_MEDIUM);
        if (!f) return;
        f->peer = p->peer;
        f->count = (int64_t)best_len;
        f->value = (double)span;
        f->first_ts = ts[best_lo];
        f->last_ts = ts[best_lo + best_len - 1];
        for (size_t k = 0; k < best_len && k < 4; k++) cs_finding_add_evidence(f, idx[best_lo + k]);
        cs_finding_set_context(a, f, idx[best_lo]);
        char d[32];
        snprintf(f->title, sizeof f->title, "Retry storm: %zu failed connects to %s within %s%s",
                 best_len, p->peer, cs_fmt_dur(span, d, sizeof d),
                 backoff ? "" : " (no backoff)");
        snprintf(f->detail, sizeof f->detail,
                 "The client kept reconnecting to a peer that was refusing connections. %s "
                 "Use exponential backoff with jitter and a circuit breaker so a dead dependency "
                 "does not turn into a self-inflicted load spike.",
                 backoff ? "Gaps between attempts grow, so some backoff exists."
                         : "Attempts are evenly spaced, so there is no backoff.");
        reported++;
    }
}

static void detect_dns(cs_analysis *a) {
    for (size_t i = 0; i < a->net.dns.len; i++) {
        const cs_dnsstat *d = cs_vec_at(&a->net.dns, i);
        char dur[32];
        if (d->failures) {
            cs_finding *f = cs_analysis_add_finding(a, "net.dns_failure", CS_LEVEL_NETWORK,
                                                    CS_SEV_HIGH);
            if (!f) return;
            f->peer = d->host;
            f->err = d->last_err;
            f->count = d->failures;
            f->first_ts = f->last_ts = cs_eventlog_at(a->log, d->last_ev)->ts;
            cs_finding_add_evidence(f, d->last_ev);
            cs_finding_set_context(a, f, d->last_ev);
            snprintf(f->title, sizeof f->title, "DNS lookup for %s failed %lld time%s (%s)",
                     d->host, (long long)d->failures, d->failures == 1 ? "" : "s",
                     d->last_err ? d->last_err : "error");
            snprintf(f->detail, sizeof f->detail,
                     "%s",
                     (d->last_err && strcmp(d->last_err, "EAI_NONAME") == 0)
                         ? "The name does not exist: check for a typo in the configured "
                           "hostname or a missing DNS record / hosts entry."
                         : "The resolver could not answer. Check /etc/resolv.conf, network "
                           "connectivity to the DNS server and whether it is overloaded.");
        } else if (d->max_dur >= a->opts.net_slow_ns) {
            cs_finding *f = cs_analysis_add_finding(a, "net.dns_slow", CS_LEVEL_NETWORK,
                                                    CS_SEV_MEDIUM);
            if (!f) return;
            f->peer = d->host;
            f->value = (double)d->max_dur;
            f->count = d->lookups;
            cs_finding_add_evidence(f, d->last_ev);
            cs_finding_set_context(a, f, d->last_ev);
            snprintf(f->title, sizeof f->title, "Slow DNS: resolving %s took up to %s", d->host,
                     cs_fmt_dur(d->max_dur, dur, sizeof dur));
            snprintf(f->detail, sizeof f->detail,
                     "Name resolution is on the critical path of every new connection. Cache "
                     "the result or use a local caching resolver.");
        }
    }
}

static void detect_slow_peers(cs_analysis *a) {
    int reported = 0;
    for (size_t i = 0; i < a->net.peers.len && reported < a->opts.max_per_detector; i++) {
        const cs_peerstat *p = cs_vec_at(&a->net.peers, i);
        int64_t worst = p->io_max > p->connect_max ? p->io_max : p->connect_max;
        if (worst < a->opts.net_slow_ns) continue;
        int is_connect = p->connect_max >= p->io_max;
        cs_finding *f = cs_analysis_add_finding(a, is_connect ? "net.slow_connect" : "net.slow_io",
                                                CS_LEVEL_NETWORK,
                                                worst >= CS_NS_PER_S ? CS_SEV_HIGH : CS_SEV_MEDIUM);
        if (!f) return;
        f->peer = p->peer;
        f->value = (double)worst;
        f->threshold = (double)a->opts.net_slow_ns;
        f->first_ts = p->first_ts;
        f->last_ts = p->last_ts;
        /* evidence: the slowest connection's events */
        size_t ev = CS_NONE;
        int64_t slow_conns = 0;
        for (size_t k = 0; k < a->net.conns.len; k++) {
            const cs_netconn *c = cs_vec_at(&a->net.conns, k);
            if (c->peer != p->peer) continue;
            int64_t w = is_connect ? c->connect_dur : c->max_io;
            if (w >= a->opts.net_slow_ns) {
                slow_conns++;
                if (ev == CS_NONE) ev = is_connect ? c->first_ev : c->last_ev;
            }
        }
        /* point at the slow I/O event itself */
        if (!is_connect && ev != CS_NONE) {
            for (size_t k = 0; k < cs_eventlog_count(a->log); k++) {
                const cs_event *e = cs_eventlog_at(a->log, k);
                if ((e->kind == CS_EV_NET_RECV || e->kind == CS_EV_NET_SEND) && e->peer == p->peer &&
                    e->dur >= a->opts.net_slow_ns) {
                    ev = k;
                    break;
                }
            }
        }
        f->count = slow_conns;
        cs_finding_add_evidence(f, ev);
        cs_finding_set_context(a, f, ev);
        char d[32], avg[32];
        int64_t mean = p->connect_n ? p->connect_total / p->connect_n : 0;
        if (is_connect) {
            snprintf(f->title, sizeof f->title, "Slow connects to %s: up to %s", p->peer,
                     cs_fmt_dur(worst, d, sizeof d));
            snprintf(f->detail, sizeof f->detail,
                     "TCP handshakes took up to %s (mean %s). Long connects point at packet "
                     "loss, an overloaded accept queue on the server, or a far-away host. "
                     "Reuse connections (keep-alive / pooling).",
                     cs_fmt_dur(worst, d, sizeof d), cs_fmt_dur(mean, avg, sizeof avg));
        } else {
            snprintf(f->title, sizeof f->title, "Slow responses from %s: waited up to %s", p->peer,
                     cs_fmt_dur(worst, d, sizeof d));
            snprintf(f->detail, sizeof f->detail,
                     "A single send/recv blocked for %s in %lld connection(s). The remote "
                     "service is slow to answer (its own dependencies, CPU, locks) or the "
                     "response is large. Add a client timeout so callers fail fast.",
                     cs_fmt_dur(worst, d, sizeof d), (long long)slow_conns);
        }
        reported++;
    }
}

static void detect_resets(cs_analysis *a) {
    for (size_t i = 0; i < a->net.peers.len; i++) {
        const cs_peerstat *p = cs_vec_at(&a->net.peers, i);
        if (!p->resets && !p->io_errors) continue;
        cs_finding *f = cs_analysis_add_finding(a, "net.reset", CS_LEVEL_NETWORK, CS_SEV_HIGH);
        if (!f) return;
        f->peer = p->peer;
        f->err = p->resets ? "ECONNRESET" : "EIO";
        f->count = p->resets ? p->resets : p->io_errors;
        f->first_ts = p->first_ts;
        f->last_ts = p->last_ts;
        size_t ev = CS_NONE;
        for (size_t k = 0; k < cs_eventlog_count(a->log); k++) {
            const cs_event *e = cs_eventlog_at(a->log, k);
            if ((e->kind == CS_EV_NET_RECV || e->kind == CS_EV_NET_SEND) && e->peer == p->peer &&
                e->rc < 0) {
                ev = k;
                f->err = e->err ? e->err : cs_errno_name(e->err_no);
                f->first_ts = e->ts;
                break;
            }
        }
        cs_finding_add_evidence(f, ev);
        cs_finding_set_context(a, f, ev);
        snprintf(f->title, sizeof f->title, "Connection to %s broke mid-request (%s, %lld time%s)",
                 p->peer, f->err ? f->err : "I/O error", (long long)f->count,
                 f->count == 1 ? "" : "s");
        snprintf(f->detail, sizeof f->detail,
                 "The peer aborted the connection while data was in flight. Typical causes: "
                 "the remote process crashed or restarted, a load balancer / proxy idle timeout, "
                 "or the server rejected the request and closed hard.");
    }
}

static void detect_premature_eof(cs_analysis *a) {
    for (size_t i = 0; i < a->net.peers.len; i++) {
        const cs_peerstat *p = cs_vec_at(&a->net.peers, i);
        int64_t silent = 0;
        size_t ev = CS_NONE;
        for (size_t k = 0; k < a->net.conns.len; k++) {
            const cs_netconn *c = cs_vec_at(&a->net.conns, k);
            if (c->peer != p->peer || c->accepted) continue;
            if (c->eof && c->sent > 0 && c->recvd == 0) {
                silent++;
                if (ev == CS_NONE) ev = c->last_ev;
            }
        }
        if (!silent) continue;
        cs_finding *f = cs_analysis_add_finding(a, "net.no_response", CS_LEVEL_NETWORK,
                                                CS_SEV_MEDIUM);
        if (!f) return;
        f->peer = p->peer;
        f->count = silent;
        cs_finding_add_evidence(f, ev);
        cs_finding_set_context(a, f, ev);
        f->first_ts = f->last_ts = ev != CS_NONE ? cs_eventlog_at(a->log, ev)->ts : 0;
        snprintf(f->title, sizeof f->title, "%s closed %lld connection%s without responding",
                 p->peer, (long long)silent, silent == 1 ? "" : "s");
        snprintf(f->detail, sizeof f->detail,
                 "The request was sent, then the peer closed the connection (recv returned 0) "
                 "without sending a single byte. The server likely rejected or crashed on the "
                 "request, or a protocol mismatch (e.g. plain HTTP to a TLS port) occurred.");
    }
}

static void detect_leaks(cs_analysis *a) {
    int64_t leaked = 0, emfile = 0;
    size_t ev = CS_NONE, emfile_ev = CS_NONE;
    for (size_t k = 0; k < a->net.conns.len; k++) {
        const cs_netconn *c = cs_vec_at(&a->net.conns, k);
        if (!c->closed && c->connected) {
            leaked++;
            if (ev == CS_NONE) ev = c->first_ev;
        }
    }
    for (size_t k = 0; k < cs_eventlog_count(a->log); k++) {
        const cs_event *e = cs_eventlog_at(a->log, k);
        if (cs_event_is_net(e->kind) && (e->err_no == EMFILE || e->err_no == ENFILE)) {
            emfile++;
            if (emfile_ev == CS_NONE) emfile_ev = k;
        }
    }
    if (leaked < 3 && !emfile) return;
    cs_finding *f = cs_analysis_add_finding(a, "net.conn_leak", CS_LEVEL_NETWORK,
                                            emfile ? CS_SEV_CRITICAL : CS_SEV_MEDIUM);
    if (!f) return;
    f->count = emfile ? emfile : leaked;
    f->value = (double)leaked;
    cs_finding_add_evidence(f, emfile_ev);
    cs_finding_add_evidence(f, ev);
    cs_finding_set_context(a, f, ev != CS_NONE ? ev : emfile_ev);
    if (emfile) {
        f->err = "EMFILE";
        snprintf(f->title, sizeof f->title,
                 "File descriptors exhausted (EMFILE x%lld) with %lld connections never closed",
                 (long long)emfile, (long long)leaked);
    } else {
        snprintf(f->title, sizeof f->title, "%lld connections were opened and never closed",
                 (long long)leaked);
    }
    snprintf(f->detail, sizeof f->detail,
             "Sockets that are never closed keep their file descriptor until the process "
             "exits. Under load the process hits its fd limit (ulimit -n) and every new "
             "connect/accept fails with EMFILE. Make sure every error path closes the socket.");
}

void cs_detect_network(cs_analysis *a) {
    detect_connect_failures(a);
    detect_retry_storm(a);
    detect_dns(a);
    detect_slow_peers(a);
    detect_resets(a);
    detect_premature_eof(a);
    detect_leaks(a);
}
