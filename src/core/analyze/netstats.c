/* Network sessions: stitch connect/send/recv/close events into connections,
 * then aggregate per remote peer and per DNS name. */
#include "callscope/analyze.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *UNKNOWN_PEER = "(unknown peer)";

static cs_netconn *conn_at(cs_netstats *s, size_t i) { return cs_vec_at(&s->conns, i); }

static size_t open_conn(cs_netstats *s, cs_hashmap *active, const cs_event *ev, size_t evi) {
    char key[32];
    snprintf(key, sizeof key, "%d:%d", ev->pid, ev->fd);
    cs_netconn *c = cs_vec_push_slot(&s->conns);
    if (!c) return CS_NONE;
    size_t idx = s->conns.len - 1;
    c->pid = ev->pid;
    c->tid = ev->tid;
    c->fd = ev->fd;
    c->peer = ev->peer ? ev->peer : UNKNOWN_PEER;
    c->proto = ev->proto ? ev->proto : "tcp";
    c->t_open = ev->ts;
    c->connect_dur = -1;
    c->first_ev = c->last_ev = evi;
    cs_hm_put(active, key, (void *)(uintptr_t)(idx + 1));
    return idx;
}

static size_t find_conn(cs_hashmap *active, const cs_event *ev) {
    char key[32];
    snprintf(key, sizeof key, "%d:%d", ev->pid, ev->fd);
    uintptr_t v = (uintptr_t)cs_hm_get(active, key);
    return v ? (size_t)(v - 1) : CS_NONE;
}

static void forget_conn(cs_hashmap *active, const cs_event *ev) {
    char key[32];
    snprintf(key, sizeof key, "%d:%d", ev->pid, ev->fd);
    void **slot = cs_hm_slot(active, key);
    if (slot) *slot = NULL;
}

static cs_dnsstat *dns_for(cs_netstats *s, cs_hashmap *dnsmap, const char *host) {
    void **slot = cs_hm_slot(dnsmap, host);
    if (!slot) return NULL;
    if (!*slot) {
        cs_dnsstat *d = cs_vec_push_slot(&s->dns);
        if (!d) return NULL;
        d->host = host;
        *slot = (void *)(uintptr_t)s->dns.len;
    }
    return cs_vec_at(&s->dns, (size_t)(uintptr_t)*slot - 1);
}

static cs_peerstat *peer_for(cs_vec *peers, cs_hashmap *peermap, const char *peer) {
    void **slot = cs_hm_slot(peermap, peer);
    if (!slot) return NULL;
    if (!*slot) {
        cs_peerstat *p = cs_vec_push_slot(peers);
        if (!p) return NULL;
        p->peer = peer;
        p->first_ts = INT64_MAX;
        *slot = (void *)(uintptr_t)peers->len;
    }
    return cs_vec_at(peers, (size_t)(uintptr_t)*slot - 1);
}

static void peer_count_err(cs_peerstat *p, const char *name) {
    if (!name) return;
    for (int i = 0; i < CS_PEER_ERRS; i++) {
        if (p->err_name[i] && strcmp(p->err_name[i], name) == 0) {
            p->err_count[i]++;
            return;
        }
        if (!p->err_name[i]) {
            p->err_name[i] = name;
            p->err_count[i] = 1;
            return;
        }
    }
}

const char *cs_peerstat_top_err(const cs_peerstat *p, int64_t *count) {
    const char *best = NULL;
    int64_t bc = 0;
    for (int i = 0; i < CS_PEER_ERRS; i++)
        if (p->err_name[i] && p->err_count[i] > bc) {
            best = p->err_name[i];
            bc = p->err_count[i];
        }
    if (count) *count = bc;
    return best;
}

static const char *err_label(const cs_event *ev) {
    if (ev->err) return ev->err;
    if (ev->err_no) return cs_errno_name(ev->err_no);
    return NULL;
}

static int cmp_peer(const void *a, const void *b) {
    const cs_peerstat *x = a, *y = b;
    int64_t ax = x->attempts + x->accepts, ay = y->attempts + y->accepts;
    if (ax != ay) return ax < ay ? 1 : -1;
    return strcmp(x->peer, y->peer);
}

int cs_netstats_build(cs_netstats *s, const cs_eventlog *log) {
    memset(s, 0, sizeof(*s));
    cs_vec_init(&s->conns, sizeof(cs_netconn));
    cs_vec_init(&s->peers, sizeof(cs_peerstat));
    cs_vec_init(&s->dns, sizeof(cs_dnsstat));
    cs_hashmap active, dnsmap, peermap;
    cs_hm_init(&active);
    cs_hm_init(&dnsmap);
    cs_hm_init(&peermap);

    size_t n = cs_eventlog_count(log);
    for (size_t i = 0; i < n; i++) {
        const cs_event *ev = cs_eventlog_at(log, i);
        if (!cs_event_is_net(ev->kind)) continue;

        if (ev->kind == CS_EV_NET_DNS) {
            if (!ev->host) continue;
            cs_dnsstat *d = dns_for(s, &dnsmap, ev->host);
            if (!d) goto oom;
            d->lookups++;
            if (ev->rc != 0) {
                d->failures++;
                d->last_err = ev->err ? ev->err : "EAI_FAIL";
            }
            if (ev->dur > 0) {
                d->total_dur += ev->dur;
                if (ev->dur > d->max_dur) d->max_dur = ev->dur;
            }
            d->last_ev = i;
            continue;
        }

        size_t ci = find_conn(&active, ev);
        if (ev->kind == CS_EV_NET_CONNECT || ev->kind == CS_EV_NET_ACCEPT) {
            if (ci != CS_NONE) { /* fd reused without a close we saw */
                cs_netconn *old = conn_at(s, ci);
                if (!old->closed) old->t_close = ev->ts;
            }
            ci = open_conn(s, &active, ev, i);
            if (ci == CS_NONE) goto oom;
            cs_netconn *c = conn_at(s, ci);
            if (ev->kind == CS_EV_NET_ACCEPT) {
                c->accepted = 1;
                c->connected = 1;
            } else {
                c->connect_dur = ev->dur;
                c->connect_rc = ev->rc;
                c->connect_err = ev->rc < 0 ? (ev->err_no ? ev->err_no : -1) : 0;
                c->connected = ev->rc >= 0;
            }
            continue;
        }

        if (ci == CS_NONE) { /* trace started mid-connection */
            ci = open_conn(s, &active, ev, i);
            if (ci == CS_NONE) goto oom;
            conn_at(s, ci)->connected = 1;
        }
        cs_netconn *c = conn_at(s, ci);
        c->last_ev = i;
        if (c->peer == UNKNOWN_PEER && ev->peer) c->peer = ev->peer;

        if (ev->kind == CS_EV_NET_SEND || ev->kind == CS_EV_NET_RECV) {
            int is_send = ev->kind == CS_EV_NET_SEND;
            if (ev->rc < 0) {
                c->io_errors++;
                if (ev->err_no == ECONNRESET || ev->err_no == EPIPE) c->reset = 1;
            } else if (!is_send && ev->rc == 0) {
                c->eof = 1;
            }
            if (is_send) {
                c->n_send++;
                c->sent += ev->bytes;
            } else {
                c->n_recv++;
                c->recvd += ev->bytes;
            }
            if (ev->dur > 0) {
                c->io_time += ev->dur;
                s->total_io_time += ev->dur;
                if (ev->dur > c->max_io) c->max_io = ev->dur;
            }
        } else if (ev->kind == CS_EV_NET_CLOSE) {
            c->closed = 1;
            c->t_close = ev->ts;
            if (ev->sent > c->sent) c->sent = ev->sent;
            if (ev->recvd > c->recvd) c->recvd = ev->recvd;
            forget_conn(&active, ev);
        }
    }

    /* per-peer aggregation */
    for (size_t i = 0; i < s->conns.len; i++) {
        const cs_netconn *c = conn_at(s, i);
        cs_peerstat *p = peer_for(&s->peers, &peermap, c->peer);
        if (!p) goto oom;
        const cs_event *first = cs_eventlog_at(log, c->first_ev);
        if (c->accepted) {
            p->accepts++;
        } else if (first->kind == CS_EV_NET_CONNECT) {
            p->attempts++;
            if (c->connect_rc < 0) {
                p->failures++;
                peer_count_err(p, err_label(first));
            }
            if (c->connect_dur >= 0) {
                p->connect_total += c->connect_dur;
                p->connect_n++;
                if (c->connect_dur > p->connect_max) p->connect_max = c->connect_dur;
            }
        }
        p->sent += c->sent;
        p->recvd += c->recvd;
        p->io_time += c->io_time;
        if (c->max_io > p->io_max) p->io_max = c->max_io;
        p->resets += c->reset;
        p->eofs += c->eof;
        p->io_errors += c->io_errors;
        if (c->reset) peer_count_err(p, "ECONNRESET");
        if (c->t_open < p->first_ts) p->first_ts = c->t_open;
        int64_t last = c->closed ? c->t_close : cs_eventlog_at(log, c->last_ev)->ts;
        if (last > p->last_ts) p->last_ts = last;
        s->total_sent += c->sent;
        s->total_recvd += c->recvd;
    }
    cs_vec_sort(&s->peers, cmp_peer);

    cs_hm_free(&active, NULL);
    cs_hm_free(&dnsmap, NULL);
    cs_hm_free(&peermap, NULL);
    return 0;
oom:
    cs_hm_free(&active, NULL);
    cs_hm_free(&dnsmap, NULL);
    cs_hm_free(&peermap, NULL);
    return -1;
}

void cs_netstats_free(cs_netstats *s) {
    cs_vec_free(&s->conns);
    cs_vec_free(&s->peers);
    cs_vec_free(&s->dns);
}

const cs_peerstat *cs_netstats_peer(const cs_netstats *s, const char *peer) {
    for (size_t i = 0; i < s->peers.len; i++) {
        const cs_peerstat *p = cs_vec_at(&s->peers, i);
        if (strcmp(p->peer, peer) == 0) return p;
    }
    return NULL;
}
