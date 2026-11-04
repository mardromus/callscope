/* Event kind tables, errno/signal names and the allocation-free JSONL encoder.
 * This file is compiled into both the analysis library and the runtime hooks. */
#include "callscope/event.h"

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

static const char *const kind_names[CS_EV__COUNT] = {
    [CS_EV_UNKNOWN] = "unknown",         [CS_EV_PROC_START] = "proc_start",
    [CS_EV_PROC_EXIT] = "proc_exit",     [CS_EV_SIGNAL] = "signal",
    [CS_EV_FN_ENTER] = "fn_enter",       [CS_EV_FN_EXIT] = "fn_exit",
    [CS_EV_NET_CONNECT] = "net_connect", [CS_EV_NET_ACCEPT] = "net_accept",
    [CS_EV_NET_SEND] = "net_send",       [CS_EV_NET_RECV] = "net_recv",
    [CS_EV_NET_CLOSE] = "net_close",     [CS_EV_NET_DNS] = "net_dns",
    [CS_EV_APP_ERROR] = "app_error",     [CS_EV_APP_LOG] = "app_log",
};

void cs_event_init(cs_event *ev, cs_event_kind kind) {
    memset(ev, 0, sizeof(*ev));
    ev->kind = kind;
    ev->dur = -1;
    ev->depth = -1;
    ev->fd = -1;
}

const char *cs_event_kind_name(cs_event_kind k) {
    return (k >= 0 && k < CS_EV__COUNT && kind_names[k]) ? kind_names[k] : "unknown";
}

cs_event_kind cs_event_kind_parse(const char *name) {
    if (!name) return CS_EV_UNKNOWN;
    for (int k = 1; k < CS_EV__COUNT; k++)
        if (strcmp(kind_names[k], name) == 0) return (cs_event_kind)k;
    return CS_EV_UNKNOWN;
}

int cs_event_is_net(cs_event_kind k) { return k >= CS_EV_NET_CONNECT && k <= CS_EV_NET_DNS; }
int cs_event_is_fn(cs_event_kind k) { return k == CS_EV_FN_ENTER || k == CS_EV_FN_EXIT; }

typedef struct {
    int code;
    const char *name;
} code_name;

#define E(x) {x, #x}
static const code_name errno_table[] = {
    E(EPERM),        E(ENOENT),       E(EINTR),        E(EIO),          E(EBADF),
    E(EAGAIN),       E(ENOMEM),       E(EACCES),       E(EFAULT),       E(EINVAL),
    E(ENFILE),       E(EMFILE),       E(EPIPE),        E(ENOTSOCK),     E(EMSGSIZE),
    E(EPROTOTYPE),   E(ENOPROTOOPT),  E(EPROTONOSUPPORT), E(EOPNOTSUPP), E(EAFNOSUPPORT),
    E(EADDRINUSE),   E(EADDRNOTAVAIL), E(ENETDOWN),    E(ENETUNREACH),  E(ENETRESET),
    E(ECONNABORTED), E(ECONNRESET),   E(ENOBUFS),      E(EISCONN),      E(ENOTCONN),
    E(ETIMEDOUT),    E(ECONNREFUSED), E(EHOSTDOWN),    E(EHOSTUNREACH), E(EALREADY),
    E(EINPROGRESS),
};

static const code_name eai_table[] = {
    E(EAI_AGAIN),  E(EAI_BADFLAGS), E(EAI_FAIL),    E(EAI_FAMILY),   E(EAI_MEMORY),
    E(EAI_NONAME), E(EAI_SERVICE),  E(EAI_SOCKTYPE), E(EAI_SYSTEM),  E(EAI_OVERFLOW),
};

static const code_name signal_table[] = {
    E(SIGSEGV), E(SIGABRT), E(SIGBUS), E(SIGFPE), E(SIGILL), E(SIGPIPE), E(SIGTERM), E(SIGINT),
};
#undef E

static const char *lookup(const code_name *t, size_t n, int code) {
    for (size_t i = 0; i < n; i++)
        if (t[i].code == code) return t[i].name;
    return NULL;
}

#define COUNT(t) (sizeof(t) / sizeof((t)[0]))

const char *cs_errno_name(int err) {
    if (err == EWOULDBLOCK) return "EAGAIN";
    return lookup(errno_table, COUNT(errno_table), err);
}

int cs_errno_from_name(const char *name) {
    if (!name) return 0;
    for (size_t i = 0; i < COUNT(errno_table); i++)
        if (strcmp(errno_table[i].name, name) == 0) return errno_table[i].code;
    return 0;
}

const char *cs_eai_name(int code) { return lookup(eai_table, COUNT(eai_table), code); }
const char *cs_signal_name(int sig) { return lookup(signal_table, COUNT(signal_table), sig); }

/* ---- allocation-free JSONL encoder --------------------------------------- */

typedef struct {
    char *buf;
    size_t n;   /* capacity */
    size_t len; /* bytes written, always < n */
} out_t;

static void put(out_t *o, const char *s, size_t k) {
    if (o->len + 1 >= o->n) return;
    size_t room = o->n - 1 - o->len;
    if (k > room) k = room;
    memcpy(o->buf + o->len, s, k);
    o->len += k;
    o->buf[o->len] = '\0';
}

static void puts_(out_t *o, const char *s) { put(o, s, strlen(s)); }

static void put_esc(out_t *o, const char *s, size_t max) {
    static const char hex[] = "0123456789abcdef";
    put(o, "\"", 1);
    size_t used = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p && used < max; p++, used++) {
        char esc[7];
        switch (*p) {
        case '"': put(o, "\\\"", 2); break;
        case '\\': put(o, "\\\\", 2); break;
        case '\n': put(o, "\\n", 2); break;
        case '\r': put(o, "\\r", 2); break;
        case '\t': put(o, "\\t", 2); break;
        default:
            if (*p < 0x20) {
                memcpy(esc, "\\u00", 4);
                esc[4] = hex[*p >> 4];
                esc[5] = hex[*p & 15];
                put(o, esc, 6);
            } else {
                put(o, (const char *)p, 1);
            }
        }
    }
    put(o, "\"", 1);
}

static void kv_i64(out_t *o, const char *k, long long v) {
    char tmp[48];
    int m = snprintf(tmp, sizeof tmp, ",\"%s\":%lld", k, v);
    if (m > 0) put(o, tmp, (size_t)m);
}

static void kv_str(out_t *o, const char *k, const char *v, size_t max) {
    if (!v) return;
    put(o, ",\"", 2);
    puts_(o, k);
    put(o, "\":", 2);
    put_esc(o, v, max);
}

size_t cs_event_to_jsonl(const cs_event *ev, char *buf, size_t n) {
    out_t o = {buf, n, 0};
    if (n == 0) return 0;
    buf[0] = '\0';
    char head[128];
    int m = snprintf(head, sizeof head, "{\"ts\":%lld,\"pid\":%d,\"tid\":%d,\"k\":\"%s\"",
                     (long long)ev->ts, ev->pid, ev->tid, cs_event_kind_name(ev->kind));
    if (m > 0) put(&o, head, (size_t)m);

    kv_str(&o, "fn", ev->fn, 200);
    if (ev->addr) {
        char tmp[48];
        int k = snprintf(tmp, sizeof tmp, ",\"addr\":\"0x%llx\"", (unsigned long long)ev->addr);
        if (k > 0) put(&o, tmp, (size_t)k);
    }
    if (ev->depth >= 0) kv_i64(&o, "depth", ev->depth);
    if (ev->fd >= 0) kv_i64(&o, "fd", ev->fd);
    kv_str(&o, "proto", ev->proto, 16);
    kv_str(&o, "peer", ev->peer, 128);
    kv_str(&o, "host", ev->host, 256);
    if (cs_event_is_net(ev->kind) || ev->kind == CS_EV_PROC_EXIT) kv_i64(&o, "rc", ev->rc);
    if (ev->err_no) {
        kv_i64(&o, "errno", ev->err_no);
        kv_str(&o, "err", ev->err ? ev->err : cs_errno_name(ev->err_no), 32);
    } else if (ev->err) {
        kv_str(&o, "err", ev->err, 32);
    }
    if (ev->kind == CS_EV_SIGNAL) {
        kv_i64(&o, "sig", ev->sig);
        const char *sn = cs_signal_name(ev->sig);
        if (sn && !ev->err) kv_str(&o, "err", sn, 16);
    }
    if (ev->kind == CS_EV_NET_SEND || ev->kind == CS_EV_NET_RECV) kv_i64(&o, "bytes", ev->bytes);
    if (ev->kind == CS_EV_NET_CLOSE) {
        kv_i64(&o, "sent", ev->sent);
        kv_i64(&o, "recvd", ev->recvd);
    }
    if (ev->dur >= 0) kv_i64(&o, "dur", ev->dur);
    kv_str(&o, "code", ev->code, 64);
    kv_str(&o, "msg", ev->msg, 1024);

    /* always terminate the object and the line, even if truncated */
    if (o.len + 3 > n) o.len = n >= 3 ? n - 3 : 0;
    buf[o.len++] = '}';
    buf[o.len++] = '\n';
    buf[o.len] = '\0';
    return o.len;
}
