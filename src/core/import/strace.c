/* strace output importer.
 *
 * Handles the common output shapes:
 *   1234  14:02:11.004211 connect(3, {sa_family=AF_INET, sin_port=htons(80), ...}, 16) = 0 <0.0004>
 *   [pid  1234] 14:02:11.004211 recvfrom(3, "...", 4096, 0, NULL, NULL) = 512 <0.200>
 *   1793750400.004211 close(3) = 0
 *   1234  14:02:11.0 connect(3, {...}, 16 <unfinished ...>
 *   1234  14:02:11.2 <... connect resumed>) = -1 ETIMEDOUT (Connection timed out) <0.2>
 *   1234  14:02:12.0 --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=NULL} ---
 *   1234  14:02:12.0 +++ killed by SIGSEGV (core dumped) +++
 *   1234  14:02:12.0 +++ exited with 1 +++ */
#include "callscope/import.h"

#include <ctype.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "callscope/strbuf.h"
#include "callscope/timeutil.h"

typedef struct {
    int is_sock;
    int pending; /* non-blocking connect in progress */
    char proto[8];
    char peer[96];
    int64_t opened, conn_start;
    int64_t sent, recvd;
} sock_state;

typedef struct {
    char name[32];
    char args[1024];
    int64_t ts;
} pending_call;

struct cs_strace_importer {
    cs_eventlog *log;
    cs_strace_opts opts;
    cs_hashmap socks;   /* "pid:fd" -> sock_state* */
    cs_hashmap pending; /* "pid" -> pending_call* */
    size_t events;
};

int64_t cs_parse_date(const char *ymd) {
    int y, m, d;
    if (!ymd || sscanf(ymd, "%d-%d-%d", &y, &m, &d) != 3) return -1;
    struct tm tm;
    memset(&tm, 0, sizeof tm);
    tm.tm_year = y - 1900;
    tm.tm_mon = m - 1;
    tm.tm_mday = d;
    time_t t = timegm(&tm);
    return t < 0 ? -1 : (int64_t)t * CS_NS_PER_S;
}

static int64_t today_midnight(void) {
    int64_t now = cs_now_ns();
    return now - now % (86400LL * CS_NS_PER_S);
}

cs_strace_importer *cs_strace_importer_new(cs_eventlog *log, const cs_strace_opts *opts) {
    cs_strace_importer *imp = calloc(1, sizeof(*imp));
    if (!imp) return NULL;
    imp->log = log;
    if (opts) imp->opts = *opts;
    if (!imp->opts.base_day_ns) imp->opts.base_day_ns = today_midnight();
    if (!imp->opts.default_pid) imp->opts.default_pid = 1;
    cs_hm_init(&imp->socks);
    cs_hm_init(&imp->pending);
    return imp;
}

void cs_strace_importer_free(cs_strace_importer *imp) {
    if (!imp) return;
    cs_hm_free(&imp->socks, free);
    cs_hm_free(&imp->pending, free);
    free(imp);
}

static sock_state *sock_get(cs_strace_importer *imp, int pid, int fd, int create) {
    char key[32];
    snprintf(key, sizeof key, "%d:%d", pid, fd);
    if (!create) return cs_hm_get(&imp->socks, key);
    void **slot = cs_hm_slot(&imp->socks, key);
    if (!slot) return NULL;
    if (!*slot) *slot = calloc(1, sizeof(sock_state));
    return *slot;
}

static void sock_drop(cs_strace_importer *imp, int pid, int fd) {
    sock_state *s = sock_get(imp, pid, fd, 0);
    if (s) memset(s, 0, sizeof *s);
}

/* ---- small lexing helpers -------------------------------------------------- */

static const char *skip_sp(const char *p) {
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

/* Parse "14:02:11.004211" (time of day) or "1793750400.004211" (epoch). */
static int parse_ts(const char **pp, int64_t base_day, int64_t *out) {
    const char *p = *pp;
    if (!isdigit((unsigned char)*p)) return -1;
    char *end;
    if (strchr(p, ':') && strchr(p, ':') < strchr(p, ' ')) {
        int h, m, s;
        if (sscanf(p, "%d:%d:%d", &h, &m, &s) != 3) return -1;
        const char *dot = p;
        while (*dot && *dot != '.' && *dot != ' ') dot++;
        int64_t frac = 0;
        int digits = 0;
        if (*dot == '.') {
            dot++;
            while (isdigit((unsigned char)*dot)) {
                if (digits < 9) {
                    frac = frac * 10 + (*dot - '0');
                    digits++;
                }
                dot++;
            }
        }
        while (digits < 9) {
            frac *= 10;
            digits++;
        }
        *out = base_day + ((int64_t)h * 3600 + m * 60 + s) * CS_NS_PER_S + frac;
        *pp = dot;
        return 0;
    }
    long long secs = strtoll(p, &end, 10);
    int64_t frac = 0;
    if (*end == '.') {
        const char *q = end + 1;
        int digits = 0;
        while (isdigit((unsigned char)*q)) {
            if (digits < 9) {
                frac = frac * 10 + (*q - '0');
                digits++;
            }
            q++;
        }
        while (digits < 9) {
            frac *= 10;
            digits++;
        }
        end = (char *)q;
    }
    if (secs < 100000) return -1; /* relative -r timestamps are not supported */
    *out = (int64_t)secs * CS_NS_PER_S + frac;
    *pp = end;
    return 0;
}

/* Extract the peer from strace's sockaddr rendering. */
static void parse_sockaddr(const char *args, char *peer, size_t n, char *proto, size_t pn) {
    peer[0] = '\0';
    const char *fam = strstr(args, "sa_family=");
    if (!fam) return;
    if (strncmp(fam + 10, "AF_UNIX", 7) == 0) {
        const char *sp = strstr(fam, "sun_path=");
        if (sp) {
            sp += 9;
            if (*sp == '@') sp++;
            if (*sp == '"') sp++;
            size_t k = strcspn(sp, "\"}");
            if (k > 80) k = 80;
            snprintf(peer, n, "unix:%.*s", (int)k, sp);
        }
        if (proto) snprintf(proto, pn, "unix");
        return;
    }
    unsigned port = 0;
    const char *pp = strstr(fam, "port=htons(");
    if (pp) port = (unsigned)strtoul(pp + 11, NULL, 10);
    const char *ip = strstr(fam, "inet_addr(\"");
    if (ip) {
        ip += 11;
        size_t k = strcspn(ip, "\"");
        snprintf(peer, n, "%.*s:%u", (int)(k < 46 ? k : 46), ip, port);
        return;
    }
    ip = strstr(fam, "inet_pton(AF_INET6, \"");
    if (ip) {
        ip += 21;
        size_t k = strcspn(ip, "\"");
        snprintf(peer, n, "[%.*s]:%u", (int)(k < 46 ? k : 46), ip, port);
    }
}

/* Leading fd argument, understanding -yy annotations like 3<TCP:[a:1->b:2]>. */
static int parse_fd_arg(const char *args, char *annot_peer, size_t n, char *proto, size_t pn) {
    annot_peer[0] = '\0';
    char *end;
    long fd = strtol(args, &end, 10);
    if (end == args) return -1;
    if (*end == '<') {
        const char *close = strchr(end, '>');
        const char *tcp = strstr(end, "TCP");
        const char *udp = strstr(end, "UDP");
        if ((tcp && (!close || tcp < close)) || (udp && (!close || udp < close))) {
            snprintf(proto, pn, "%s", (tcp && (!close || tcp < close)) ? "tcp" : "udp");
            const char *arrow = strstr(end, "->");
            if (arrow && (!close || arrow < close)) {
                arrow += 2;
                size_t k = strcspn(arrow, "]>");
                if (k > 90) k = 90;
                snprintf(annot_peer, n, "%.*s", (int)k, arrow);
            }
        }
    }
    return (int)fd;
}

typedef struct {
    int pid;
    int64_t ts;
    char name[32];
    const char *args; /* everything after '(' */
    long long rc;
    int has_rc;
    char err[32];
    int64_t dur;
} call_t;

/* Parse "= -1 ECONNREFUSED (Connection refused) <0.000123>" from the tail. */
static void parse_result(const char *tail, call_t *c) {
    c->has_rc = 0;
    c->err[0] = '\0';
    c->dur = -1;
    const char *eq = NULL;
    for (const char *p = tail; (p = strstr(p, ") = ")) != NULL; p++) eq = p;
    if (!eq) return;
    const char *p = eq + 4;
    char *end;
    c->rc = strtoll(p, &end, 0);
    if (end == p) {
        if (*p == '?') c->rc = 0;
        else return;
    }
    c->has_rc = 1;
    p = skip_sp(end);
    if (*p == 'E' && isupper((unsigned char)p[1])) {
        size_t k = 0;
        while (k < sizeof c->err - 1 && (isupper((unsigned char)p[k]) || isdigit((unsigned char)p[k]) || p[k] == '_'))
            k++;
        memcpy(c->err, p, k);
        c->err[k] = '\0';
    }
    const char *lt = strrchr(p, '<');
    if (lt) {
        double secs = strtod(lt + 1, &end);
        if (end != lt + 1 && *end == '>') c->dur = (int64_t)(secs * 1e9);
    }
}

static int is_one_of(const char *name, const char *const *set) {
    for (; *set; set++)
        if (strcmp(name, *set) == 0) return 1;
    return 0;
}

static const char *const SENDS[] = {"send", "sendto", "sendmsg", "sendmmsg", "write", "writev", NULL};
static const char *const RECVS[] = {"recv", "recvfrom", "recvmsg", "recvmmsg", "read", "readv", NULL};

static int add(cs_strace_importer *imp, cs_event *ev) {
    ev->line = 0;
    if (cs_eventlog_add(imp->log, ev) == 0) {
        imp->events++;
        return 1;
    }
    return 0;
}

static int emit_pending(cs_strace_importer *imp, call_t *c, int fd, sock_state *s, const char *err) {
    s->pending = 0;
    cs_event ev;
    cs_event_init(&ev, CS_EV_NET_CONNECT);
    ev.ts = s->conn_start;
    ev.pid = ev.tid = c->pid;
    ev.fd = fd;
    ev.peer = s->peer[0] ? s->peer : NULL;
    ev.proto = s->proto;
    ev.rc = err ? -1 : 0;
    ev.err = err;
    ev.err_no = cs_errno_from_name(err);
    ev.dur = c->ts - s->conn_start;
    return add(imp, &ev);
}

static int handle_call(cs_strace_importer *imp, call_t *c) {
    char annot[96], proto[8] = "";
    cs_event ev;
    const char *name = c->name;

    if (strcmp(name, "socket") == 0) {
        if (!c->has_rc || c->rc < 0) return 0;
        if (!strstr(c->args, "AF_INET") && !strstr(c->args, "AF_UNIX")) return 0;
        sock_state *s = sock_get(imp, c->pid, (int)c->rc, 1);
        if (!s) return 0;
        memset(s, 0, sizeof *s);
        s->is_sock = 1;
        s->opened = c->ts;
        snprintf(s->proto, sizeof s->proto, "%s",
                 strstr(c->args, "AF_UNIX") ? "unix" : strstr(c->args, "SOCK_DGRAM") ? "udp" : "tcp");
        return 0;
    }

    int fd = parse_fd_arg(c->args, annot, sizeof annot, proto, sizeof proto);
    if (fd < 0) return 0;

    if (strcmp(name, "connect") == 0) {
        sock_state *s = sock_get(imp, c->pid, fd, 1);
        if (!s) return 0;
        if (!s->is_sock) {
            s->is_sock = 1;
            s->opened = c->ts;
            snprintf(s->proto, sizeof s->proto, "%s", proto[0] ? proto : "tcp");
        }
        parse_sockaddr(c->args, s->peer, sizeof s->peer, s->proto, sizeof s->proto);
        if (strcmp(c->err, "EINPROGRESS") == 0) { /* outcome shows up later */
            s->pending = 1;
            s->conn_start = c->ts;
            return 0;
        }
        cs_event_init(&ev, CS_EV_NET_CONNECT);
        ev.ts = c->ts;
        ev.pid = ev.tid = c->pid;
        ev.fd = fd;
        ev.peer = s->peer[0] ? s->peer : NULL;
        ev.proto = s->proto;
        ev.rc = c->rc;
        ev.err = c->err[0] ? c->err : NULL;
        ev.err_no = cs_errno_from_name(ev.err);
        ev.dur = c->dur;
        return add(imp, &ev);
    }

    if (strcmp(name, "accept") == 0 || strcmp(name, "accept4") == 0) {
        if (!c->has_rc || c->rc < 0) return 0;
        sock_state *s = sock_get(imp, c->pid, (int)c->rc, 1);
        if (!s) return 0;
        memset(s, 0, sizeof *s);
        s->is_sock = 1;
        s->opened = c->ts;
        snprintf(s->proto, sizeof s->proto, "tcp");
        parse_sockaddr(c->args, s->peer, sizeof s->peer, NULL, 0);
        cs_event_init(&ev, CS_EV_NET_ACCEPT);
        ev.ts = c->ts;
        ev.pid = ev.tid = c->pid;
        ev.fd = (int)c->rc;
        ev.peer = s->peer[0] ? s->peer : NULL;
        ev.proto = s->proto;
        ev.dur = c->dur;
        return add(imp, &ev);
    }

    if (strcmp(name, "getsockopt") == 0 && strstr(c->args, "SO_ERROR")) {
        sock_state *s = sock_get(imp, c->pid, fd, 0);
        if (!s || !s->pending) return 0;
        const char *br = strchr(strstr(c->args, "SO_ERROR"), '[');
        char err[32] = "";
        if (br && br[1] == 'E') {
            size_t k = strcspn(br + 1, "]");
            if (k >= sizeof err) k = sizeof err - 1;
            memcpy(err, br + 1, k);
            err[k] = '\0';
        }
        if (!strcmp(err, "EINPROGRESS")) return 0;
        return emit_pending(imp, c, fd, s, err[0] ? err : NULL);
    }

    int is_send = is_one_of(name, SENDS), is_recv = is_one_of(name, RECVS);
    if (is_send || is_recv) {
        sock_state *s = sock_get(imp, c->pid, fd, annot[0] || proto[0]);
        if (!s) return 0;
        if (!s->is_sock && (annot[0] || proto[0])) {
            s->is_sock = 1;
            s->opened = c->ts;
            snprintf(s->proto, sizeof s->proto, "%s", proto[0] ? proto : "tcp");
            snprintf(s->peer, sizeof s->peer, "%s", annot);
        }
        if (!s->is_sock) return 0;
        int extra = 0;
        if (s->pending) extra = emit_pending(imp, c, fd, s, NULL); /* first I/O = connected */
        (void)extra;
        if (!s->peer[0] && strncmp(name, "sendto", 6) == 0)
            parse_sockaddr(c->args, s->peer, sizeof s->peer, NULL, 0);
        if (c->has_rc && c->rc > 0) {
            if (is_send) s->sent += c->rc;
            else s->recvd += c->rc;
        }
        if (strcmp(c->err, "EAGAIN") == 0) return 0;
        cs_event_init(&ev, is_send ? CS_EV_NET_SEND : CS_EV_NET_RECV);
        ev.ts = c->ts;
        ev.pid = ev.tid = c->pid;
        ev.fd = fd;
        ev.peer = s->peer[0] ? s->peer : NULL;
        ev.proto = s->proto;
        ev.rc = c->rc;
        ev.bytes = c->rc > 0 ? c->rc : 0;
        ev.err = c->err[0] ? c->err : NULL;
        ev.err_no = cs_errno_from_name(ev.err);
        ev.dur = c->dur;
        return add(imp, &ev);
    }

    if (strcmp(name, "close") == 0) {
        sock_state *s = sock_get(imp, c->pid, fd, 0);
        if (!s || !s->is_sock) return 0;
        cs_event_init(&ev, CS_EV_NET_CLOSE);
        ev.ts = c->ts;
        ev.pid = ev.tid = c->pid;
        ev.fd = fd;
        ev.peer = s->peer[0] ? s->peer : NULL;
        ev.proto = s->proto;
        ev.sent = s->sent;
        ev.recvd = s->recvd;
        ev.dur = c->ts - s->opened;
        int r = add(imp, &ev);
        sock_drop(imp, c->pid, fd);
        return r;
    }
    return 0;
}

static int signal_from_name(const char *p) {
    static const struct {
        const char *n;
        int s;
    } t[] = {{"SIGSEGV", SIGSEGV}, {"SIGABRT", SIGABRT}, {"SIGBUS", SIGBUS}, {"SIGFPE", SIGFPE},
             {"SIGILL", SIGILL},   {"SIGPIPE", SIGPIPE}, {"SIGKILL", SIGKILL}, {"SIGTERM", SIGTERM}};
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
        if (strncmp(p, t[i].n, strlen(t[i].n)) == 0) return t[i].s;
    return 0;
}

int cs_strace_importer_line(cs_strace_importer *imp, const char *line) {
    const char *p = skip_sp(line);
    int pid = imp->opts.default_pid;
    if (strncmp(p, "[pid", 4) == 0) {
        pid = (int)strtol(p + 4, (char **)&p, 10);
        if (*p == ']') p++;
        p = skip_sp(p);
    } else {
        /* "1234  14:02:11.0 ..." has a pid column followed by two spaces */
        const char *q = p;
        while (isdigit((unsigned char)*q)) q++;
        if (q != p && (*q == ' ' || *q == '\t')) {
            const char *after = skip_sp(q);
            if (isdigit((unsigned char)*after)) {
                pid = (int)strtol(p, NULL, 10);
                p = after;
            }
        }
    }
    int64_t ts = 0;
    if (parse_ts(&p, imp->opts.base_day_ns, &ts) != 0) return 0;
    p = skip_sp(p);

    cs_event ev;
    if (strncmp(p, "---", 3) == 0) { /* signal delivery */
        int sig = signal_from_name(skip_sp(p + 3));
        if (sig == SIGSEGV || sig == SIGABRT || sig == SIGBUS || sig == SIGFPE || sig == SIGILL) {
            cs_event_init(&ev, CS_EV_SIGNAL);
            ev.ts = ts;
            ev.pid = ev.tid = pid;
            ev.sig = sig;
            return add(imp, &ev);
        }
        return 0;
    }
    if (strncmp(p, "+++", 3) == 0) {
        const char *q = skip_sp(p + 3);
        cs_event_init(&ev, CS_EV_PROC_EXIT);
        ev.ts = ts;
        ev.pid = ev.tid = pid;
        if (strncmp(q, "exited with", 11) == 0) {
            ev.rc = strtol(q + 11, NULL, 10);
        } else if (strncmp(q, "killed by", 9) == 0) {
            ev.sig = signal_from_name(skip_sp(q + 9));
            ev.rc = 128 + ev.sig;
            ev.msg = "killed by signal";
        } else {
            return 0;
        }
        return add(imp, &ev);
    }

    call_t c;
    memset(&c, 0, sizeof c);
    c.pid = pid;
    c.ts = ts;
    char joined[2048];

    if (strncmp(p, "<...", 4) == 0) { /* resumed call */
        const char *q = skip_sp(p + 4);
        size_t k = strcspn(q, " ");
        if (k >= sizeof c.name) return 0;
        memcpy(c.name, q, k);
        c.name[k] = '\0';
        char key[16];
        snprintf(key, sizeof key, "%d", pid);
        pending_call *pc = cs_hm_get(&imp->pending, key);
        const char *rest = strstr(q, "resumed>");
        if (!rest) return 0;
        rest += 8;
        snprintf(joined, sizeof joined, "%s%s", (pc && strcmp(pc->name, c.name) == 0) ? pc->args : "", rest);
        if (pc) {
            c.ts = pc->ts;
            pc->name[0] = '\0';
        }
        c.args = joined;
        parse_result(joined, &c);
        return handle_call(imp, &c);
    }

    size_t k = 0;
    while (p[k] && (isalnum((unsigned char)p[k]) || p[k] == '_')) k++;
    if (!k || p[k] != '(' || k >= sizeof c.name) return 0;
    memcpy(c.name, p, k);
    c.name[k] = '\0';
    const char *args = p + k + 1;

    const char *unf = strstr(args, "<unfinished ...>");
    if (unf) {
        char key[16];
        snprintf(key, sizeof key, "%d", pid);
        void **slot = cs_hm_slot(&imp->pending, key);
        if (!slot) return 0;
        if (!*slot) *slot = calloc(1, sizeof(pending_call));
        pending_call *pc = *slot;
        if (!pc) return 0;
        snprintf(pc->name, sizeof pc->name, "%s", c.name);
        size_t alen = (size_t)(unf - args);
        if (alen >= sizeof pc->args) alen = sizeof pc->args - 1;
        memcpy(pc->args, args, alen);
        pc->args[alen] = '\0';
        pc->ts = ts;
        return 0;
    }
    c.args = args;
    parse_result(args, &c);
    return handle_call(imp, &c);
}

int cs_import_strace(cs_eventlog *log, FILE *fp, const cs_strace_opts *opts,
                     cs_import_stats *stats) {
    cs_strace_importer *imp = cs_strace_importer_new(log, opts);
    if (!imp) return -1;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    cs_import_stats st = {0};
    while ((n = getline(&line, &cap, fp)) >= 0) {
        st.lines++;
        if (cs_strace_importer_line(imp, line) == 0) st.skipped++;
    }
    free(line);
    st.events = imp->events;
    cs_strace_importer_free(imp);
    cs_eventlog_finish(log);
    if (stats) *stats = st;
    return 0;
}
