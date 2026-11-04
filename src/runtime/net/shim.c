/* Network-call tracer, loaded with LD_PRELOAD into ANY dynamically linked
 * program (no rebuild needed):
 *
 *   LD_PRELOAD=libcallscope_net.so CALLSCOPE_LOG=trace.jsonl curl http://...
 *   (or simply: callscope record -- curl http://...)
 *
 * We wrap the libc socket API, remember which fds are sockets and who they
 * talk to, and emit one event per connect/accept/dns lookup/close plus (unless
 * CALLSCOPE_NET_IO=0) one per send/recv. Non-blocking connects that return
 * EINPROGRESS are resolved later from getsockopt(SO_ERROR) or the first I/O. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "../common/rt.h"
#include "callscope/timeutil.h"

#define CS_MAX_FD 16384

typedef struct {
    unsigned char is_sock;
    unsigned char pending; /* non-blocking connect still in flight */
    unsigned char announced;
    char proto[6];
    char peer[72];
    int64_t conn_start;
    int64_t opened;
    int64_t sent, recvd;
} fdinfo;

static fdinfo g_fds[CS_MAX_FD];
static int g_io_events = 1;
static __thread int t_inside; /* >0 while inside a wrapper (e.g. getaddrinfo) */

/* ---- real libc entry points ---------------------------------------------- */
typedef int (*socket_fn)(int, int, int);
typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*accept_fn)(int, struct sockaddr *, socklen_t *);
typedef int (*accept4_fn)(int, struct sockaddr *, socklen_t *, int);
typedef ssize_t (*send_fn)(int, const void *, size_t, int);
typedef ssize_t (*recv_fn)(int, void *, size_t, int);
typedef ssize_t (*sendto_fn)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef ssize_t (*recvfrom_fn)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef ssize_t (*sendmsg_fn)(int, const struct msghdr *, int);
typedef ssize_t (*recvmsg_fn)(int, struct msghdr *, int);
typedef ssize_t (*read_fn)(int, void *, size_t);
typedef ssize_t (*write_fn)(int, const void *, size_t);
typedef int (*close_fn)(int);
typedef int (*gai_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef int (*getsockopt_fn)(int, int, int, void *, socklen_t *);

static socket_fn real_socket;
static connect_fn real_connect;
static accept_fn real_accept;
static accept4_fn real_accept4;
static send_fn real_send;
static recv_fn real_recv;
static sendto_fn real_sendto;
static recvfrom_fn real_recvfrom;
static sendmsg_fn real_sendmsg;
static recvmsg_fn real_recvmsg;
static read_fn real_read;
static write_fn real_write;
static close_fn real_close;
static gai_fn real_getaddrinfo;
static getsockopt_fn real_getsockopt;

#define RESOLVE(name) real_##name = (name##_fn)dlsym(RTLD_NEXT, #name)

static void resolve_all(void) {
    RESOLVE(socket);
    RESOLVE(connect);
    RESOLVE(accept);
    RESOLVE(accept4);
    RESOLVE(send);
    RESOLVE(recv);
    RESOLVE(sendto);
    RESOLVE(recvfrom);
    RESOLVE(sendmsg);
    RESOLVE(recvmsg);
    RESOLVE(read);
    RESOLVE(write);
    RESOLVE(close);
    real_getaddrinfo = (gai_fn)dlsym(RTLD_NEXT, "getaddrinfo");
    RESOLVE(getsockopt);
}

__attribute__((constructor)) static void shim_init(void) {
    resolve_all();
    if (!cs_rt_enabled()) return;
    const char *io = getenv("CALLSCOPE_NET_IO");
    if (io && strcmp(io, "0") == 0) g_io_events = 0;
    cs_rt_proc_start("net");
}

#define ENSURE(name)                                                                               \
    do {                                                                                           \
        if (!real_##name) resolve_all();                                                           \
    } while (0)

/* ---- helpers -------------------------------------------------------------- */

static fdinfo *fdi(int fd) { return (fd >= 0 && fd < CS_MAX_FD) ? &g_fds[fd] : NULL; }

static int tracking(int fd) {
    fdinfo *f = fdi(fd);
    return f && f->is_sock && t_inside == 0 && cs_rt_enabled();
}

static void format_addr(const struct sockaddr *sa, socklen_t len, char *out, size_t n) {
    out[0] = '\0';
    if (!sa) return;
    if (sa->sa_family == AF_INET && len >= (socklen_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof ip);
        snprintf(out, n, "%s:%u", ip, (unsigned)ntohs(in->sin_port));
    } else if (sa->sa_family == AF_INET6 && len >= (socklen_t)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof ip);
        snprintf(out, n, "[%s]:%u", ip, (unsigned)ntohs(in6->sin6_port));
    } else if (sa->sa_family == AF_UNIX) {
        const struct sockaddr_un *un = (const struct sockaddr_un *)sa;
        snprintf(out, n, "unix:%.60s", un->sun_path[0] ? un->sun_path : "@abstract");
    }
}

static void mark_socket(int fd, int domain, int type) {
    fdinfo *f = fdi(fd);
    if (!f) return;
    memset(f, 0, sizeof *f);
    f->is_sock = 1;
    f->opened = cs_now_ns();
    int base = type & 0xf; /* strip SOCK_NONBLOCK / SOCK_CLOEXEC */
    const char *p = domain == AF_UNIX ? "unix" : base == SOCK_DGRAM ? "udp" : "tcp";
    snprintf(f->proto, sizeof f->proto, "%s", p);
}

static void emit_connect(int fd, int rc, int err, int64_t dur) {
    fdinfo *f = fdi(fd);
    cs_event ev;
    cs_event_init(&ev, CS_EV_NET_CONNECT);
    ev.fd = fd;
    ev.peer = f->peer[0] ? f->peer : NULL;
    ev.proto = f->proto;
    ev.rc = rc;
    ev.err_no = err;
    ev.dur = dur;
    cs_rt_emit(&ev);
    f->announced = 1;
}

static void settle_pending(int fd, int err) {
    fdinfo *f = fdi(fd);
    if (!f || !f->pending) return;
    f->pending = 0;
    emit_connect(fd, err ? -1 : 0, err, cs_now_ns() - f->conn_start);
}

static void emit_io(cs_event_kind kind, int fd, ssize_t rc, int err, int64_t dur) {
    fdinfo *f = fdi(fd);
    if (f->pending) settle_pending(fd, (rc < 0 && err != EAGAIN) ? err : 0);
    if (rc > 0) {
        if (kind == CS_EV_NET_SEND)
            f->sent += rc;
        else
            f->recvd += rc;
    }
    if (!g_io_events) return;
    if (rc < 0 && (err == EAGAIN || err == EWOULDBLOCK)) return; /* not interesting */
    cs_event ev;
    cs_event_init(&ev, kind);
    ev.fd = fd;
    ev.peer = f->peer[0] ? f->peer : NULL;
    ev.proto = f->proto;
    ev.rc = rc;
    ev.bytes = rc > 0 ? rc : 0;
    ev.err_no = rc < 0 ? err : 0;
    ev.dur = dur;
    cs_rt_emit(&ev);
}

/* ---- wrappers ------------------------------------------------------------- */

int socket(int domain, int type, int protocol) {
    ENSURE(socket);
    int fd = real_socket(domain, type, protocol);
    if (fd >= 0 && (domain == AF_INET || domain == AF_INET6 || domain == AF_UNIX))
        mark_socket(fd, domain, type);
    return fd;
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    ENSURE(connect);
    if (!tracking(fd)) return real_connect(fd, addr, len);
    fdinfo *f = fdi(fd);
    format_addr(addr, len, f->peer, sizeof f->peer);
    int64_t t0 = cs_now_ns();
    int rc = real_connect(fd, addr, len);
    int saved = errno;
    int64_t dur = cs_now_ns() - t0;
    if (rc < 0 && saved == EINPROGRESS) {
        f->pending = 1;
        f->conn_start = t0;
    } else if (strcmp(f->proto, "udp") != 0 || rc < 0) {
        emit_connect(fd, rc, rc < 0 ? saved : 0, dur);
    }
    errno = saved;
    return rc;
}

static int finish_accept(int lfd, int fd, struct sockaddr *addr, socklen_t *len, int64_t t0) {
    int saved = errno;
    if (fd >= 0 && tracking(lfd)) {
        fdinfo *l = fdi(lfd);
        mark_socket(fd, AF_INET, SOCK_STREAM);
        fdinfo *f = fdi(fd);
        if (f && l) memcpy(f->proto, l->proto, sizeof f->proto);
        if (f && addr && len) format_addr(addr, *len, f->peer, sizeof f->peer);
        cs_event ev;
        cs_event_init(&ev, CS_EV_NET_ACCEPT);
        ev.fd = fd;
        ev.peer = (f && f->peer[0]) ? f->peer : NULL;
        ev.proto = f ? f->proto : NULL;
        ev.dur = cs_now_ns() - t0;
        cs_rt_emit(&ev);
    }
    errno = saved;
    return fd;
}

int accept(int lfd, struct sockaddr *addr, socklen_t *len) {
    ENSURE(accept);
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    int64_t t0 = cs_now_ns();
    int fd = real_accept(lfd, addr ? addr : (struct sockaddr *)&ss, addr ? len : &sl);
    return finish_accept(lfd, fd, addr ? addr : (struct sockaddr *)&ss, addr ? len : &sl, t0);
}

int accept4(int lfd, struct sockaddr *addr, socklen_t *len, int flags) {
    ENSURE(accept4);
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    int64_t t0 = cs_now_ns();
    int fd = real_accept4(lfd, addr ? addr : (struct sockaddr *)&ss, addr ? len : &sl, flags);
    return finish_accept(lfd, fd, addr ? addr : (struct sockaddr *)&ss, addr ? len : &sl, t0);
}

#define IO_WRAP(kind, call)                                                                        \
    do {                                                                                           \
        if (!tracking(fd)) return call;                                                            \
        int64_t t0 = cs_now_ns();                                                                  \
        ssize_t rc = call;                                                                         \
        int saved = errno;                                                                         \
        emit_io(kind, fd, rc, saved, cs_now_ns() - t0);                                            \
        errno = saved;                                                                             \
        return rc;                                                                                 \
    } while (0)

ssize_t send(int fd, const void *buf, size_t n, int flags) {
    ENSURE(send);
    IO_WRAP(CS_EV_NET_SEND, real_send(fd, buf, n, flags));
}

ssize_t recv(int fd, void *buf, size_t n, int flags) {
    ENSURE(recv);
    IO_WRAP(CS_EV_NET_RECV, real_recv(fd, buf, n, flags));
}

ssize_t sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *to,
               socklen_t tl) {
    ENSURE(sendto);
    fdinfo *f = fdi(fd);
    if (to && f && f->is_sock && !f->peer[0]) format_addr(to, tl, f->peer, sizeof f->peer);
    IO_WRAP(CS_EV_NET_SEND, real_sendto(fd, buf, n, flags, to, tl));
}

ssize_t recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *from, socklen_t *fl) {
    ENSURE(recvfrom);
    IO_WRAP(CS_EV_NET_RECV, real_recvfrom(fd, buf, n, flags, from, fl));
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    ENSURE(sendmsg);
    IO_WRAP(CS_EV_NET_SEND, real_sendmsg(fd, msg, flags));
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
    ENSURE(recvmsg);
    IO_WRAP(CS_EV_NET_RECV, real_recvmsg(fd, msg, flags));
}

ssize_t read(int fd, void *buf, size_t n) {
    ENSURE(read);
    IO_WRAP(CS_EV_NET_RECV, real_read(fd, buf, n));
}

ssize_t write(int fd, const void *buf, size_t n) {
    ENSURE(write);
    IO_WRAP(CS_EV_NET_SEND, real_write(fd, buf, n));
}

int getsockopt(int fd, int level, int name, void *val, socklen_t *len) {
    ENSURE(getsockopt);
    int rc = real_getsockopt(fd, level, name, val, len);
    int saved = errno;
    if (rc == 0 && level == SOL_SOCKET && name == SO_ERROR && val && tracking(fd)) {
        fdinfo *f = fdi(fd);
        int soerr = *(int *)val;
        if (f->pending && soerr != EINPROGRESS) settle_pending(fd, soerr);
    }
    errno = saved;
    return rc;
}

int close(int fd) {
    ENSURE(close);
    if (tracking(fd)) {
        fdinfo *f = fdi(fd);
        if (f->pending) settle_pending(fd, 0);
        if (f->announced || f->sent || f->recvd) {
            cs_event ev;
            cs_event_init(&ev, CS_EV_NET_CLOSE);
            ev.fd = fd;
            ev.peer = f->peer[0] ? f->peer : NULL;
            ev.proto = f->proto;
            ev.sent = f->sent;
            ev.recvd = f->recvd;
            ev.dur = cs_now_ns() - f->opened; /* lifetime of the socket */
            cs_rt_emit(&ev);
        }
        memset(f, 0, sizeof *f);
    } else if (fdi(fd)) {
        g_fds[fd].is_sock = 0;
    }
    return real_close(fd);
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                struct addrinfo **res) {
    ENSURE(getaddrinfo);
    if (t_inside || !cs_rt_enabled() || !node) return real_getaddrinfo(node, service, hints, res);
    t_inside++; /* hide the resolver's own UDP traffic */
    int64_t t0 = cs_now_ns();
    int rc = real_getaddrinfo(node, service, hints, res);
    int64_t dur = cs_now_ns() - t0;
    t_inside--;

    cs_event ev;
    cs_event_init(&ev, CS_EV_NET_DNS);
    ev.host = node;
    ev.rc = rc;
    ev.dur = dur;
    char first[72] = "";
    if (rc == 0 && res && *res) {
        format_addr((*res)->ai_addr, (*res)->ai_addrlen, first, sizeof first);
        ev.msg = first;
    } else if (rc != 0) {
        ev.err = cs_eai_name(rc);
        ev.msg = gai_strerror(rc);
    }
    cs_rt_emit(&ev);
    return rc;
}
