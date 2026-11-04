/* event.h - the callscope event model.
 *
 * Every trace is a stream of events written as JSON Lines (one object per
 * line). Function-level events come from compiler instrumentation, network-
 * level events from the LD_PRELOAD shim or an strace import, and application
 * events from explicit cs_error()/cs_log() calls. See docs/log-format.md. */
#ifndef CALLSCOPE_EVENT_H
#define CALLSCOPE_EVENT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cs_event_kind {
    CS_EV_UNKNOWN = 0,
    CS_EV_PROC_START, /* process began tracing; msg = command line */
    CS_EV_PROC_EXIT,  /* normal exit; rc = exit status */
    CS_EV_SIGNAL,     /* fatal signal caught; sig = signal number */
    CS_EV_FN_ENTER,   /* function entered; fn, addr, depth */
    CS_EV_FN_EXIT,    /* function returned; fn, dur */
    CS_EV_NET_CONNECT, /* connect(); fd, peer, rc, err, dur */
    CS_EV_NET_ACCEPT,  /* accept(); fd (new socket), peer */
    CS_EV_NET_SEND,    /* send/write on a socket; fd, bytes, dur */
    CS_EV_NET_RECV,    /* recv/read on a socket; fd, bytes (0 = peer closed), dur */
    CS_EV_NET_CLOSE,   /* close() of a socket; fd, sent, recvd totals */
    CS_EV_NET_DNS,     /* getaddrinfo(); host, rc, err, dur */
    CS_EV_APP_ERROR,   /* application reported error; code, msg */
    CS_EV_APP_LOG,     /* application log line; msg (level in code) */
    CS_EV__COUNT
} cs_event_kind;

typedef struct cs_event {
    int64_t ts; /* ns since epoch (CLOCK_REALTIME) */
    int32_t pid;
    int32_t tid;
    cs_event_kind kind;

    int64_t dur;    /* duration in ns, -1 when unknown */
    int32_t depth;  /* call depth for fn events, -1 when unknown */
    uint64_t addr;  /* function address */
    int32_t fd;     /* socket fd, -1 when not applicable */
    int64_t rc;     /* return value / exit status */
    int32_t err_no; /* errno value (0 = success) */
    int32_t sig;    /* signal number for CS_EV_SIGNAL */
    int64_t bytes;  /* bytes moved by one send/recv */
    int64_t sent;   /* totals reported at close */
    int64_t recvd;

    const char *fn;    /* function name */
    const char *peer;  /* "ip:port" or unix path */
    const char *proto; /* "tcp", "udp", "unix" */
    const char *host;  /* DNS name looked up */
    const char *err;   /* symbolic errno, e.g. "ECONNREFUSED" */
    const char *code;  /* app error code / log level */
    const char *msg;   /* free text */

    size_t line; /* 1-based line in the source log (analysis side only) */
} cs_event;

/* Reset an event to "no data" defaults (-1 for dur/depth/fd). */
void cs_event_init(cs_event *ev, cs_event_kind kind);

const char *cs_event_kind_name(cs_event_kind k);
cs_event_kind cs_event_kind_parse(const char *name);
int cs_event_is_net(cs_event_kind k);
int cs_event_is_fn(cs_event_kind k);

/* Symbolic name for an errno value ("ECONNREFUSED"), or NULL if unknown. */
const char *cs_errno_name(int err);
/* Reverse lookup, 0 if unknown. */
int cs_errno_from_name(const char *name);
/* Symbolic name for a getaddrinfo() error code ("EAI_NONAME"), or NULL. */
const char *cs_eai_name(int code);
/* Short signal name ("SIGSEGV") or NULL. */
const char *cs_signal_name(int sig);

/* Serialise one event as a single JSON line (with trailing '\n') into buf.
 * Never allocates, so it is safe to use from the runtime hooks.
 * Returns the number of bytes written (always < n), truncating long strings. */
size_t cs_event_to_jsonl(const cs_event *ev, char *buf, size_t n);

#ifdef __cplusplus
}
#endif
#endif
