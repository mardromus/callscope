/* analyze.h - turning raw events into call trees, statistics and findings.
 *
 *   cs_analysis a;
 *   cs_analyze(&a, &log, NULL);        // NULL = default thresholds
 *   for (size_t i = 0; i < a.findings.len; i++) ... CS_VEC_AT(&a.findings, cs_finding, i)
 *   cs_analysis_free(&a);
 *
 * Three layers are built, each usable on its own:
 *   1. cs_calltree  - per-thread call stacks rebuilt from fn_enter/fn_exit
 *   2. cs_fnstats   - per-function counts, inclusive/exclusive time, percentiles
 *   3. cs_netstats  - per-connection sessions, per-peer and per-DNS-name stats
 * Detectors then look across all three (see docs/detectors.md). */
#ifndef CALLSCOPE_ANALYZE_H
#define CALLSCOPE_ANALYZE_H

#include <stddef.h>
#include <stdint.h>

#include "callscope/eventlog.h"
#include "callscope/vec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CS_NONE ((size_t)-1)

/* ---- call tree ------------------------------------------------------------ */

typedef struct cs_frame {
    const char *fn;
    int32_t pid, tid, depth;
    int64_t start, end;
    int64_t incl;     /* inclusive time (ns) */
    int64_t excl;     /* exclusive time: incl minus direct children */
    int64_t net_wait; /* time spent inside network calls under this frame */
    size_t parent;    /* CS_NONE for a root frame */
    size_t enter_ev, exit_ev;
    int open;         /* never returned: crash site or still running at end of trace */
    int unwound;      /* skipped by a non-local exit (longjmp/exception) */
    int n_children;
} cs_frame;

typedef struct cs_calltree {
    cs_vec frames;    /* cs_frame */
    size_t *ev_frame; /* per event index: innermost open frame on that thread, or CS_NONE */
    size_t n_events;
    int32_t max_depth;
    size_t n_open;
    size_t n_threads;
} cs_calltree;

int cs_calltree_build(cs_calltree *t, const cs_eventlog *log);
void cs_calltree_free(cs_calltree *t);
const cs_frame *cs_calltree_frame(const cs_calltree *t, size_t idx);
/* Write "main > handle_request > charge_payment" for frame idx. */
size_t cs_calltree_stack_str(const cs_calltree *t, size_t idx, char *buf, size_t n);

/* ---- function statistics -------------------------------------------------- */

typedef struct cs_fnstat {
    const char *fn;
    int64_t calls;
    int64_t incl_total, excl_total, net_wait_total;
    int64_t min, max, p50, p95, p99; /* of inclusive time per call */
    int64_t open_frames;
    int32_t max_depth;
    size_t slowest_frame;
} cs_fnstat;

typedef struct cs_fnstats {
    cs_vec stats;       /* cs_fnstat, sorted by excl_total descending */
    int64_t total_excl; /* sum of exclusive time of all frames */
} cs_fnstats;

int cs_fnstats_build(cs_fnstats *s, const cs_calltree *t);
void cs_fnstats_free(cs_fnstats *s);
const cs_fnstat *cs_fnstats_find(const cs_fnstats *s, const char *fn);

/* ---- network statistics --------------------------------------------------- */

#define CS_PEER_ERRS 6

typedef struct cs_netconn {
    int32_t pid, tid, fd;
    const char *peer, *proto;
    int64_t t_open, t_close;
    int64_t connect_dur;
    int64_t connect_rc;
    int32_t connect_err;
    int64_t sent, recvd, n_send, n_recv;
    int64_t io_time, max_io, io_errors;
    int eof, reset, closed, accepted, connected;
    size_t first_ev, last_ev;
} cs_netconn;

typedef struct cs_peerstat {
    const char *peer;
    int64_t attempts, failures, accepts;
    int64_t sent, recvd;
    int64_t connect_total, connect_max, connect_n;
    int64_t io_time, io_max, resets, eofs, io_errors;
    int64_t first_ts, last_ts;
    const char *err_name[CS_PEER_ERRS];
    int64_t err_count[CS_PEER_ERRS];
} cs_peerstat;

typedef struct cs_dnsstat {
    const char *host;
    int64_t lookups, failures, total_dur, max_dur;
    const char *last_err;
    size_t last_ev;
} cs_dnsstat;

typedef struct cs_netstats {
    cs_vec conns; /* cs_netconn in open order */
    cs_vec peers; /* cs_peerstat sorted by attempts desc */
    cs_vec dns;   /* cs_dnsstat */
    int64_t total_io_time;
    int64_t total_sent, total_recvd;
} cs_netstats;

int cs_netstats_build(cs_netstats *s, const cs_eventlog *log);
void cs_netstats_free(cs_netstats *s);
const cs_peerstat *cs_netstats_peer(const cs_netstats *s, const char *peer);
/* Most frequent error name for a peer, or NULL. */
const char *cs_peerstat_top_err(const cs_peerstat *p, int64_t *count);

/* ---- findings --------------------------------------------------------------- */

typedef enum { CS_SEV_INFO, CS_SEV_LOW, CS_SEV_MEDIUM, CS_SEV_HIGH, CS_SEV_CRITICAL } cs_severity;
typedef enum { CS_LEVEL_FUNCTION, CS_LEVEL_NETWORK, CS_LEVEL_APP, CS_LEVEL_CROSS } cs_level;

#define CS_MAX_EVIDENCE 8

typedef struct cs_finding {
    char id[8];           /* "F01" */
    const char *detector; /* "net.connect_failure" */
    cs_level level;
    cs_severity sev;
    char title[192];
    char detail[640];
    char stack[512];      /* call path where it happened, if known */
    const char *fn;
    const char *peer;
    const char *err;
    int32_t pid, tid;
    int64_t first_ts, last_ts;
    int64_t count;
    double value;         /* main metric (ns, ratio, count) */
    double threshold;
    double score;         /* ranking weight, higher = more important */
    size_t evidence[CS_MAX_EVIDENCE]; /* event indices */
    size_t n_evidence;
} cs_finding;

const char *cs_severity_name(cs_severity s);
const char *cs_level_name(cs_level l);

/* ---- analysis --------------------------------------------------------------- */

typedef struct cs_analyze_opts {
    int64_t slow_min_ns;    /* a call must take at least this long to be "slow" (50 ms) */
    double slow_factor;     /* ...and this many times its function's median (5x) */
    int recursion_limit;    /* same function this many times on one stack (128) */
    int64_t net_slow_ns;    /* connect or single I/O slower than this (300 ms) */
    int retry_count;        /* failed connects to one peer inside the window (4) */
    int64_t retry_window_ns;/* (10 s) */
    double hotspot_share;   /* function owning this share of exclusive time (0.35) */
    double net_wait_share;  /* slow call whose time is mostly network wait (0.6) */
    int64_t error_link_ns;  /* max gap for "network failure caused app error" (2 s) */
    int max_per_detector;   /* (6) */
} cs_analyze_opts;

typedef struct cs_analysis {
    const cs_eventlog *log;
    cs_analyze_opts opts;
    cs_calltree tree;
    cs_fnstats fns;
    cs_netstats net;
    cs_vec findings; /* cs_finding sorted by score descending */
    int64_t span_ns;
    size_t n_fn_events, n_net_events, n_app_errors, n_app_logs, n_signals;
    int crashed, has_exit;
    int64_t exit_code;
} cs_analysis;

void cs_analyze_opts_default(cs_analyze_opts *o);
int cs_analyze(cs_analysis *a, const cs_eventlog *log, const cs_analyze_opts *opts);
void cs_analysis_free(cs_analysis *a);

/* Used by detectors: append a finding pre-filled with defaults. */
cs_finding *cs_analysis_add_finding(cs_analysis *a, const char *detector, cs_level level,
                                    cs_severity sev);
void cs_finding_add_evidence(cs_finding *f, size_t ev_index);
const cs_finding *cs_analysis_finding(const cs_analysis *a, const char *id);

#ifdef __cplusplus
}
#endif
#endif
