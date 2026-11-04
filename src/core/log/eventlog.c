#include "callscope/eventlog.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "callscope/json.h"

void cs_eventlog_init(cs_eventlog *log) {
    memset(log, 0, sizeof(*log));
    cs_vec_init(&log->events, sizeof(cs_event));
    cs_hm_init(&log->strings);
}

void cs_eventlog_free(cs_eventlog *log) {
    cs_vec_free(&log->events);
    cs_hm_free(&log->strings, NULL);
}

const char *cs_eventlog_intern(cs_eventlog *log, const char *s) {
    if (!s) return NULL;
    const char *k = cs_hm_key(&log->strings, s);
    if (k) return k;
    if (!cs_hm_slot(&log->strings, s)) return NULL;
    return cs_hm_key(&log->strings, s);
}

int cs_eventlog_add(cs_eventlog *log, const cs_event *ev) {
    cs_event *dst = cs_vec_push_slot(&log->events);
    if (!dst) return -1;
    *dst = *ev;
    dst->fn = cs_eventlog_intern(log, ev->fn);
    dst->peer = cs_eventlog_intern(log, ev->peer);
    dst->proto = cs_eventlog_intern(log, ev->proto);
    dst->host = cs_eventlog_intern(log, ev->host);
    dst->err = cs_eventlog_intern(log, ev->err);
    dst->code = cs_eventlog_intern(log, ev->code);
    dst->msg = cs_eventlog_intern(log, ev->msg);
    return 0;
}

static int64_t get_i64(const cs_json *o, const char *k, int64_t dflt) {
    return cs_json_as_i64(cs_json_get(o, k), dflt);
}

static const char *get_str(const cs_json *o, const char *k) {
    return cs_json_as_str(cs_json_get(o, k), NULL);
}

int cs_eventlog_add_line(cs_eventlog *log, const char *line, size_t len, size_t lineno) {
    while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) len--;
    size_t i = 0;
    while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
    if (i == len) return 0; /* blank */
    if (line[i] == '#') return 0; /* comment */

    cs_json *o = cs_json_parse(line, len, NULL, 0);
    if (!o || o->type != CS_JSON_OBJ) {
        cs_json_free(o);
        return -1;
    }
    cs_event ev;
    cs_event_init(&ev, cs_event_kind_parse(get_str(o, "k")));
    if (ev.kind == CS_EV_UNKNOWN) ev.kind = cs_event_kind_parse(get_str(o, "kind"));
    ev.ts = get_i64(o, "ts", 0);
    ev.pid = (int32_t)get_i64(o, "pid", 0);
    ev.tid = (int32_t)get_i64(o, "tid", ev.pid);
    ev.dur = get_i64(o, "dur", -1);
    ev.depth = (int32_t)get_i64(o, "depth", -1);
    ev.fd = (int32_t)get_i64(o, "fd", -1);
    ev.rc = get_i64(o, "rc", 0);
    ev.err_no = (int32_t)get_i64(o, "errno", 0);
    ev.sig = (int32_t)get_i64(o, "sig", 0);
    ev.bytes = get_i64(o, "bytes", 0);
    ev.sent = get_i64(o, "sent", 0);
    ev.recvd = get_i64(o, "recvd", 0);
    const char *addr = get_str(o, "addr");
    if (addr) ev.addr = strtoull(addr, NULL, 0);
    ev.fn = get_str(o, "fn");
    ev.peer = get_str(o, "peer");
    ev.proto = get_str(o, "proto");
    ev.host = get_str(o, "host");
    ev.err = get_str(o, "err");
    ev.code = get_str(o, "code");
    ev.msg = get_str(o, "msg");
    if (ev.err && !ev.err_no) ev.err_no = cs_errno_from_name(ev.err);
    ev.line = lineno;
    int rc = cs_eventlog_add(log, &ev);
    cs_json_free(o);
    return rc;
}

int cs_eventlog_load_stream(cs_eventlog *log, FILE *fp) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    size_t lineno = 0;
    while ((n = getline(&line, &cap, fp)) >= 0) {
        lineno++;
        if (cs_eventlog_add_line(log, line, (size_t)n, lineno) != 0) {
            if (!log->malformed) log->first_bad_line = lineno;
            log->malformed++;
        }
    }
    free(line);
    return 0;
}

int cs_eventlog_load_file(cs_eventlog *log, const char *path, char *err, size_t errlen) {
    FILE *fp = strcmp(path, "-") == 0 ? stdin : fopen(path, "r");
    if (!fp) {
        if (err) snprintf(err, errlen, "cannot open %s: %s", path, strerror(errno));
        return -1;
    }
    snprintf(log->source, sizeof log->source, "%s", path);
    cs_eventlog_load_stream(log, fp);
    if (fp != stdin) fclose(fp);
    cs_eventlog_finish(log);
    return 0;
}

static int cmp_event(const void *a, const void *b) {
    const cs_event *x = a, *y = b;
    if (x->ts != y->ts) return x->ts < y->ts ? -1 : 1;
    return (x->line > y->line) - (x->line < y->line);
}

static int cmp_i32(const void *a, const void *b) {
    int32_t x = *(const int32_t *)a, y = *(const int32_t *)b;
    return (x > y) - (x < y);
}

static size_t count_unique(int32_t *vals, size_t n) {
    if (!n) return 0;
    qsort(vals, n, sizeof(*vals), cmp_i32);
    size_t u = 1;
    for (size_t i = 1; i < n; i++)
        if (vals[i] != vals[i - 1]) u++;
    return u;
}

void cs_eventlog_finish(cs_eventlog *log) {
    size_t n = log->events.len;
    /* keep insertion order as a tiebreaker for events without a source line */
    for (size_t i = 0; i < n; i++) {
        cs_event *ev = cs_vec_at(&log->events, i);
        if (!ev->line) ev->line = i + 1;
    }
    cs_vec_sort(&log->events, cmp_event);
    log->t_min = log->t_max = 0;
    if (!n) return;
    log->t_min = ((cs_event *)cs_vec_at(&log->events, 0))->ts;
    log->t_max = ((cs_event *)cs_vec_at(&log->events, n - 1))->ts;

    int32_t *pids = malloc(n * sizeof(int32_t));
    int32_t *tids = malloc(n * sizeof(int32_t));
    if (pids && tids) {
        for (size_t i = 0; i < n; i++) {
            const cs_event *ev = cs_vec_at(&log->events, i);
            pids[i] = ev->pid;
            tids[i] = ev->tid;
        }
        log->n_pids = count_unique(pids, n);
        log->n_tids = count_unique(tids, n);
    }
    free(pids);
    free(tids);
}

int cs_eventlog_write(const cs_eventlog *log, FILE *fp) {
    char buf[8192];
    for (size_t i = 0; i < log->events.len; i++) {
        size_t m = cs_event_to_jsonl(cs_vec_at(&log->events, i), buf, sizeof buf);
        if (fwrite(buf, 1, m, fp) != m) return -1;
    }
    return 0;
}
