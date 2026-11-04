/* Trace writer used by every runtime component.
 *
 * Lines are written with a single write(2) on an O_APPEND descriptor, so the
 * tracer and the network shim (and forked children) can share one file
 * without interleaving partial lines. */
#define _GNU_SOURCE
#include "rt.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "callscope/timeutil.h"

static int g_fd = -1;
static int g_enabled = -1;
static int g_pid;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static __thread int t_tid;

static void CS_NOINSTR after_fork_child(void) {
    g_pid = (int)getpid();
    t_tid = 0;
}

static void CS_NOINSTR open_log(void) {
    const char *dis = getenv("CALLSCOPE_DISABLE");
    g_enabled = !(dis && *dis && strcmp(dis, "0") != 0);
    g_pid = (int)getpid();
    pthread_atfork(NULL, NULL, after_fork_child);
    if (!g_enabled) return;
    const char *path = getenv("CALLSCOPE_LOG");
    if (!path || !*path) path = "callscope.jsonl";
    g_fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                        0644);
    if (g_fd < 0) g_enabled = 0;
}

int cs_rt_enabled(void) {
    pthread_once(&g_once, open_log);
    return g_enabled;
}

int cs_trace_enabled(void) { return cs_rt_enabled(); }

int cs_rt_pid(void) {
    pthread_once(&g_once, open_log);
    return g_pid;
}

int cs_rt_tid(void) {
    if (!t_tid) t_tid = (int)syscall(SYS_gettid);
    return t_tid;
}

void cs_rt_emit(cs_event *ev) {
    if (!cs_rt_enabled()) return;
    if (!ev->ts) ev->ts = cs_now_ns();
    if (!ev->pid) ev->pid = cs_rt_pid();
    if (!ev->tid) ev->tid = cs_rt_tid();
    char line[CS_RT_LINE_MAX];
    size_t n = cs_event_to_jsonl(ev, line, sizeof line);
    /* raw syscall: never re-enter the network shim's write() wrapper */
    ssize_t w = syscall(SYS_write, g_fd, line, n);
    (void)w;
}

void cs_rt_proc_start(const char *component) {
    if (!cs_rt_enabled()) return;
    /* CALLSCOPE_STARTED=<pid> marks that this process already announced itself */
    char mark[32];
    snprintf(mark, sizeof mark, "%d", cs_rt_pid());
    const char *prev = getenv("CALLSCOPE_STARTED");
    if (prev && strcmp(prev, mark) == 0) return;
    setenv("CALLSCOPE_STARTED", mark, 1);

    char cmd[1024] = "";
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = syscall(SYS_read, fd, cmd, sizeof cmd - 1);
        syscall(SYS_close, fd);
        if (n > 0) {
            for (ssize_t i = 0; i < n - 1; i++)
                if (cmd[i] == '\0') cmd[i] = ' ';
            cmd[n] = '\0';
        }
    }
    cs_event ev;
    cs_event_init(&ev, CS_EV_PROC_START);
    ev.msg = cmd;
    ev.code = component;
    cs_rt_emit(&ev);
}

static void CS_NOINSTR emit_app(cs_event_kind kind, const char *code, const char *fmt,
                                va_list ap) {
    char msg[1024];
    vsnprintf(msg, sizeof msg, fmt, ap);
    cs_event ev;
    cs_event_init(&ev, kind);
    ev.code = code;
    ev.msg = msg;
    cs_rt_emit(&ev);
}

void cs_error(const char *code, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    emit_app(CS_EV_APP_ERROR, code, fmt, ap);
    va_end(ap);
}

void cs_log(const char *level, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    emit_app(CS_EV_APP_LOG, level, fmt, ap);
    va_end(ap);
}
