/* Function-call tracer built on GCC/Clang -finstrument-functions.
 *
 * The compiler inserts calls to __cyg_profile_func_enter/exit around every
 * function of an instrumented program. We keep a per-thread stack of entry
 * timestamps so each exit event carries the call's duration, and install
 * crash handlers (on an alternate stack, so stack overflows are caught too)
 * that record the fatal signal before the process dies. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../common/rt.h"
#include "callscope/timeutil.h"
#include "symbols.h"

#define CS_STACK_MAX 4096

static __thread int64_t t_start[CS_STACK_MAX];
static __thread int t_depth;
static __thread int t_busy; /* re-entrancy guard */
static int g_max_depth = CS_STACK_MAX;
static int g_ready;

void __cyg_profile_func_enter(void *fn, void *caller) CS_NOINSTR;
void __cyg_profile_func_exit(void *fn, void *caller) CS_NOINSTR;

static const int crash_signals[] = {SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL};
static char g_altstack[64 * 1024];

static void CS_NOINSTR on_crash(int sig, siginfo_t *si, void *uctx) {
    (void)uctx;
    cs_event ev;
    cs_event_init(&ev, CS_EV_SIGNAL);
    ev.sig = sig;
    ev.depth = t_depth;
    if (si) ev.addr = (uint64_t)(uintptr_t)si->si_addr;
    ev.msg = "fatal signal; open frames at this point are the crash site";
    cs_rt_emit(&ev);
    /* SA_RESETHAND restored the default action; re-raise to die normally */
    raise(sig);
}

static void CS_NOINSTR install_crash_handlers(void) {
    stack_t ss;
    memset(&ss, 0, sizeof ss);
    ss.ss_sp = g_altstack;
    ss.ss_size = sizeof g_altstack;
    sigaltstack(&ss, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_crash;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    for (size_t i = 0; i < sizeof crash_signals / sizeof crash_signals[0]; i++)
        sigaction(crash_signals[i], &sa, NULL);
}

__attribute__((constructor)) static void CS_NOINSTR tracer_init(void) {
    if (!cs_rt_enabled()) return;
    const char *md = getenv("CALLSCOPE_MAX_DEPTH");
    if (md && *md) {
        int v = atoi(md);
        if (v > 0 && v <= CS_STACK_MAX) g_max_depth = v;
    }
    install_crash_handlers();
    cs_rt_proc_start("trace");
    g_ready = 1;
}

void __cyg_profile_func_enter(void *fn, void *caller) {
    (void)caller;
    if (!g_ready || t_busy) return;
    t_busy = 1;
    int d = t_depth++;
    if (d < g_max_depth) {
        int64_t now = cs_now_ns();
        t_start[d] = now;
        cs_event ev;
        cs_event_init(&ev, CS_EV_FN_ENTER);
        ev.ts = now;
        ev.fn = cs_sym_name(fn);
        ev.addr = (uint64_t)(uintptr_t)fn;
        ev.depth = d;
        cs_rt_emit(&ev);
    }
    t_busy = 0;
}

void __cyg_profile_func_exit(void *fn, void *caller) {
    (void)caller;
    if (!g_ready || t_busy || t_depth <= 0) return;
    t_busy = 1;
    int d = --t_depth;
    if (d < g_max_depth) {
        int64_t now = cs_now_ns();
        cs_event ev;
        cs_event_init(&ev, CS_EV_FN_EXIT);
        ev.ts = now;
        ev.fn = cs_sym_name(fn);
        ev.depth = d;
        ev.dur = now - t_start[d];
        cs_rt_emit(&ev);
    }
    t_busy = 0;
}
