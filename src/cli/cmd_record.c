/* `callscope record -- program args...`
 *
 * Runs any dynamically linked program with libcallscope_net.so preloaded so
 * its network calls are traced, collects function events too when the program
 * links libcallscope_trace, and appends the real exit status at the end. */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "callscope/event.h"
#include "callscope/report.h"
#include "callscope/timeutil.h"
#include "cli.h"

static int exists(const char *p) {
    struct stat st;
    return stat(p, &st) == 0;
}

/* Locate libcallscope_net.so: $CALLSCOPE_NET_LIB, next to the binary, ../lib, build dir. */
static int find_net_lib(char *out, size_t n) {
    const char *env = getenv("CALLSCOPE_NET_LIB");
    if (env && exists(env)) {
        snprintf(out, n, "%s", env);
        return 0;
    }
    char self[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self, sizeof self - 1);
    if (len > 0) {
        self[len] = '\0';
        char *slash = strrchr(self, '/');
        if (slash) {
            *slash = '\0';
            const char *cands[] = {"/libcallscope_net.so", "/../lib/libcallscope_net.so",
                                   "/../lib64/libcallscope_net.so"};
            for (size_t i = 0; i < sizeof cands / sizeof cands[0]; i++) {
                char p[PATH_MAX + 64];
                snprintf(p, sizeof p, "%s%s", self, cands[i]);
                if (exists(p)) {
                    char resolved[PATH_MAX];
                    const char *use = realpath(p, resolved) ? resolved : p;
                    if (strlen(use) >= n) return -1;
                    memcpy(out, use, strlen(use) + 1);
                    return 0;
                }
            }
        }
    }
#ifdef CALLSCOPE_NET_LIB_BUILD
    if (exists(CALLSCOPE_NET_LIB_BUILD)) {
        // cppcheck-suppress invalidPrintfArgType_s
        snprintf(out, n, "%s", CALLSCOPE_NET_LIB_BUILD);
        return 0;
    }
#endif
    return -1;
}

static void append_exit(const char *path, pid_t pid, int status) {
    cs_event ev;
    cs_event_init(&ev, CS_EV_PROC_EXIT);
    ev.ts = cs_now_ns();
    ev.pid = ev.tid = (int32_t)pid;
    if (WIFEXITED(status)) {
        ev.rc = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        ev.sig = WTERMSIG(status);
        ev.rc = 128 + ev.sig;
        ev.msg = "killed by signal";
    }
    char line[1024];
    size_t n = cs_event_to_jsonl(&ev, line, sizeof line);
    FILE *fp = fopen(path, "a");
    if (fp) {
        fwrite(line, 1, n, fp);
        fclose(fp);
    }
}

int cmd_record(int argc, char **argv) {
    const char *out = "callscope.jsonl", *report = NULL;
    int io = 1, append = 0, i = 2;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--")) {
            i++;
            break;
        }
        if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[++i];
        else if (!strcmp(argv[i], "--report") && i + 1 < argc) report = argv[++i];
        else if (!strcmp(argv[i], "--no-io")) io = 0;
        else if (!strcmp(argv[i], "--append")) append = 1;
        else if (argv[i][0] != '-') break;
        else cli_die("record: unknown option %s", argv[i]);
    }
    if (i >= argc) cli_die("record: missing program (usage: callscope record [-o file] -- prog args)");

    char lib[PATH_MAX];
    if (find_net_lib(lib, sizeof lib) != 0)
        cli_die("record: cannot find libcallscope_net.so (set CALLSCOPE_NET_LIB)");
    if (!append) unlink(out);

    char abs_out[PATH_MAX * 2];
    if (out[0] != '/') {
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof cwd)) cli_die("record: getcwd failed");
        snprintf(abs_out, sizeof abs_out, "%s/%s", cwd, out);
    } else {
        snprintf(abs_out, sizeof abs_out, "%s", out);
    }

    char preload[PATH_MAX * 2];
    const char *prev = getenv("LD_PRELOAD");
    snprintf(preload, sizeof preload, "%s%s%s", lib, prev && *prev ? ":" : "", prev ? prev : "");

    fprintf(stderr, "callscope: recording %s -> %s\n", argv[i], out);
    pid_t pid = fork();
    if (pid < 0) cli_die("record: fork failed: %s", strerror(errno));
    if (pid == 0) {
        setenv("LD_PRELOAD", preload, 1);
        setenv("CALLSCOPE_LOG", abs_out, 1);
        if (!io) setenv("CALLSCOPE_NET_IO", "0", 1);
        unsetenv("CALLSCOPE_STARTED");
        execvp(argv[i], &argv[i]);
        fprintf(stderr, "callscope: cannot run %s: %s\n", argv[i], strerror(errno));
        _exit(127);
    }
    signal(SIGINT, SIG_IGN); /* let Ctrl-C reach the child, then summarise */
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    signal(SIGINT, SIG_DFL);
    append_exit(abs_out, pid, status);

    cs_eventlog log;
    if (cli_load(abs_out, &log) != 0) return 2;
    cs_analysis a;
    cs_analyze(&a, &log, NULL);
    cs_rca_result r;
    cs_rca_rules(&a, &r);
    fprintf(stderr, "callscope: %zu events, %zu findings. Root cause: %s\n",
            cs_eventlog_count(&log), a.findings.len, r.summary);
    if (report) {
        cs_strbuf sb;
        cs_sb_init(&sb);
        cs_report_html(&sb, &a, &r);
        if (cli_write_file(report, sb.data, sb.len) == 0)
            fprintf(stderr, "callscope: wrote %s\n", report);
        cs_sb_free(&sb);
    } else {
        fprintf(stderr, "callscope: next: callscope analyze %s   |   callscope report %s\n", out, out);
    }
    cs_analysis_free(&a);
    cs_eventlog_free(&log);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
