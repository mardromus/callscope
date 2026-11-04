/* callscope command line entry point. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "callscope/http.h"
#include "cli.h"

static void usage(FILE *fp) {
    fprintf(fp,
            "callscope %s - function-level and network-level call analysis with root cause "
            "detection\n\n"
            "usage: callscope <command> [options]\n\n"
            "capture\n"
            "  record [-o trace.jsonl] [--no-io] [--report out.html] -- <program> [args...]\n"
            "                       run any program with the network tracer preloaded\n"
            "                       (programs built with -finstrument-functions + "
            "libcallscope_trace\n"
            "                       add function-level events to the same trace)\n"
            "  import strace <file> [-o out.jsonl] [--date YYYY-MM-DD] [--pid N]\n"
            "                       convert `strace -f -tt -T` output into a callscope trace\n"
            "  gen <scenario> [-o out.jsonl] [--requests N] [--seed N] [--threads N]\n"
            "  gen --list           synthetic traces with a known fault, for demos and tests\n\n"
            "analyse\n"
            "  analyze <trace>      findings, top functions and peers (terminal)\n"
            "  rca <trace>          root cause, causal chain, fixes\n"
            "  report <trace> [-o report.html] [--md report.md] [--json-out report.json]\n\n"
            "options for analyze / rca / report\n"
            "  --ai                 investigate with the LLM agent (falls back to rules)\n"
            "  --json               machine readable output\n"
            "  --no-color           plain output\n"
            "  --slow-ms N          minimum duration of a slow call (default 50)\n"
            "  --net-slow-ms N      slow connect / network I/O threshold (default 300)\n"
            "  -v, --verbose        show the agent's tool calls\n\n"
            "AI configuration (any OpenAI-compatible API)\n"
            "  CALLSCOPE_LLM_API_KEY / GROQ_API_KEY / OPENAI_API_KEY\n"
            "  CALLSCOPE_LLM_BASE_URL   default https://api.groq.com/openai/v1\n"
            "  CALLSCOPE_LLM_MODEL      default llama-3.3-70b-versatile\n"
            "  (Ollama: CALLSCOPE_LLM_BASE_URL=http://localhost:11434/v1 "
            "CALLSCOPE_LLM_MODEL=llama3.1)\n\n"
            "Use \"-\" as <trace> to read from stdin.\n",
            CALLSCOPE_VERSION);
}

void cli_die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "callscope: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(2);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    const char *cmd = argv[1];
    if (!strcmp(cmd, "analyze") || !strcmp(cmd, "analyse")) return cmd_analyze(argc, argv);
    if (!strcmp(cmd, "rca")) return cmd_rca(argc, argv);
    if (!strcmp(cmd, "report")) return cmd_report(argc, argv);
    if (!strcmp(cmd, "record")) return cmd_record(argc, argv);
    if (!strcmp(cmd, "gen")) return cmd_gen(argc, argv);
    if (!strcmp(cmd, "import")) return cmd_import(argc, argv);
    if (!strcmp(cmd, "version") || !strcmp(cmd, "--version")) {
        printf("callscope %s (ai transport: %s)\n", CALLSCOPE_VERSION, cs_http_backend());
        return 0;
    }
    if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
        usage(stdout);
        return 0;
    }
    fprintf(stderr, "callscope: unknown command '%s'\n\n", cmd);
    usage(stderr);
    return 2;
}
