/* Knowledge base of failure modes: what a finding usually means, how to fix
 * it and what to check next. Entries with a specific `err` win over generic
 * ones for the same detector. */
#include <stdio.h>
#include <string.h>

#include "callscope/rca.h"

static const cs_kb_entry KB[] = {
    {"net.connect_failure", "ECONNREFUSED", "dependency-unavailable",
     "The service at {peer} was not accepting connections (ECONNREFUSED): it was down, "
     "restarting, or listening on a different port. Every request that needed it from {fn} "
     "failed.",
     {"Restore the service at {peer} (check its process / container status and logs).",
      "Verify the host and port configured for this dependency match where it listens.",
      "Add a circuit breaker so callers fail fast instead of retrying a dead dependency.",
      "Return a clear degraded response instead of an error when this dependency is down."},
     {"Is anything listening on {peer}? (ss -ltnp / netstat on that host)",
      "Did a deploy or restart of the dependency happen at the time of the first failure?",
      "Do other clients of {peer} see the same errors?"}},
    {"net.connect_failure", "ETIMEDOUT", "network-path",
     "Connections to {peer} timed out (ETIMEDOUT): packets are dropped by a firewall / security "
     "group, the host is unreachable, or it is too overloaded to complete handshakes.",
     {"Check firewall / security-group rules between this host and {peer}.",
      "Check routing and whether {peer} is up (ping, traceroute, tcpdump for SYNs).",
      "Lower the connect timeout so callers fail fast, and add retries with backoff."},
     {"Do SYN packets leave this host and reach {peer}?",
      "Is {peer} CPU or accept-queue saturated?", NULL}},
    {"net.connect_failure", "EMFILE", "resource-exhaustion",
     "The process ran out of file descriptors (EMFILE), so new connections could not even be "
     "created. This is almost always a socket / file leak.",
     {"Find the code path that opens sockets without closing them (see the leak finding).",
      "Use RAII-style helpers or a single cleanup label so every error path closes the fd.",
      "Raise ulimit -n only as a stop-gap, not as the fix."},
     {"ls /proc/<pid>/fd | wc -l over time: does it only grow?", NULL, NULL}},
    {"net.connect_failure", NULL, "dependency-unavailable",
     "Connections from {fn} to {peer} failed ({err}), so the dependency could not be used.",
     {"Check the health of {peer} and the network path to it.",
      "Add timeouts, retries with backoff and a circuit breaker around this call."},
     {"When did the first failure happen and what changed then?", NULL, NULL}},
    {"net.dns_failure", "EAI_NONAME", "configuration",
     "The hostname {peer} does not resolve (EAI_NONAME). The configured name is wrong or its "
     "DNS record / hosts entry is missing, so the dependency can never be reached.",
     {"Fix the hostname in the service configuration (look for a typo or a stale name).",
      "Create or restore the DNS record for {peer}.",
      "Validate dependency hostnames at startup and refuse to start with an unresolvable one."},
     {"dig / nslookup {peer} from the same host and network namespace.",
      "Did a config change or DNS migration happen recently?", NULL}},
    {"net.dns_failure", NULL, "network-path",
     "DNS resolution of {peer} failed ({err}): the resolver is unreachable or erroring.",
     {"Check /etc/resolv.conf and connectivity to the DNS servers.",
      "Use a local caching resolver to ride out short outages."},
     {"Does resolution of other names work from this host?", NULL, NULL}},
    {"net.slow_io", NULL, "dependency-slow",
     "{peer} was slow to answer: individual responses took up to {value_dur}, so {fn} spent "
     "almost all of its time blocked waiting. The application code is not the bottleneck; the "
     "dependency is.",
     {"Investigate {peer}'s own latency (its database, CPU, locks, downstream calls).",
      "Set a client-side timeout well below the caller's SLA and handle it.",
      "Cache responses or make the call asynchronous if the result is not needed inline.",
      "Add a latency SLO / alert on this dependency."},
     {"Is {peer} slow for all clients or only this one?",
      "Did request size or traffic to {peer} change?",
      "What does {peer}'s own tracing show for the same time window?"}},
    {"net.slow_connect", NULL, "network-path",
     "TCP handshakes with {peer} were slow (up to {value_dur}): packet loss, a saturated accept "
     "queue, or a distant host.",
     {"Reuse connections (keep-alive / pooling) so the handshake is paid once.",
      "Check {peer}'s listen backlog and SYN drops; check packet loss on the path."},
     {"netstat -s | grep -i listen on {peer}: are SYNs being dropped?", NULL, NULL}},
    {"net.dns_slow", NULL, "network-path",
     "Resolving {peer} was slow (up to {value_dur}) and sits on the critical path.",
     {"Cache DNS results or run a local caching resolver.",
      "Resolve once at startup for static dependencies."},
     {NULL, NULL, NULL}},
    {"net.reset", NULL, "dependency-unstable",
     "{peer} aborted connections mid-request ({err}). The remote process crashed or restarted, "
     "or a proxy / load balancer cut the connection (idle timeout, request rejected).",
     {"Check {peer}'s logs for crashes or restarts at that time.",
      "Check proxy / load-balancer idle timeouts versus how long requests take.",
      "Handle ECONNRESET explicitly: retry idempotent requests once, fail cleanly otherwise."},
     {"Did {peer} restart at the time of the reset?", NULL, NULL}},
    {"net.no_response", NULL, "dependency-unstable",
     "{peer} accepted the request and then closed the connection without replying.",
     {"Check {peer}'s logs for the rejected request.",
      "Verify both sides speak the same protocol (TLS vs plain, HTTP version)."},
     {NULL, NULL, NULL}},
    {"net.conn_leak", NULL, "resource-exhaustion",
     "Sockets are opened and never closed on an error path inside {fn}. Leaked descriptors "
     "accumulate until the process hits its fd limit and every new connection fails.",
     {"Close the socket on every early return in {fn} (single cleanup path / goto out).",
      "Add a test that exercises the error path and asserts the fd count is stable.",
      "Monitor open fds per process and alert well before the limit."},
     {"Which branch in {fn} returns without close()? Start from the first error it reports.",
      NULL, NULL}},
    {"net.retry_storm", NULL, "retry-policy",
     "The client hammered {peer} with retries and no backoff, multiplying load on a dependency "
     "that was already failing.",
     {"Use exponential backoff with jitter.", "Add a circuit breaker / retry budget."},
     {NULL, NULL, NULL}},
    {"fn.recursion", NULL, "code-defect",
     "{fn} recursed without terminating ({count} nested calls) until the stack overflowed and "
     "the process crashed. This is a code defect: a missing or unreachable base case, or a "
     "cycle in the input it walks.",
     {"Fix the base case in {fn}; add a depth limit as a safety net.",
      "Detect cycles in the data structure being walked (visited set).",
      "Add a regression test with the input that triggered it."},
     {"Which input reached {fn} right before the recursion started?", NULL, NULL}},
    {"fn.crash", NULL, "code-defect",
     "The process crashed in {fn}. The call path shows the exact code that faulted.",
     {"Run the failing input under AddressSanitizer or a debugger to see the faulting access.",
      "Check {fn} for NULL / freed / out-of-bounds pointer use."},
     {"Is the crash reproducible with the same input?", NULL, NULL}},
    {"fn.hang", NULL, "hang",
     "{fn} never returned: the process was blocked there when the trace ended.",
     {"Add timeouts to blocking calls made from {fn}.",
      "Capture a stack dump (gdb -p / eu-stack) while it hangs to see the blocking call."},
     {NULL, NULL, NULL}},
    {"fn.hotspot", NULL, "performance",
     "{fn} dominates execution time. It is the most valuable place to optimise.",
     {"Profile {fn} (perf / gprof) to find the hot loop.",
      "Cache its result or move it off the request path."},
     {NULL, NULL, NULL}},
    {"fn.slow_call", NULL, "performance",
     "{fn} is slow in its own code (not waiting on the network).",
     {"Profile {fn} for the slow path.", "Check for lock contention or disk I/O inside it."},
     {NULL, NULL, NULL}},
    {"cross.error_propagation", NULL, "code-defect",
     "{peer} failed with {err} and the error-handling path that followed crashed the process. "
     "The dependency failure is the trigger; the crash is a code defect in how that failure is "
     "handled (e.g. using a NULL / partial response).",
     {"Fix the error path: check the result of the network call before using the response.",
      "Add a test that simulates {err} from {peer} and asserts a clean error, not a crash.",
      "Then investigate why {peer} failed (its logs / restarts)."},
     {"What does the code do with the response buffer when recv fails?", NULL, NULL}},
    {"app.error", NULL, "application",
     "The application reported {err} ({count} times).",
     {"Read the error messages and the code that raises {err}."},
     {NULL, NULL, NULL}},
};

const cs_kb_entry *cs_kb_lookup(const char *detector, const char *err) {
    const cs_kb_entry *generic = NULL;
    for (size_t i = 0; i < sizeof KB / sizeof KB[0]; i++) {
        if (strcmp(KB[i].detector, detector) != 0) continue;
        if (KB[i].err && err && strcmp(KB[i].err, err) == 0) return &KB[i];
        if (!KB[i].err && !generic) generic = &KB[i];
    }
    return generic;
}

void cs_kb_render(const char *tmpl, const cs_finding *f, char *out, size_t n) {
    size_t len = 0;
    if (!n) return;
    out[0] = '\0';
    if (!tmpl) return;
    char tmp[64];
    for (const char *p = tmpl; *p && len + 1 < n;) {
        const char *rep = NULL;
        size_t skip = 0;
        if (*p == '{') {
            if (strncmp(p, "{peer}", 6) == 0) {
                rep = (f && f->peer) ? f->peer : "the dependency";
                skip = 6;
            } else if (strncmp(p, "{fn}", 4) == 0) {
                rep = (f && f->fn) ? f->fn : "the caller";
                skip = 4;
            } else if (strncmp(p, "{err}", 5) == 0) {
                rep = (f && f->err) ? f->err : "an error";
                skip = 5;
            } else if (strncmp(p, "{count}", 7) == 0) {
                snprintf(tmp, sizeof tmp, "%lld", f ? (long long)f->count : 0LL);
                rep = tmp;
                skip = 7;
            } else if (strncmp(p, "{value_dur}", 11) == 0) {
                double ns = f ? f->value : 0;
                if (ns >= 1e9)
                    snprintf(tmp, sizeof tmp, "%.2f s", ns / 1e9);
                else
                    snprintf(tmp, sizeof tmp, "%.1f ms", ns / 1e6);
                rep = tmp;
                skip = 11;
            }
        }
        if (rep) {
            int w = snprintf(out + len, n - len, "%s", rep);
            if (w < 0) break;
            len += (size_t)w;
            if (len >= n) {
                len = n - 1;
                break;
            }
            p += skip;
        } else {
            out[len++] = *p++;
            out[len] = '\0';
        }
    }
    out[len < n ? len : n - 1] = '\0';
}
