# Architecture

callscope is split into a capture side (runtime libraries that write a trace)
and an analysis side (a library that reads the trace and explains it).

## 1. Capture

### Function level: `libcallscope_trace.so`

With `-finstrument-functions` the compiler calls

```c
void __cyg_profile_func_enter(void *fn, void *caller);
void __cyg_profile_func_exit(void *fn, void *caller);
```

around every function. The tracer:

1. keeps a per-thread stack of entry timestamps, so every `fn_exit` carries its duration;
2. resolves the function address to a name with `dladdr` (cached per thread);
3. installs crash handlers for SIGSEGV/SIGABRT/SIGBUS/SIGFPE/SIGILL on an **alternate
   signal stack**, so even a stack overflow from runaway recursion is recorded before
   the process dies;
4. guards against re-entrancy and honours `CALLSCOPE_MAX_DEPTH`.

### Network level: `libcallscope_net.so`

Loaded with `LD_PRELOAD`, it wraps `socket, connect, accept/accept4, send/recv,
sendto/recvfrom, sendmsg/recvmsg, read/write, close, getsockopt, getaddrinfo`.

- A table indexed by fd remembers which fds are sockets, their protocol and peer,
  and the byte totals reported at `close`.
- `read`/`write` are only traced for fds known to be sockets.
- Non-blocking connects (`EINPROGRESS`) are resolved from `getsockopt(SO_ERROR)` or
  the first I/O on the socket, so the recorded latency is the real handshake time.
- DNS traffic issued *by* `getaddrinfo` is hidden (one `net_dns` event instead).

### Shared writer

Both libraries use one writer (`src/runtime/common/writer.c`): events are encoded
into a stack buffer by `cs_event_to_jsonl` (no malloc) and appended with a single
raw `write(2)` syscall on an `O_APPEND` descriptor. Lines from several components
and forked children therefore never interleave.

### Other sources

- `callscope import strace`: parses `strace -f -tt -T` (also `-ttt`, `-yy`,
  unfinished/resumed calls, signals and exit lines).
- `callscope gen`: a deterministic simulator with injected faults.

## 2. Analysis (`libcallscope.a`)

```
eventlog ──► calltree ──► net time attribution ──► fnstats
    │            │                                    │
    └──► netstats│                                    │
                 ▼                                    ▼
            detectors (function, network, application, cross-level)
                 │
                 ▼
         findings (scored, ranked, F01..Fnn)
                 │
                 ▼
     rca rules engine ──► (optional) LLM agent ──► reports
```

| Stage | File | Output |
|---|---|---|
| Load | `core/log/eventlog.c` | events sorted by `(ts, line)`, strings interned |
| Call trees | `core/analyze/calltree.c` | frames with incl/excl time, open (never returned) frames, **`ev_frame[]`**: for every event, the innermost frame open on its thread |
| Network time | `core/analyze/correlate.c` | `net_self` / `net_wait` per frame |
| Function stats | `core/analyze/fnstats.c` | calls, totals, exact p50/p95/p99, slowest frame |
| Network stats | `core/analyze/netstats.c` | sessions per `(pid, fd)`, per-peer and per-DNS aggregates |
| Detectors | `core/analyze/detect_*.c` | findings with evidence event indices and call path |
| RCA | `core/rca/rules.c`, `core/ai/agent.c` | `cs_rca_result` |
| Reports | `core/report/*.c` | terminal, Markdown, JSON, HTML (timeline + flame graph SVG) |

### Why the event → frame map matters

Network events come from a different component than function events, but they
share `tid` and a clock. While replaying the trace in time order we always know the
top of each thread's stack, so recording `ev_frame[i]` costs O(1) per event. That
single array powers:

- the "where" of every network finding (`main > handle_request > charge_payment`);
- attribution of network wait to functions (cross-level slow-call findings);
- error propagation (a failed `recv` followed by an `app_error` or `SIGSEGV` on the
  same thread).

## 3. Root cause

See [ai-rca.md](ai-rca.md).
