# Detectors

Every finding has an id (`F01` = highest score), a detector name, a level, a
severity, a title and detail, the call path where it happened, and up to 8
evidence event indices. Score = severity weight + log2(occurrences) / 2, plus a
bonus for cross-level findings (they explain more).

## Function level

| Detector | Fires when | Severity |
|---|---|---|
| `fn.crash` | a fatal signal was recorded (or strace saw "killed by") | critical |
| `fn.hang` | frames are still open at the end of the trace without a crash, innermost open for ≥ `slow_min` | medium/high |
| `fn.recursion` | one function appears ≥ `recursion_limit/2` times on a single stack deeper than `recursion_limit` (128) | high, critical if it crashed |
| `fn.slow_call` | a call takes ≥ max(50 ms, min(5 × median, 1 s)); pass-through ancestors and loop/dispatcher frames are skipped so the *deepest* slow function is reported | medium/high |
| `fn.hotspot` | a leaf-like function owns ≥ 35% of execution time excluding network waits | low/medium |

## Network level

| Detector | Fires when | Severity |
|---|---|---|
| `net.connect_failure` | connects to a peer failed (`ECONNREFUSED`, `ETIMEDOUT`, `EMFILE`, ...) | high, critical if every attempt (≥3) failed |
| `net.retry_storm` | ≥ 4 failed connects to one peer within 10 s; reports whether gaps grow (backoff) | medium, low with backoff |
| `net.dns_failure` / `net.dns_slow` | lookups failed / took ≥ 300 ms | high / medium |
| `net.slow_connect` / `net.slow_io` | a handshake or single send/recv took ≥ 300 ms | medium/high |
| `net.reset` | `ECONNRESET` / `EPIPE` / I/O errors on a session | high |
| `net.no_response` | request sent, then the peer closed without a byte back | medium |
| `net.conn_leak` | ≥ 3 sockets never closed, or any `EMFILE`/`ENFILE` | medium, critical with EMFILE |

## Application level

| Detector | Fires when |
|---|---|
| `app.error` | `cs_error()` events, grouped by code |
| `app.exit_status` | the process exited non-zero (and was not killed by a signal) |

## Cross-level

| Detector | Fires when |
|---|---|
| `cross.slow_because_network` | a slow function spent ≥ 60% of its slowest call blocked in network calls; names the dominant peer |
| `cross.error_propagation` | an `app_error` or crash on a thread was preceded (≤ 2 s) by a network failure on the same thread; grouped by (peer, error, effect) |

## Tuning

`cs_analyze_opts` (or the CLI flags `--slow-ms`, `--net-slow-ms`) controls the
thresholds. Defaults are in `cs_analyze_opts_default()`.
