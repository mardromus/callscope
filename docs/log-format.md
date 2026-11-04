# Trace format (JSON Lines)

One JSON object per line. Lines starting with `#` and blank lines are ignored;
malformed lines are skipped and counted. Order does not matter: events are sorted
by `ts` when loaded.

## Common fields

| Field | Type | Meaning |
|---|---|---|
| `ts` | int | wall-clock nanoseconds since the Unix epoch (integer, not float!) |
| `pid` | int | process id |
| `tid` | int | thread id (defaults to `pid`) |
| `k` | string | event kind (below) |
| `dur` | int | duration in ns (absent when unknown) |

## Kinds

| `k` | Extra fields | Notes |
|---|---|---|
| `proc_start` | `msg` (command line), `code` (component) | |
| `proc_exit` | `rc` (exit status), `sig` | `rc = 128 + sig` when killed |
| `signal` | `sig`, `err` (`SIGSEGV`), `depth` | frames open at this moment are the crash site |
| `fn_enter` | `fn`, `addr`, `depth` | |
| `fn_exit` | `fn`, `depth`, `dur` | |
| `net_connect` | `fd`, `peer`, `proto`, `rc`, `errno`, `err`, `dur` | `rc < 0` = failed |
| `net_accept` | `fd` (new socket), `peer`, `proto` | |
| `net_send` / `net_recv` | `fd`, `peer`, `rc`, `bytes`, `err`, `dur` | `net_recv` with `rc = 0` = peer closed |
| `net_close` | `fd`, `peer`, `sent`, `recvd`, `dur` (socket lifetime) | |
| `net_dns` | `host`, `rc` (0 = ok), `err` (`EAI_NONAME`), `msg` (first address), `dur` | |
| `app_error` | `code`, `msg` | from `cs_error()` |
| `app_log` | `code` (level), `msg` | from `cs_log()` |

`peer` is `ip:port`, `[ipv6]:port` or `unix:/path`. `err` is the symbolic errno
name; if only `err` is present, `errno` is derived from it.

## Example

```json
{"ts":1793809800000412000,"pid":4242,"tid":4242,"k":"fn_enter","fn":"charge_payment","depth":3}
{"ts":1793809800000519000,"pid":4242,"tid":4242,"k":"net_dns","host":"payments.internal","rc":0,"dur":61000,"msg":"10.0.4.22:9102"}
{"ts":1793809800000633000,"pid":4242,"tid":4242,"k":"net_connect","fd":7,"proto":"tcp","peer":"10.0.4.22:9102","rc":-1,"errno":111,"err":"ECONNREFUSED","dur":54000}
{"ts":1793809800100801000,"pid":4242,"tid":4242,"k":"app_error","code":"PAYMENT_UNAVAILABLE","msg":"payment service unreachable after 3 attempts (order 1013)"}
{"ts":1793809800100903000,"pid":4242,"tid":4242,"k":"fn_exit","fn":"charge_payment","depth":3,"dur":100491000}
```

## Producing traces from other languages

Emit the same objects from your own code (one `write` per line, `O_APPEND`) and
callscope analyses them like native traces. Network events alone are enough for
the network detectors; add `fn_enter`/`fn_exit` to get call paths.
