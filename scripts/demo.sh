#!/usr/bin/env bash
# End-to-end demo: run the instrumented order service against mock upstreams
# that misbehave in different ways, record function + network traces, and
# produce an HTML report with the root cause for each run.
#
#   ./scripts/demo.sh [build-dir]        (default: build)
#   open demo-out/*.html
set -u
BUILD=${1:-build}
CS="$BUILD/callscope"
APP="$BUILD/examples/orderservice"
MOCK="$BUILD/examples/mock_upstream"
OUT=demo-out
INV=127.0.0.1:19101
PAY=127.0.0.1:19102

for bin in "$CS" "$APP" "$MOCK"; do
  [ -x "$bin" ] || { echo "missing $bin - run: make build" >&2; exit 1; }
done
mkdir -p "$OUT"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; pids=(); }
trap cleanup EXIT

start_mock() { # port mode [delay]
  "$MOCK" --port "$1" --mode "$2" --delay-ms "${3:-0}" 2>/dev/null &
  pids+=($!)
  sleep 0.2
}

run() { # name, app args...
  local name=$1; shift
  echo
  echo "=== $name ==="
  "$CS" record -o "$OUT/$name.jsonl" --report "$OUT/$name.html" -- \
    "$APP" --inventory "$INV" --payment "$PAY" --requests 8 "$@"
  "$CS" report "$OUT/$name.jsonl" --md "$OUT/$name.md" >/dev/null 2>&1
}

start_mock 19101 ok

start_mock 19102 ok
run healthy
cleanup; start_mock 19101 ok

start_mock 19102 slow 700
run slow-payment
cleanup; start_mock 19101 ok

# nothing listening on the payment port
run payment-down

start_mock 19102 reset
run reset-crash --bug-null-reply
cleanup; start_mock 19101 ok; start_mock 19102 ok

run recursion-crash --bug-recursion

echo
echo "Reports written to $OUT/:"
ls -1 "$OUT"/*.html
