#!/usr/bin/env bash
# CLI end-to-end checks: every command runs, exit codes mean something, and
# every synthetic scenario's RCA names the expected root cause.
set -euo pipefail
CS=${1:?usage: e2e.sh path/to/callscope}
DATA=$(cd "$(dirname "$0")" && pwd)/data
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

"$CS" version >/dev/null || fail "version"
"$CS" help | grep -q "record" || fail "help"
"$CS" gen --list | grep -q upstream-down || fail "gen --list"

"$CS" gen healthy -o "$tmp/h.jsonl" 2>/dev/null
"$CS" analyze "$tmp/h.jsonl" --no-color >/dev/null && rc=0 || rc=$?
[ "$rc" = 0 ] || fail "healthy trace should exit 0 (got $rc)"

for s in upstream-down slow-upstream dns-failure recursion-crash reset-crash fd-leak; do
  expected=$("$CS" gen --list | awk -v s="$s" '$1==s {print $2}')
  "$CS" gen "$s" -o "$tmp/$s.jsonl" 2>/dev/null
  "$CS" analyze "$tmp/$s.jsonl" --no-color >/dev/null && rc=0 || rc=$?
  [ "$rc" = 1 ] || fail "$s: analyze should exit 1 when problems are found (got $rc)"
  root=$("$CS" rca "$tmp/$s.jsonl" --json | python3 -c '
import json,sys
d=json.load(sys.stdin)
print(d["causal_chain"][0]["detector"])') || true
  [ "$root" = "$expected" ] || fail "$s: root $root, expected $expected"
  "$CS" report "$tmp/$s.jsonl" -o "$tmp/$s.html" --md "$tmp/$s.md" 2>/dev/null
  grep -q "</html>" "$tmp/$s.html" || fail "$s: html report"
  echo "ok  $s -> $root"
done

"$CS" import strace "$DATA/sample.strace" -o "$tmp/s.jsonl" --date 2026-11-04 2>/dev/null
out=$("$CS" analyze "$tmp/s.jsonl" --json || true)
echo "$out" | python3 -c 'import json,sys; json.load(sys.stdin)' || fail "import + analyze --json"
echo "ok  strace import"

if "$CS" analyze /nonexistent.jsonl 2>/dev/null; then fail "missing file should fail"; fi
echo "all e2e checks passed"
