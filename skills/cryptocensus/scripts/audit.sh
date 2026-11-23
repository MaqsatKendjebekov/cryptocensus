#!/bin/bash
# Read-only CryptoCensus audit for an agent: selftest, SSH scan, optional TLS, the live
# downgrade proof, the roadmap and the report. Nothing is changed on any server.
# stdout: one JSON document. Human output goes to <run>/audit.log.
# Usage: audit.sh <targets> [ssh_port=22] [tls_port]
#   CRYPTOCENSUS=/path/to/cryptocensus   the binary, if it is not on PATH
#   CC_RUN_DIR=/path/to/dir              where to write, default ./cc_audit_<time>
set -u
T="${1:?usage: audit.sh <targets> [ssh_port=22] [tls_port]}"
SP="${2:-22}"; TP="${3:-}"
CC="${CRYPTOCENSUS:-$(command -v cryptocensus || true)}"
if [ -z "$CC" ] || [ ! -x "$CC" ]; then
  echo '{"error": "cryptocensus binary not found: set CRYPTOCENSUS or add it to PATH", "exit": 2}'; exit 2
fi
RUN="${CC_RUN_DIR:-./cc_audit_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$RUN"; LOG="$RUN/audit.log"; : >"$LOG"

if ! "$CC" selftest --no-color >>"$LOG" 2>&1; then
  echo "{\"error\": \"selftest failed, see $LOG\", \"exit\": 2}"; exit 2
fi
"$CC" scan --targets "$T" --port "$SP" --out "$RUN" --json >"$RUN/scan.json" 2>>"$LOG"
if [ $? -eq 2 ]; then cat "$RUN/scan.json"; exit 2; fi     # nothing answered: stop, nothing graded
if [ -n "$TP" ]; then
  "$CC" tls --targets "$T" --port "$TP" --out "$RUN" --append --json >"$RUN/tls.json" 2>>"$LOG"
fi
"$CC" downgrade --targets "$T" --port "$SP" --json >"$RUN/downgrade.json" 2>>"$LOG"
"$CC" roadmap --out "$RUN" --no-color >>"$LOG" 2>&1
"$CC" report --out "$RUN" --no-color >>"$LOG" 2>&1

doc() { if [ -s "$1" ]; then cat "$1"; else echo null; fi; }
printf '{\n"run": "%s",\n"scan": %s,\n"tls": %s,\n"downgrade": %s,\n' "$RUN" "$(doc "$RUN/scan.json")" "$(doc "$RUN/tls.json")" "$(doc "$RUN/downgrade.json")"
printf '"files": {"inventory": "%s/inventory.json", "cbom": "%s/cbom.json", "report": "%s/report.html", "dashboard": "%s/heatmap.html", "roadmap": "%s/roadmap.html", "sarif": "%s/cryptocensus.sarif", "log": "%s"}\n}\n' \
  "$RUN" "$RUN" "$RUN" "$RUN" "$RUN" "$RUN" "$LOG"
