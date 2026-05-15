#!/bin/bash
# Append one benchmark run to docs/benchmarks-results.json.
#
# Reversible by design: never edits past runs, only appends. To discard a run,
# git checkout the file or pop the last array element by hand.
#
# Usage:
#   ./scripts/record-bench.sh <description> <pps> <gbps> <cpu_percent> <rx_drops_at_pps> [notes]
#
# Example:
#   ./scripts/record-bench.sh "baseline cBPF only" 1000000 12.0 95 1000000 "single RX queue"
#
# Branch + commit + date are auto-filled from git. Requires jq.

set -e

RESULTS="docs/benchmarks-results.json"

if [ $# -lt 5 ]; then
	echo "usage: $0 <description> <pps> <gbps> <cpu_percent> <rx_drops_at_pps> [notes]" >&2
	exit 1
fi

DESC="$1"
PPS="$2"
GBPS="$3"
CPU="$4"
DROPS_AT="$5"
NOTES="${6:-}"

BRANCH=$(git rev-parse --abbrev-ref HEAD)
COMMIT=$(git rev-parse --short HEAD)
DATE=$(date +%Y-%m-%d)

if [ ! -f "$RESULTS" ]; then
	echo "ERROR: $RESULTS not found (run from repo root)" >&2
	exit 1
fi

run=$(jq -n \
	--arg branch "$BRANCH" \
	--arg commit "$COMMIT" \
	--arg desc "$DESC" \
	--arg date "$DATE" \
	--argjson pps "$PPS" \
	--argjson gbps "$GBPS" \
	--argjson cpu "$CPU" \
	--argjson drops_at "$DROPS_AT" \
	--arg notes "$NOTES" \
	'{branch: $branch, commit: $commit, description: $desc, date: $date, pps: $pps, gbps: $gbps, cpu_percent: $cpu, rx_drops_at_pps: $drops_at, notes: $notes}')

tmp=$(mktemp)
jq --argjson run "$run" '.runs += [$run]' "$RESULTS" > "$tmp"
mv "$tmp" "$RESULTS"

echo "Appended run to $RESULTS:" >&2
echo "$run" | jq . >&2
echo "" >&2
echo "Review with: jq '.runs[] | \"\(.branch): \(.pps) pps, \(.cpu_percent)% CPU\"' $RESULTS" >&2
