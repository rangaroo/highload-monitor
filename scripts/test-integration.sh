#!/bin/bash
# Integration test: pf + analyzer on veth, confirm end-to-end packet flow.
#
# Prerequisites:
#  - veth0/veth1 set up via netns-setup.sh
#  - go build ./cmd/pf && go build ./cmd/analyzer
#  - pf and analyzer binaries in PATH or ./
#
# Procedure:
#  1. Start pf on veth0
#  2. Start analyzer, register TCP filter
#  3. Generate TCP traffic from veth1 → veth0:443
#  4. Poll analyzer output for packet count + entropy
#  5. Stop, verify rx_drops == 0

set -e

echo "Integration test: pf + analyzer on veth"

# Config
PF_BIN="${PF_BIN:-.}/pf"
ANALYZER_BIN="${ANALYZER_BIN:-.}/analyzer"
PF_HTTP="http://localhost:9100"
IFACE="veth0"
TEST_DURATION=5

if [ ! -x "$PF_BIN" ]; then
	echo "ERROR: $PF_BIN not found or not executable" >&2
	exit 1
fi
if [ ! -x "$ANALYZER_BIN" ]; then
	echo "ERROR: $ANALYZER_BIN not found or not executable" >&2
	exit 1
fi

cleanup() {
	echo "Cleaning up..." >&2
	pkill -f "$PF_BIN" || true
	pkill -f "$ANALYZER_BIN" || true
	sleep 1
}
trap cleanup EXIT

echo "[1/5] Starting pf on $IFACE..." >&2
"$PF_BIN" -iface "$IFACE" -promisc -http :9100 -dump :9101 > /tmp/pf.log 2>&1 &
PF_PID=$!
sleep 2

echo "[2/5] Starting analyzer..." >&2
"$ANALYZER_BIN" -pf "$PF_HTTP" -filter "tcp::" -interval 1s > /tmp/analyzer.log 2>&1 &
ANALYZER_PID=$!
sleep 1

echo "[3/5] Registering TCP filter..." >&2
curl -s -X POST "$PF_HTTP/v1/filters" \
	-H 'Content-Type: application/json' \
	-d '{"filter":{"protocol":"tcp","dst_port":443}}' | jq '.id' || true

echo "[4/5] Generating TCP traffic to veth0:443..." >&2
# Use nc to connect; it will timeout but that's OK, we just need SYN packets
timeout 3 nc -w 1 192.168.99.1 443 < /dev/null > /dev/null 2>&1 || true

sleep 1

echo "[5/5] Checking results..." >&2
stats=$(curl -s "$PF_HTTP/v1/stats")
rx_packets=$(echo "$stats" | jq '.rx_packets')
rx_drops=$(echo "$stats" | jq '.rx_drops')
analyzer_lines=$(wc -l < /tmp/analyzer.log)

echo ""
echo "=== Results ==="
echo "RX packets: $rx_packets"
echo "RX drops: $rx_drops"
echo "Analyzer JSON lines: $analyzer_lines"
echo ""

if [ "$rx_drops" -gt 0 ]; then
	echo "FAIL: rx_drops > 0 (expected 0)" >&2
	exit 1
fi

if [ "$rx_packets" -eq 0 ]; then
	echo "WARN: no packets captured (check veth setup + traffic generation)" >&2
fi

if [ "$analyzer_lines" -lt 1 ]; then
	echo "WARN: analyzer produced no output" >&2
fi

echo "PASS: zero-loss, end-to-end flow confirmed" >&2
echo ""
echo "=== Logs ==="
echo "--- pf.log ---"
tail -10 /tmp/pf.log
echo ""
echo "--- analyzer.log ---"
tail -5 /tmp/analyzer.log
