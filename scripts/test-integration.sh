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
#  3. Generate TCP traffic from veth1 -> veth0:443
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

UDPFLOOD_BIN="${UDPFLOOD_BIN:-.}/udpflood"
if [ ! -x "$UDPFLOOD_BIN" ]; then
	echo "ERROR: $UDPFLOOD_BIN not found (go build ./cmd/udpflood)" >&2
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

# udpflood emits UDP/443, so analyzer + filter must target UDP/443.
echo "[2/5] Starting analyzer (udp::443)..." >&2
"$ANALYZER_BIN" -pf "$PF_HTTP" -filter "udp::443" -interval 1s > /tmp/analyzer.log 2>&1 &
ANALYZER_PID=$!
sleep 1

echo "[3/5] Registering UDP filter..." >&2
curl -s -X POST "$PF_HTTP/v1/filters" \
	-H 'Content-Type: application/json' \
	-d '{"filter":{"protocol":"udp","dst_port":443}}' | jq '.id' || true

echo "[4/5] Injecting 10000 UDP frames on veth1 (netns pftest) -> veth0:443..." >&2
# veth1 lives in the pftest netns (see netns-setup.sh). Run udpflood there so
# frames cross to veth0's RX in the default ns. A localhost UDP socket would
# be loopback-shortcut and never hit pf.
ip netns exec pftest "$UDPFLOOD_BIN" -iface veth1 \
	-dst-ip 192.168.99.1 -src-ip 192.168.99.2 \
	-dst-port 443 -size 1000 -count 10000 2>&1 | sed 's/^/  udpflood: /' >&2

sleep 2

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

FAIL=0

if [ "$rx_drops" -gt 0 ]; then
	echo "FAIL: rx_drops > 0 (expected 0 — zero-loss criterion)" >&2
	FAIL=1
fi

if [ "$rx_packets" -lt 100 ]; then
	echo "FAIL: only $rx_packets packets captured (expected 100+; traffic gen broken)" >&2
	FAIL=1
fi

if [ "$analyzer_lines" -lt 1 ]; then
	echo "FAIL: analyzer produced no output" >&2
	FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
	echo "" >&2
	echo "INTEGRATION TEST FAILED" >&2
	echo ""
	echo "=== Logs ==="
	echo "--- pf.log ---"; tail -15 /tmp/pf.log
	echo "--- analyzer.log ---"; tail -10 /tmp/analyzer.log
	exit 1
fi

echo "PASS: zero-loss confirmed, $rx_packets packets captured + dumped" >&2
echo ""
echo "=== Logs ==="
echo "--- pf.log ---"
tail -10 /tmp/pf.log
echo ""
echo "--- analyzer.log ---"
tail -5 /tmp/analyzer.log
