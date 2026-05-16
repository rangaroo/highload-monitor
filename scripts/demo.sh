#!/bin/bash
# Automated demo for asciinema recording.
# Runs entirely in one terminal: starts pf in background, registers a filter,
# sends 10s of traffic, polls stats, then tears down cleanly.
#
# Usage:
#   sudo ./scripts/demo.sh
#
# Prerequisites:
#   go build -o pf ./cmd/pf
#   go build -o analyzer ./cmd/analyzer
#   go build -o udpflood ./cmd/udpflood
#   sudo ./scripts/netns-setup.sh

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PF_BIN="${PF_BIN:-$REPO_ROOT/pf}"
ANALYZER_BIN="${ANALYZER_BIN:-$REPO_ROOT/analyzer}"
UDPFLOOD_BIN="${UDPFLOOD_BIN:-$REPO_ROOT/udpflood}"
NS="pftest"
IFACE_RX="veth0"
IFACE_TX="veth1"
DST_IP="192.168.99.1"
PF_HTTP="http://localhost:9100"

for bin in "$PF_BIN" "$ANALYZER_BIN" "$UDPFLOOD_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "ERROR: $bin not found - run go build first" >&2
        exit 1
    fi
done

# verify netns access before starting anything
if ! ip netns exec "$NS" true 2>/dev/null; then
    echo "ERROR: cannot enter netns '$NS' - run: sudo ./scripts/netns-setup.sh" >&2
    exit 1
fi

cleanup() {
    echo ""
    echo "--- shutting down ---"
    kill "$PF_PID" 2>/dev/null || true
    kill "$ANALYZER_PID" 2>/dev/null || true
    wait "$PF_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== highload-monitor demo ==="
echo ""
PF_QUEUES="${PF_QUEUES:-1}"
echo "--- starting pf on $IFACE_RX ($PF_QUEUES queue(s)) ---"
"$PF_BIN" -iface "$IFACE_RX" -promisc -queues "$PF_QUEUES" &
PF_PID=$!
sleep 1

echo ""
echo "--- health check ---"
curl -s "$PF_HTTP/v1/health" | jq .
sleep 0.5

ANALYZER_LOG="/tmp/analyzer-demo.log"
echo ""
echo "--- starting analyzer (udp::443 filter) -> log: $ANALYZER_LOG ---"
"$ANALYZER_BIN" -pf "$PF_HTTP" -filter "udp::443" -interval 1s >"$ANALYZER_LOG" 2>&1 &
ANALYZER_PID=$!
sleep 1

echo ""
echo "--- current filters ---"
curl -s "$PF_HTTP/v1/filters" | jq .
sleep 0.5

echo ""
echo "--- analyzer stats (live, from log) ---"
echo ""
echo "--- sending 10s of UDP traffic into veth ---"
ip netns exec "$NS" "$UDPFLOOD_BIN" \
    -iface "$IFACE_TX" -dst-ip "$DST_IP" -dst-port 443 \
    -parallel 4 -duration 10s >/dev/null 2>&1 &
FLOOD_PID=$!

echo ""
echo "--- polling /v1/stats every 2s (10s) ---"
for i in 1 2 3 4 5; do
    sleep 2
    echo "=== pf stats ==="
    curl -s "$PF_HTTP/v1/stats" | jq '{rx_packets, rx_drops, tx_packets}'
    echo "=== analyzer ==="
    tail -n 2 "$ANALYZER_LOG" 2>/dev/null || true
    echo ""
done

wait "$FLOOD_PID" 2>/dev/null || true

echo ""
echo "--- removing filter ---"
FID=$(curl -s "$PF_HTTP/v1/filters" | jq -r '.filters[0].id')
if [ -n "$FID" ] && [ "$FID" != "null" ]; then
    curl -s -X DELETE "$PF_HTTP/v1/filters/$FID"
    echo "removed filter $FID"
fi
sleep 0.5

echo ""
echo "--- final stats ---"
curl -s "$PF_HTTP/v1/stats" | jq .

echo ""
echo "=== demo complete ==="
