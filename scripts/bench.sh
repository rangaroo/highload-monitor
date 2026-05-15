#!/bin/bash
# Benchmark: find pf's max sustained pps before rx_drops > 0 (zero-loss point).
#
# Uses the in-repo udpflood tool (raw AF_PACKET injector) on veth1 in the
# pftest netns. Ramps offered load by sending progressively larger bursts and
# polling /v1/stats for the first nonzero rx_drops.
#
# Prerequisites:
#  - veth pair up: sudo ./scripts/netns-setup.sh
#  - binaries built: go build -o pf ./cmd/pf && go build -o udpflood ./cmd/udpflood
#  - pf running: sudo ./pf -iface veth0 -promisc
#
# Usage:
#  sudo ./scripts/bench.sh
#
# Output: a table of offered-pps vs rx_drops, plus the detected breaking point.

set -e

PF_STATS_URL="${PF_STATS_URL:-http://localhost:9100/v1/stats}"
UDPFLOOD_BIN="${UDPFLOOD_BIN:-.}/udpflood"
NS="pftest"
IFACE="veth1"
DST_IP="192.168.99.1"
SRC_IP="192.168.99.2"
DST_PORT=443
SIZE=1000

if [ ! -x "$UDPFLOOD_BIN" ]; then
	echo "ERROR: $UDPFLOOD_BIN not found (go build -o udpflood ./cmd/udpflood)" >&2
	exit 1
fi

if ! curl -sf "$PF_STATS_URL" >/dev/null; then
	echo "ERROR: pf not reachable at $PF_STATS_URL (start pf first)" >&2
	exit 1
fi

get_drops() { curl -s "$PF_STATS_URL" | jq '.rx_drops'; }
get_rx()    { curl -s "$PF_STATS_URL" | jq '.rx_packets'; }

# Offered rates in pps. udpflood -pps caps the send rate; 0 = unbounded
# (line rate, as fast as the syscall loop allows).
rates=(100000 250000 500000 1000000 2000000 0)

baseline_drops=$(get_drops)
echo "Baseline rx_drops: $baseline_drops" >&2
echo "" >&2
printf "%-12s %-12s %-12s %-10s\n" "offered_pps" "actual_pps" "rx_total" "rx_drops" >&2
echo "------------------------------------------------------" >&2

breaking_point=""
for rate in "${rates[@]}"; do
	rx_before=$(get_rx)

	# 2-second burst at the target rate (count chosen to last ~2s; for
	# unbounded, send a large fixed count).
	if [ "$rate" -eq 0 ]; then
		count=5000000
		label="unbounded"
	else
		count=$((rate * 2))
		label="$rate"
	fi

	out=$(ip netns exec "$NS" "$UDPFLOOD_BIN" -iface "$IFACE" \
		-dst-ip "$DST_IP" -src-ip "$SRC_IP" -dst-port "$DST_PORT" \
		-size "$SIZE" -count "$count" ${rate:+-pps "$rate"} 2>&1)

	actual_pps=$(echo "$out" | grep -oE '[0-9]+ pps' | grep -oE '[0-9]+' || echo "?")

	sleep 0.5
	rx_after=$(get_rx)
	drops=$(get_drops)
	rx_delta=$((rx_after - rx_before))

	printf "%-12s %-12s %-12s %-10s\n" "$label" "$actual_pps" "$rx_delta" "$drops" >&2

	if [ "$drops" -gt "$baseline_drops" ]; then
		breaking_point="$label (actual ${actual_pps} pps)"
		break
	fi
done

echo "" >&2
if [ -n "$breaking_point" ]; then
	echo "BREAKING POINT: rx_drops first exceeded baseline at offered=$breaking_point" >&2
else
	echo "NO LOSS up to max offered rate (${rates[-2]} pps + unbounded burst)." >&2
	echo "pf kept rx_drops == $baseline_drops throughout." >&2
fi
