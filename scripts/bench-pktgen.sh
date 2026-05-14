#!/bin/bash
# Benchmark script: measure pf max throughput before packet loss.
#
# Uses Linux pktgen kernel module to flood veth0 at increasing rates.
# Polls /v1/stats to detect when rx_drops > 0, recording the breaking-point pps.
#
# Requires:
#  - veth0 set up via netns-setup.sh
#  - pf running on veth0
#  - /sys/kernel/debug/pktgen available (requires CONFIG_NET_PKTGEN=m)
#
# Usage:
#  sudo ./scripts/bench-pktgen.sh
#
# Output: CSV to stdout: rate_pps,rx_packets,rx_drops

set -e

PF_STATS_URL="${PF_STATS_URL:-http://localhost:9100/v1/stats}"
IFACE="${IFACE:-veth0}"
PKTGEN_DIR="/sys/kernel/debug/pktgen"

if [ ! -d "$PKTGEN_DIR" ]; then
	echo "ERROR: pktgen not available at $PKTGEN_DIR" >&2
	echo "Load: sudo modprobe pktgen" >&2
	exit 1
fi

cleanup() {
	echo "Cleaning up pktgen..." >&2
	echo "reset" >"$PKTGEN_DIR/pgctrl" 2>/dev/null || true
}
trap cleanup EXIT

# Initialize pktgen device
echo "Setting up pktgen on $IFACE..." >&2
{
	echo "rem_device_all"
	echo "add_device $IFACE"
} >"$PKTGEN_DIR/pgctrl"

sleep 0.5

DEV="$PKTGEN_DIR/$IFACE"
{
	echo "pkt_size 1500"
	echo "burst 1000"
	echo "flag IPDST_RND"
	echo "flag UDPSRC_RND"
	echo "flag UDPDST_RND"
	# Destination: pick random IPs to stress all filters
	echo "dst_min 192.168.0.1"
	echo "dst_max 192.168.99.254"
	echo "src 192.168.99.2"
} >"$DEV"

# Test rates in pps: start low, ramp up until we see drops
rates=(100000 500000 1000000 2000000 5000000 10000000)

baseline_drops=$(curl -s "$PF_STATS_URL" | grep -o '"rx_drops":[0-9]*' | cut -d: -f2)
echo "rx_pps,rx_packets,rx_drops" >&2

for rate in "${rates[@]}"; do
	# Set pktgen rate
	echo "rate_pps $rate" >"$DEV"

	# Start generator, let it run for 5s
	echo "start" >"$PKTGEN_DIR/pgctrl"
	sleep 5
	echo "stop" >"$PKTGEN_DIR/pgctrl"

	# Check pf stats
	stats=$(curl -s "$PF_STATS_URL")
	rx_packets=$(echo "$stats" | grep -o '"rx_packets":[0-9]*' | cut -d: -f2)
	rx_drops=$(echo "$stats" | grep -o '"rx_drops":[0-9]*' | cut -d: -f2)

	# Estimate actual pps from packet count
	actual_pps=$((rx_packets / 5))

	echo "$actual_pps,$rx_packets,$rx_drops" >&2

	# Stop if we're seeing drops
	if [ "$rx_drops" -gt "$baseline_drops" ]; then
		echo "BREAKING POINT: ${actual_pps} pps, drops=$rx_drops" >&2
		exit 0
	fi
done

echo "No drops detected at max rate ${rates[-1]} pps" >&2
