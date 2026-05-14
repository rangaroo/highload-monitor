#!/bin/bash
# Demo script for asciinema recording.
#
# Records a 3-pane demo:
#  - Pane 1: pf logs
#  - Pane 2: analyzer JSON output
#  - Pane 3: curl /v1/stats polling
#
# User should:
#  1. Start tmux with 3 panes
#  2. Run this script in pane 1
#  3. Manually run analyzer in pane 2
#  4. Manually run curl in pane 3
#  5. Manually send traffic with nc/iperf in pane 3
#
# Or, for a recorded script, use tmux with send-keys.

set -e

IFACE="${IFACE:-veth0}"
PF_BIN="${PF_BIN:-.}/pf"

if [ ! -x "$PF_BIN" ]; then
	echo "ERROR: $PF_BIN not found" >&2
	exit 1
fi

echo "=== Packet Forwarder Demo ==="
echo ""
echo "Starting pf on $IFACE..."
echo ""

exec "$PF_BIN" -iface "$IFACE" -promisc -http :9100 -dump :9101
