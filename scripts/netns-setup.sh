#!/usr/bin/env bash
# netns-setup.sh - create a veth pair for local PF testing
#
# After running this:
#   sudo ./pf -iface veth0 -promisc
#   ping -I veth1 192.168.99.1          # generate traffic
#   tcpdump -i veth1 -n                 # watch forwarded frames arrive back
#
# Tear down:
#   sudo ip link delete veth0           # removes both veth0 and veth1

set -euo pipefail

VETH0=veth0
VETH1=veth1
NSNAME=pftest
IP0=192.168.99.1/24  # assigned to veth0 (default ns)
IP1=192.168.99.2/24  # assigned to veth1 (in pftest ns)

# clean up any previous run
ip link del "$VETH0" 2>/dev/null || true
ip netns del "$NSNAME" 2>/dev/null || true

echo "creating netns $NSNAME and veth pair"
ip netns add "$NSNAME"
ip link add "$VETH0" type veth peer name "$VETH1"
ip link set "$VETH1" netns "$NSNAME"

ip link set "$VETH0" up
ip -n "$NSNAME" link set "$VETH1" up
ip -n "$NSNAME" link set lo up  # enable loopback in namespace

ip addr add "$IP0" dev "$VETH0"
ip -n "$NSNAME" addr add "$IP1" dev "$VETH1"

# allow the kernel to accept packets destined for other MACs (needed for PF promisc mode)
ip link set "$VETH0" promisc on
ip -n "$NSNAME" link set "$VETH1" promisc on

echo "done"
echo ""
echo "  default ns:  veth0  $IP0    <- PF binds here"
echo "  pftest ns:   veth1  $IP1    <- traffic source"
echo ""
echo "quick test:"
echo "  sudo ./pf -iface veth0 -promisc"
echo "  sudo ip netns exec pftest ping -c 4 192.168.99.1"
echo ""
echo "or from pftest ns:"
echo "  sudo ip netns exec pftest tcpdump -i veth1 -n"
