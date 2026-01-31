#!/usr/bin/bash

# Set up tap0
sudo ip tuntap add name tap0 mode tap user $USER 
sudo ip link set tap0 up
sudo ip addr add 192.168.69.1/24 dev tap0

# Set up tap1
sudo ip tuntap add name tap1 mode tap user $USER 
sudo ip link set tap1 up
sudo ip addr add 192.168.69.2/24 dev tap1

# Create a bridge
sudo ip link add name br0 type bridge

# Add both TAP interfaces to the bridge
sudo ip link set tap0 master br0
sudo ip link set tap1 master br0

# Bring up the bridge
sudo ip link set br0 up

# Network emulation parameters (customize these!)
DELAY="10ms"           # One-way delay (RTT will be 2x this)
BANDWIDTH="400mbit"     # Bandwidth limit
BUFFER_PACKETS="4000"   # Buffer size in packets (router queue)
MTU=1500              # Maximum transmission unit
NETEM_LIMIT="4000"   # Netem queue limit in packets (must be large for high BDP!)

# Calculate buffer size in bytes
BUFFER_BYTES=$((BUFFER_PACKETS * MTU))

# Calculate burst size (should be at least rate/HZ, typically rate/10 for smoother shaping)
# For 10mbit: 10000000/8/10 = 125000 bytes
BURST=$((10 * MTU))

# Apply traffic control on tap0 (server side)
# netem for delay with large buffer to handle BDP
sudo tc qdisc add dev tap0 root handle 1: netem delay $DELAY limit $NETEM_LIMIT
# tbf for bandwidth limiting with tail-drop
sudo tc qdisc add dev tap0 parent 1:1 handle 10: tbf rate $BANDWIDTH burst $BURST limit $BUFFER_BYTES

# Apply traffic control on tap1 (client side)
sudo tc qdisc add dev tap1 root handle 1: netem delay $DELAY limit $NETEM_LIMIT
sudo tc qdisc add dev tap1 parent 1:1 handle 10: tbf rate $BANDWIDTH burst $BURST limit $BUFFER_BYTES

echo "Network emulation setup complete:"
echo "  - Delay: $DELAY per direction (RTT: ~$((2 * ${DELAY%ms}))ms)"
echo "  - Bandwidth: $BANDWIDTH"
echo "  - Buffer: $BUFFER_PACKETS packets ($BUFFER_BYTES bytes)"
echo "  - Loss: Only on buffer overflow (tail-drop)"
echo ""
echo "BDP calculation for reference:"
BDP_BYTES=$((${BANDWIDTH%mbit} * 1000000 / 8 * ${DELAY%ms} / 1000))
BDP_PACKETS=$((BDP_BYTES / MTU))
echo "  - Bandwidth-Delay Product: ~$BDP_PACKETS packets ($BDP_BYTES bytes)"
if [ $BUFFER_PACKETS -lt $BDP_PACKETS ]; then
    echo "  ⚠ Warning: Buffer < BDP, expect losses even at full link utilization"
else
    echo "  ✓ Buffer >= BDP, good for testing"
fi
