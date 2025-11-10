#!/usr/bin/bash

# Usage: ./scripts/perf_client_run.sh [bbr|cubic|reno|none]
# Default is bbr

ALGO=${1:-bbr}

SMOLTCP_IFACE_MAX_ADDR_COUNT=3 ./target/release/examples/perf_client --tap tap1 -c $ALGO -s 192.168.69.1 -p 8000
