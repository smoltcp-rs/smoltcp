#!/usr/bin/bash

# Usage: ./scripts/perf_server_run.sh [bbr|cubic|reno|none]
# Default is bbr

ALGO=${1:-bbr}

SMOLTCP_IFACE_MAX_ADDR_COUNT=3 ./target/release/examples/perf_server --tap tap0 -c $ALGO
