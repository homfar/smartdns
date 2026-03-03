#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-127.0.0.1}"
PORT="${2:-53}"
QPS="${QPS:-2000}"
DURATION="${DURATION:-30}"

cat > /tmp/dnsperf-input.txt <<EOF
example.com A
www.example.com A
example.com MX
EOF

echo "Running dnsperf against ${TARGET}:${PORT} qps=${QPS} duration=${DURATION}s"
dnsperf -s "${TARGET}" -p "${PORT}" -Q "${QPS}" -d /tmp/dnsperf-input.txt -l "${DURATION}"
