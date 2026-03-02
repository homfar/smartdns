#!/usr/bin/env bash
set -euo pipefail
dig @127.0.0.1 -p 53 example.com A +tcp
