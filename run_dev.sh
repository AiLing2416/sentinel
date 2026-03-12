#!/usr/bin/env bash
# Sentinel — Development runner
# Usage: ./run_dev.sh

set -euo pipefail
cd "$(dirname "$0")"

echo "🔑 Starting Sentinel..."
.venv/bin/python3 src/main.py "$@"
