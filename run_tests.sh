#!/usr/bin/env bash
# Run all tests with coverage
set -euo pipefail
cd "$(dirname "$0")"

VENV=".venv/bin/python3"
if [ -f "$VENV" ]; then
    PYTHON="$VENV"
else
    PYTHON="python3"
fi

echo "🧪 Running Sentinel tests..."
$PYTHON -m pytest tests/ -v --tb=short --cov=src --cov-report=term-missing "$@"
