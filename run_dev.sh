#!/usr/bin/env bash
# Sentinel — Development runner
# Usage: ./run_dev.sh

set -euo pipefail
cd "$(dirname "$0")"

# Compile translation files (.po → .mo) into build/locale/
echo "🌐 Compiling translations..."
for lang in en zh_CN zh_TW de; do
    mkdir -p "build/locale/${lang}/LC_MESSAGES"
    if [ -f "po/${lang}.po" ]; then
        msgfmt "po/${lang}.po" -o "build/locale/${lang}/LC_MESSAGES/sentinel.mo"
    fi
done

echo "🔑 Starting Sentinel..."
.venv/bin/python3 src/main.py "$@"
