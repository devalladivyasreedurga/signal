#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install -q -r requirements.txt

if ! redis-cli ping 2>/dev/null | grep -q PONG; then
  echo "Starting Redis..."
  redis-server --daemonize yes && sleep 1
fi

python3 tests/demo.py
