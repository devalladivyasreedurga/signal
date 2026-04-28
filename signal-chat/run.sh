#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "=== UIC Signal Chat — starting services ==="

# Add Homebrew to PATH so redis-server / redis-cli are found
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

# Check Redis
if ! redis-cli ping &>/dev/null; then
  echo "Starting Redis..."
  redis-server --daemonize yes
  sleep 1
fi

# Python venv
if [ ! -d "$ROOT/.venv" ]; then
  echo "Creating Python venv..."
  python3 -m venv "$ROOT/.venv"
fi
source "$ROOT/.venv/bin/activate"
pip install -q -r "$ROOT/requirements.txt"

# Kill anything already on port 5001
lsof -ti:5001 | xargs kill -9 2>/dev/null || true
sleep 1

# Start Flask server
echo "Starting Flask server on :5001..."
cd "$ROOT"
python -m server.app &
SERVER_PID=$!
sleep 2

# Frontend
echo "Installing frontend deps..."
cd "$ROOT/frontend"
npm install --silent
echo "Starting Vite dev server on :3000..."
npm run dev &
VITE_PID=$!

echo ""
echo "=== Ready ==="
echo "  Backend:  http://localhost:5001"
echo "  Frontend: http://localhost:3000"
echo ""
echo "Press Ctrl-C to stop all services."

cleanup() {
  echo "Stopping..."
  kill $SERVER_PID $VITE_PID 2>/dev/null || true
}
trap cleanup INT TERM
wait
