#!/usr/bin/env bash
set -euo pipefail

BACKEND_CMD=${BACKEND_CMD:-"pnpm --prefix artifacts/api-server run dev"}
FRONTEND_CMD=${FRONTEND_CMD:-"pnpm --prefix artifacts/deepclean run dev"}
BACKEND_PORT=${BACKEND_PORT:-8080}
FRONTEND_PORT=${FRONTEND_PORT:-3000}

pids=()

children() {
  local _p=$1
  ps -o pid= --ppid "${_p}" | awk '{$1=$1};1'
}

kill_tree() {
  local root=$1
  local -a to_kill
  to_kill=("${root}")
  for pid in "${to_kill[@]}"; do
    for c in $(children "$pid"); do
      to_kill+=("$c")
    done
  done
  for ((i=${#to_kill[@]}-1;i>=0;i--)); do
    kill -TERM "${to_kill[i]}" 2>/dev/null || true
  done
}

cleanup() {
  echo "Shutting down..."
  for pid in "${pids[@]:-}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill_tree "$pid"
    fi
  done
  wait
  exit 0
}

trap cleanup INT TERM

# Kill any existing processes on the ports we're about to use
echo "Cleaning up ports $BACKEND_PORT and $FRONTEND_PORT..."
lsof -nP -iTCP:$BACKEND_PORT -sTCP:LISTEN | grep -v COMMAND | awk '{print $2}' | xargs kill -9 2>/dev/null || true
lsof -nP -iTCP:$FRONTEND_PORT -sTCP:LISTEN | grep -v COMMAND | awk '{print $2}' | xargs kill -9 2>/dev/null || true
sleep 1

echo "Starting backend: $BACKEND_CMD (PORT=$BACKEND_PORT)"
( export PORT="$BACKEND_PORT"; exec $BACKEND_CMD ) &
backend_pid=$!
pids+=("$backend_pid")

sleep 0.5

echo "Starting frontend: $FRONTEND_CMD (PORT=$FRONTEND_PORT)"
( export PORT="$FRONTEND_PORT"; exec $FRONTEND_CMD ) &
frontend_pid=$!
pids+=("$frontend_pid")

echo "Started backend pid=$backend_pid frontend pid=$frontend_pid"
wait
echo "One process exited, shutting down"
cleanup
