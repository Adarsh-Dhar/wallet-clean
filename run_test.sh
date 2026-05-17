#!/usr/bin/env bash
set -euo pipefail

# run_test.sh — Repo-level test runner that delegates to tests/run-tests.sh
# Usage: ./run_test.sh [quick|unit|integration|load|all|ci|help]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/tests/run-tests.sh"
ARTIFACTS_DIR="$SCRIPT_DIR/artifacts/api-server"

if [ ! -f "$RUNNER" ]; then
  echo "Error: test runner not found at $RUNNER"
  exit 1
fi

MODE="${1:-quick}"

check_deps() {
  local missing=0
  command -v node >/dev/null 2>&1 || { echo "Node.js not found"; missing=1; }
  command -v pnpm >/dev/null 2>&1 || command -v npm >/dev/null 2>&1 || { echo "pnpm/npm not found"; missing=1; }
  command -v curl >/dev/null 2>&1 || { echo "curl not found"; missing=1; }
  if [ $missing -eq 1 ]; then
    echo "Install missing dependencies and try again." >&2
    exit 1
  fi
}

ensure_artifacts_deps() {
  if [ -d "$ARTIFACTS_DIR" ]; then
    echo "Ensuring dependencies in $ARTIFACTS_DIR..."
    pushd "$ARTIFACTS_DIR" >/dev/null
    if [ ! -d "node_modules" ]; then
      if command -v pnpm >/dev/null 2>&1; then
        pnpm install
      else
        npm install
      fi
    else
      echo "node_modules already present, skipping install. Run 'pnpm install' to refresh." 
    fi
    popd >/dev/null
  else
    echo "Warning: $ARTIFACTS_DIR not found — integration tests may fail" >&2
  fi
}

start_server_if_needed() {
  # For integration/load/all/ci ensure server is running (attempt to start via ./run.sh)
  case "$MODE" in
    integration|load|all|ci)
      if curl -sSf http://localhost:8080/api/health >/dev/null 2>&1; then
        echo "Server already running on http://localhost:8080"
        return 0
      fi

      if [ -x "$SCRIPT_DIR/run.sh" ]; then
        echo "Starting server with ./run.sh in background..."
        (cd "$SCRIPT_DIR" && nohup ./run.sh >/tmp/deepclean-server.log 2>&1 &) 
        # wait for health
        for i in {1..20}; do
          if curl -sSf http://localhost:8080/api/health >/dev/null 2>&1; then
            echo "Server is up"
            return 0
          fi
          sleep 1
        done
        echo "Timed out waiting for server to start; check /tmp/deepclean-server.log" >&2
        return 1
      else
        echo "Server not running and ./run.sh is not executable or missing. Start server manually." >&2
        return 1
      fi
      ;;
    *)
      return 0
      ;;
  esac
}

print_help() {
  cat <<EOF
Usage: ./run_test.sh [mode]

Modes:
  quick        Run fast unit-only tests (default)
  unit         Run unit tests only
  integration  Run integration tests (requires server)
  load         Run load tests (requires server)
  all          Run all tests
  ci           CI mode (coverage + integration)
  help         Show this message

This script delegates to tests/run-tests.sh. It ensures the API package deps are installed
and attempts to start the server for integration/load modes.
EOF
}

if [ "$MODE" = "help" ]; then
  print_help
  exit 0
fi

echo "[run_test] mode=$MODE"
check_deps
ensure_artifacts_deps
start_server_if_needed || true

echo "Invoking test runner: $RUNNER $MODE"
bash "$RUNNER" "$MODE"
