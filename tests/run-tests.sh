#!/bin/bash

################################################################################
# DeepClean Test Runner
# 
# Orchestrates all test suites (unit, integration, load, etc.)
# Usage: ./run-tests.sh [unit|integration|load|all|quick|ci]
# 
# Examples:
#   ./run-tests.sh unit          # Run unit tests only
#   ./run-tests.sh integration   # Run integration tests
#   ./run-tests.sh load          # Run load tests
#   ./run-tests.sh all           # Run all tests
#   ./run-tests.sh quick         # Fast subset for development
#   ./run-tests.sh ci            # CI/CD mode with coverage
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="."
RESULTS_DIR="./test-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TEST_MODE="${1:-quick}"

# Check dependencies
check_dependencies() {
  local missing=0
  
  echo -e "${BLUE}Checking dependencies...${NC}"
  
  if ! command -v node &> /dev/null; then
    echo -e "${RED}✗ Node.js not found${NC}"
    missing=1
  else
    echo -e "${GREEN}✓ Node.js${NC} $(node --version)"
  fi
  
  if ! command -v pnpm &> /dev/null && ! command -v npm &> /dev/null; then
    echo -e "${RED}✗ npm/pnpm not found${NC}"
    missing=1
  fi
  
  if ! command -v curl &> /dev/null; then
    echo -e "${RED}✗ curl not found${NC}"
    missing=1
  fi
  
  if [ $missing -eq 1 ]; then
    echo -e "${RED}Missing dependencies. Please install Node.js and npm/pnpm.${NC}"
    exit 1
  fi
}

# Setup
setup() {
  echo -e "${BLUE}Setting up test environment...${NC}"
  mkdir -p "$RESULTS_DIR"
  
  # Check if .env exists
  if [ ! -f ".env" ]; then
    echo -e "${YELLOW}⚠ .env file not found${NC}"
    echo "Please create .env with required variables"
  fi
}

# Check if server is running
check_server() {
  echo -e "${BLUE}Checking if API server is running...${NC}"
  
  if curl -s http://localhost:8080/api/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Server is running on port 8080${NC}"
    return 0
  else
    echo -e "${YELLOW}⚠ Server not running on port 8080${NC}"
    echo "Start the server with: ./run.sh"
    return 1
  fi
}

# Run unit tests
run_unit_tests() {
  echo -e "\n${BLUE}========================================${NC}"
  echo -e "${BLUE}Running Unit Tests${NC}"
  echo -e "${BLUE}========================================${NC}"
  
  if command -v pnpm &> /dev/null; then
    pnpm test:unit 2>&1 | tee "$RESULTS_DIR/unit-tests-$TIMESTAMP.log"
  else
    npm run test:unit 2>&1 | tee "$RESULTS_DIR/unit-tests-$TIMESTAMP.log"
  fi
  
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Unit tests passed${NC}"
    return 0
  else
    echo -e "${RED}✗ Unit tests failed${NC}"
    return 1
  fi
}

# Run integration tests
run_integration_tests() {
  echo -e "\n${BLUE}========================================${NC}"
  echo -e "${BLUE}Running Integration Tests${NC}"
  echo -e "${BLUE}========================================${NC}"
  
  if ! check_server; then
    echo -e "${RED}Cannot run integration tests without server${NC}"
    return 1
  fi
  
  if command -v pnpm &> /dev/null; then
    pnpm test:integration 2>&1 | tee "$RESULTS_DIR/integration-tests-$TIMESTAMP.log"
  else
    npm run test:integration 2>&1 | tee "$RESULTS_DIR/integration-tests-$TIMESTAMP.log"
  fi
  
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Integration tests passed${NC}"
    return 0
  else
    echo -e "${RED}✗ Integration tests failed${NC}"
    return 1
  fi
}

# Run load tests
run_load_tests() {
  echo -e "\n${BLUE}========================================${NC}"
  echo -e "${BLUE}Running Load Tests${NC}"
  echo -e "${BLUE}========================================${NC}"
  
  if ! check_server; then
    echo -e "${RED}Cannot run load tests without server${NC}"
    return 1
  fi
  
  bash ./load-test.sh 2>&1 | tee "$RESULTS_DIR/load-tests-$TIMESTAMP.log"
  
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Load tests completed${NC}"
    return 0
  else
    echo -e "${RED}✗ Load tests had issues${NC}"
    return 1
  fi
}

# Run coverage tests
run_coverage() {
  echo -e "\n${BLUE}========================================${NC}"
  echo -e "${BLUE}Running Coverage Analysis${NC}"
  echo -e "${BLUE}========================================${NC}"
  
  if command -v pnpm &> /dev/null; then
    pnpm test:coverage 2>&1 | tee "$RESULTS_DIR/coverage-$TIMESTAMP.log"
  else
    npm run test:coverage 2>&1 | tee "$RESULTS_DIR/coverage-$TIMESTAMP.log"
  fi
  
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Coverage analysis completed${NC}"
    return 0
  else
    echo -e "${RED}✗ Coverage analysis failed${NC}"
    return 1
  fi
}

# Quick test mode (for development)
run_quick_tests() {
  echo -e "\n${BLUE}========================================${NC}"
  echo -e "${BLUE}Quick Test Mode (Unit Tests Only)${NC}"
  echo -e "${BLUE}========================================${NC}"
  
  run_unit_tests
}

# CI mode (comprehensive)
run_ci_tests() {
  echo -e "\n${BLUE}========================================${NC}"
  echo -e "${BLUE}CI Mode (All Tests with Coverage)${NC}"
  echo -e "${BLUE}========================================${NC}"
  
  local failed=0
  
  run_unit_tests || failed=1
  run_coverage || failed=1
  
  if check_server; then
    run_integration_tests || failed=1
  fi
  
  return $failed
}

# Run all tests
run_all_tests() {
  echo -e "\n${BLUE}========================================${NC}"
  echo -e "${BLUE}Running All Tests${NC}"
  echo -e "${BLUE}========================================${NC}"
  
  local failed=0
  
  run_unit_tests || failed=1
  run_coverage || failed=1
  
  if check_server; then
    run_integration_tests || failed=1
    run_load_tests || failed=1
  fi
  
  return $failed
}

# Print summary
print_summary() {
  echo -e "\n${BLUE}========================================${NC}"
  echo -e "${BLUE}Test Results Summary${NC}"
  echo -e "${BLUE}========================================${NC}"
  echo "Test mode: $TEST_MODE"
  echo "Timestamp: $TIMESTAMP"
  echo "Results directory: $RESULTS_DIR"
  echo ""
  
  # List all logs
  ls -lh "$RESULTS_DIR"/*.log 2>/dev/null || echo "No test logs found"
  
  echo -e "\n${GREEN}Test run completed!${NC}"
}

# Print help
print_help() {
  cat << EOF
DeepClean Test Runner

Usage: ./run-tests.sh [command]

Commands:
  unit         Run unit tests only
  integration  Run integration tests (requires server)
  load         Run load tests (requires server)
  all          Run all tests
  quick        Run quick tests (unit only) - default
  ci           Run CI mode (all tests + coverage)
  help         Show this help message

Examples:
  ./run-tests.sh quick        # Fast tests for development
  ./run-tests.sh integration  # API integration tests
  ./run-tests.sh ci           # Full CI pipeline

Environment Variables:
  SERVER_URL   API server URL (default: http://localhost:8080)
  TEST_TIMEOUT Test timeout in ms (default: 30000)

Notes:
  - Server must be running for integration/load tests
  - Start server with: ./run.sh
  - Coverage requires c8 or nyc
  - Load tests require curl

EOF
}

# Main
main() {
  echo -e "${BLUE}"
  echo "╔════════════════════════════════════════╗"
  echo "║  DeepClean Test Runner                 ║"
  echo "║  $(date '+%Y-%m-%d %H:%M:%S')          ║"
  echo "╚════════════════════════════════════════╝"
  echo -e "${NC}"
  
  check_dependencies
  setup
  
  case "$TEST_MODE" in
    unit)
      run_unit_tests
      ;;
    integration)
      run_integration_tests
      ;;
    load)
      run_load_tests
      ;;
    all)
      run_all_tests
      ;;
    quick)
      run_quick_tests
      ;;
    ci)
      run_ci_tests
      ;;
    help)
      print_help
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown test mode: $TEST_MODE${NC}"
      print_help
      exit 1
      ;;
  esac
  
  local exit_code=$?
  print_summary
  
  if [ $exit_code -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
  else
    echo -e "${RED}Some tests failed!${NC}"
  fi
  
  exit $exit_code
}

# Run main
main
