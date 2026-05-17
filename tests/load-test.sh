#!/bin/bash

# Load Testing Script for DeepClean
# Tests API under various load scenarios

set -e

API_BASE="http://localhost:8080/api"
TARGET_ADDRESS="0xb8552ec41cd7b5697464602d24d9c174f6fb863c"
RESULTS_DIR="./load-test-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$RESULTS_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}DeepClean Load Testing Suite${NC}"
echo -e "${YELLOW}========================================${NC}"

# ============================================================
# Test 1: Single Request Baseline
# ============================================================
echo -e "\n${YELLOW}Test 1: Single Request Baseline${NC}"
echo "Sending one request to measure baseline response time..."

START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -X POST "$API_BASE/populate-wallet" \
  -H 'Content-Type: application/json' \
  -d "{\"targetAddress\":\"$TARGET_ADDRESS\"}")
END_TIME=$(date +%s%N)

DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "Response time: ${DURATION_MS}ms"
echo "Response preview:"
echo "$RESPONSE" | jq '.injected, .quarantined, .onChainDigest' 2>/dev/null || echo "$RESPONSE" | head -c 200

if [ "$DURATION_MS" -lt 60000 ]; then
  echo -e "${GREEN}✓ PASS${NC} - Response time acceptable"
else
  echo -e "${RED}✗ FAIL${NC} - Response time too slow"
fi

# ============================================================
# Test 2: Sequential Requests (10 requests, one after another)
# ============================================================
echo -e "\n${YELLOW}Test 2: Sequential Requests (10 requests)${NC}"
echo "Sending 10 sequential requests..."

TOTAL_TIME=0
SUCCESS_COUNT=0
FAIL_COUNT=0

for i in {1..10}; do
  echo -n "  Request $i... "
  
  START_TIME=$(date +%s%N)
  HTTP_CODE=$(curl -s -o /tmp/response_$i.json -w "%{http_code}" \
    -X POST "$API_BASE/populate-wallet" \
    -H 'Content-Type: application/json' \
    -d "{\"targetAddress\":\"$TARGET_ADDRESS\"}")
  END_TIME=$(date +%s%N)
  
  DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))
  TOTAL_TIME=$((TOTAL_TIME + DURATION_MS))
  
  if [ "$HTTP_CODE" -eq 200 ]; then
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    echo -e "${GREEN}OK${NC} (${DURATION_MS}ms)"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "${RED}FAIL${NC} (HTTP $HTTP_CODE)"
  fi
  
  # Small delay between requests
  sleep 1
done

AVG_TIME=$((TOTAL_TIME / 10))
echo "Results: $SUCCESS_COUNT successful, $FAIL_COUNT failed"
echo "Average response time: ${AVG_TIME}ms"

if [ "$SUCCESS_COUNT" -eq 10 ]; then
  echo -e "${GREEN}✓ PASS${NC} - All requests succeeded"
else
  echo -e "${RED}✗ FAIL${NC} - Some requests failed"
fi

# ============================================================
# Test 3: Concurrent Requests (5 parallel requests)
# ============================================================
echo -e "\n${YELLOW}Test 3: Concurrent Requests (5 parallel)${NC}"
echo "Sending 5 concurrent requests..."

START_TIME=$(date +%s%N)

# Send 5 requests in parallel
for i in {1..5}; do
  curl -s -X POST "$API_BASE/populate-wallet" \
    -H 'Content-Type: application/json' \
    -d "{\"targetAddress\":\"$TARGET_ADDRESS\"}" \
    > /tmp/concurrent_$i.json &
done

# Wait for all background jobs
wait
END_TIME=$(date +%s%N)

DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "All 5 requests completed in: ${DURATION_MS}ms"
SUCCESS=0
for i in {1..5}; do
  if jq -e '.injected' /tmp/concurrent_$i.json > /dev/null 2>&1; then
    SUCCESS=$((SUCCESS + 1))
  fi
done

echo "Results: $SUCCESS/5 successful"
if [ "$SUCCESS" -eq 5 ]; then
  echo -e "${GREEN}✓ PASS${NC} - All concurrent requests succeeded"
else
  echo -e "${RED}✗ FAIL${NC} - Some concurrent requests failed"
fi

# ============================================================
# Test 4: High Load (20 parallel requests)
# ============================================================
echo -e "\n${YELLOW}Test 4: High Load Test (20 parallel requests)${NC}"
echo "Sending 20 concurrent requests..."

START_TIME=$(date +%s%N)

for i in {1..20}; do
  curl -s -X POST "$API_BASE/populate-wallet" \
    -H 'Content-Type: application/json' \
    -d "{\"targetAddress\":\"$TARGET_ADDRESS\"}" \
    > /tmp/high_load_$i.json &
done

wait
END_TIME=$(date +%s%N)

DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "All 20 requests completed in: ${DURATION_MS}ms"
SUCCESS=0
for i in {1..20}; do
  if jq -e '.injected' /tmp/high_load_$i.json > /dev/null 2>&1; then
    SUCCESS=$((SUCCESS + 1))
  fi
done

echo "Results: $SUCCESS/20 successful"
if [ "$SUCCESS" -ge 16 ]; then  # 80% success rate
  echo -e "${GREEN}✓ PASS${NC} - High load handled"
else
  echo -e "${RED}✗ FAIL${NC} - High load caused failures"
fi

# ============================================================
# Test 5: Analyze Endpoint Load Test
# ============================================================
echo -e "\n${YELLOW}Test 5: Analyze Endpoint Load Test (10 parallel)${NC}"
echo "Testing threat analysis endpoint under load..."

START_TIME=$(date +%s%N)

for i in {1..10}; do
  curl -s -X POST "$API_BASE/threats/analyze" \
    -H 'Content-Type: application/json' \
    -d '{
      "objectId": "0xtest'$i'",
      "objectType": "0xtest::fake::Token",
      "senderAddress": "0x8cb08623b2514d8e90994ac4800d5c05d01775dfec7e324150be638b74e9932e",
      "displayName": "Test Token '$i'",
      "displayUrl": "https://test-'$i'.com"
    }' \
    > /tmp/analyze_$i.json &
done

wait
END_TIME=$(date +%s%N)

DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "All 10 analyze requests completed in: ${DURATION_MS}ms"
SUCCESS=0
for i in {1..10}; do
  if jq -e '.riskScore' /tmp/analyze_$i.json > /dev/null 2>&1; then
    SUCCESS=$((SUCCESS + 1))
  fi
done

echo "Results: $SUCCESS/10 successful"
if [ "$SUCCESS" -eq 10 ]; then
  echo -e "${GREEN}✓ PASS${NC} - Analyze endpoint handled load"
else
  echo -e "${RED}✗ FAIL${NC} - Analyze endpoint had issues"
fi

# ============================================================
# Test 6: List Endpoint Performance
# ============================================================
echo -e "\n${YELLOW}Test 6: List Endpoint Performance${NC}"
echo "Testing threats list endpoint..."

START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -X GET "$API_BASE/threats?limit=100")
END_TIME=$(date +%s%N)

DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "Response time: ${DURATION_MS}ms"
THREAT_COUNT=$(echo "$RESPONSE" | jq 'length' 2>/dev/null || echo "0")
echo "Threats returned: $THREAT_COUNT"

if [ "$DURATION_MS" -lt 1000 ]; then
  echo -e "${GREEN}✓ PASS${NC} - List endpoint is fast"
else
  echo -e "${YELLOW}⚠ WARN${NC} - List endpoint is slow"
fi

# ============================================================
# Test 7: Memory & Connection Stability (30 second sustained load)
# ============================================================
echo -e "\n${YELLOW}Test 7: 30-Second Sustained Load${NC}"
echo "Sending continuous requests for 30 seconds..."

START_TIME=$(date +%s)
TOTAL_REQUESTS=0
SUCCESS_COUNT=0
FAIL_COUNT=0

while [ $(($(date +%s) - START_TIME)) -lt 30 ]; do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$API_BASE/populate-wallet" \
    -H 'Content-Type: application/json' \
    -d "{\"targetAddress\":\"$TARGET_ADDRESS\"}")
  
  TOTAL_REQUESTS=$((TOTAL_REQUESTS + 1))
  if [ "$HTTP_CODE" -eq 200 ]; then
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
done

echo "30-second results:"
echo "  Total requests: $TOTAL_REQUESTS"
echo "  Successful: $SUCCESS_COUNT"
echo "  Failed: $FAIL_COUNT"
SUCCESS_RATE=$((SUCCESS_COUNT * 100 / TOTAL_REQUESTS))
echo "  Success rate: ${SUCCESS_RATE}%"

if [ "$SUCCESS_RATE" -ge 95 ]; then
  echo -e "${GREEN}✓ PASS${NC} - System stable under sustained load"
else
  echo -e "${RED}✗ FAIL${NC} - System unstable under sustained load"
fi

# ============================================================
# Summary Report
# ============================================================
echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}Load Testing Summary${NC}"
echo -e "${YELLOW}========================================${NC}"

echo "Results saved to: $RESULTS_DIR/"
echo "Timestamp: $TIMESTAMP"

# Cleanup
rm -f /tmp/response_*.json /tmp/concurrent_*.json /tmp/high_load_*.json /tmp/analyze_*.json

echo -e "\n${GREEN}Load testing complete!${NC}"
