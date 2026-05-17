# DeepClean Test Suite Guide

Complete testing framework with unit, integration, load, and performance tests.

## 📋 Quick Start

### 1. Install Dependencies
```bash
cd artifacts/api-server
pnpm install
pnpm add -D vitest @vitest/ui @vitest/coverage-v8 supertest
```

### 2. Copy Test Files
```bash
# Copy test files to project
cp onchain.test.ts artifacts/api-server/src/lib/
cp integration.test.ts artifacts/api-server/src/
cp vitest.config.ts artifacts/api-server/

# Make scripts executable
chmod +x run-tests.sh load-test.sh
```

### 3. Start the API Server
```bash
./run.sh
# or in another terminal
cd artifacts/api-server && pnpm dev
```

### 4. Run Tests
```bash
# Quick tests (unit only)
./run-tests.sh quick

# Full test suite
./run-tests.sh all

# Specific test type
./run-tests.sh unit
./run-tests.sh integration
./run-tests.sh load
./run-tests.sh ci  # For CI/CD with coverage
```

---

## 🧪 Test Suites Overview

### Unit Tests (`onchain.test.ts`)
**What it tests:** Core functionality in isolation
- Private key parsing (suiprivkey1, base64, hex formats)
- Threat verdict scoring
- Database operations
- Address validation
- Error handling

**Run:**
```bash
pnpm run test:unit
```

**Expected:** ~50 test cases, < 5 seconds

---

### Integration Tests (`integration.test.ts`)
**What it tests:** Full API endpoints and workflows
- POST `/api/populate-wallet` - Threat population
- POST `/api/threats/analyze` - Threat analysis
- GET `/api/threats` - List threats with filtering
- Error handling & edge cases
- Concurrent request handling
- Response validation

**Prerequisites:** Server running on `http://localhost:8080`

**Run:**
```bash
./run-tests.sh integration
```

**Expected:** ~30 test cases, 30-60 seconds

---

### Load Tests (`load-test.sh`)
**What it tests:** System behavior under stress
1. **Baseline** - Single request
2. **Sequential** - 10 requests one after another
3. **Concurrent** - 5 parallel requests
4. **High Load** - 20 parallel requests
5. **Endpoint Load** - Analyze endpoint under stress
6. **List Performance** - Pagination performance
7. **Sustained Load** - 30 seconds continuous

**Prerequisites:** Server running on `http://localhost:8080`

**Run:**
```bash
bash ./load-test.sh
```

**Expected:** ~2 minutes, detailed performance metrics

---

### Coverage Analysis
**What it measures:** Code coverage percentage

**Run:**
```bash
pnpm run test:coverage
```

**Target:** 80%+ coverage

---

## 📊 Test Commands

### Package.json Scripts
```bash
# Run all tests
npm run test:all
npm run test:ci

# Run specific tests
npm run test:unit
npm run test:integration
npm run test:load
npm run test:watch      # Watch mode for development
npm run test:ui         # Vitest UI dashboard
npm run test:coverage   # With coverage report
npm run test:coverage:html  # Open HTML coverage report
```

### Master Test Runner
```bash
# Smart test runner with orchestration
./run-tests.sh quick         # Fast (unit only)
./run-tests.sh unit          # Unit tests
./run-tests.sh integration   # Integration tests
./run-tests.sh load          # Load tests
./run-tests.sh all           # All tests
./run-tests.sh ci            # CI mode (coverage + unit + integration)
./run-tests.sh help          # Show help
```

### Load Testing with Artillery
```bash
# Install Artillery
pnpm add -D artillery

# Run load test with scenarios
pnpm run test:load:artillery

# Or manually
artillery run artillery.yml
```

---

## 🎯 Recommended Testing Workflow

### Development (Every commit)
```bash
./run-tests.sh quick   # Fast feedback
```

### Before Push (Every PR)
```bash
./run-tests.sh all     # Comprehensive test
```

### Pre-Production (Before deploy)
```bash
./run-tests.sh ci      # Full coverage + integration
pnpm run test:load     # Stress test
```

### CI/CD Pipeline
```bash
# In your CI config
./run-tests.sh ci      # All tests with coverage
```

---

## 📈 Performance Targets

| Test | Target | Current |
|------|--------|---------|
| Unit Tests | < 5s | ✓ |
| Integration Tests | < 60s | ⏳ |
| Load Test (20 concurrent) | 80%+ success | ⏳ |
| Coverage | 80%+ | ⏳ |
| Response time P99 | < 60s | ⏳ |

---

## 🔍 Test Details

### Unit Test Coverage

```typescript
// Private key parsing
✓ suiprivkey1 format
✓ base64 format
✓ hex format (0x...)
✓ JSON export format
✓ Reject invalid formats
✓ Handle key length validation

// Transaction building
✓ Valid PTB construction
✓ Verdict type validation
✓ Risk score bounds (0-100)
✓ Reason code validation (1-5)
✓ Address normalization

// Error handling
✓ Non-fatal on-chain errors
✓ Gas coin errors
✓ Network timeouts
✓ Rate limiting (429)
```

### Integration Test Coverage

```typescript
// Populate-Wallet Endpoint
✓ Happy path
✓ Concurrent requests
✓ Missing address
✓ Invalid address format
✓ Timeout handling
✓ Response structure validation
✓ onChainDigest field present

// Threats Analyze
✓ Valid analysis
✓ Required field validation
✓ Optional field handling
✓ Special character sanitization
✓ XSS prevention

// Threats List
✓ Filtering by verdict
✓ Filtering by status
✓ Pagination
✓ Sort order
```

### Load Test Scenarios

```bash
Test 1: Baseline
└─ Single request response time

Test 2: Sequential
└─ 10 sequential requests
└─ Target: all succeed

Test 3: Concurrent (5 parallel)
└─ All 5 requests
└─ Target: 100% success

Test 4: High Load (20 parallel)
└─ All 20 requests
└─ Target: 80%+ success

Test 5: Analyze Endpoint (10 parallel)
└─ Threat analysis under load
└─ Target: all complete

Test 6: List Endpoint
└─ Response time < 1s
└─ Target: performance

Test 7: Sustained Load (30 seconds)
└─ Continuous requests
└─ Target: stable memory/connections
└─ Success rate: 95%+
```

---

## 🚨 Failure Debugging

### Unit Tests Fail
```bash
# Run with verbose output
pnpm run test:unit -- --reporter=verbose

# Run specific test
pnpm run test:unit -- --grep "private key"

# Debug mode
pnpm run test:unit -- --inspect-brk
```

### Integration Tests Fail
1. **Check server is running:**
   ```bash
   curl http://localhost:8080/api/health
   ```

2. **Check environment:**
   ```bash
   cat .env | grep -E "REAL_ONCHAIN|QUARANTINE"
   ```

3. **Check logs:**
   ```bash
   # From server terminal
   # Look for: REAL_ONCHAIN: true, onChainEnabled: true
   ```

### Load Tests Fail
```bash
# Run with details
bash ./load-test.sh 2>&1 | grep -E "PASS|FAIL"

# Check server resources
top -p $(pgrep -f "pnpm dev")
```

---

## 📋 CI/CD Integration

### GitHub Actions Example
```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: deepclean
          POSTGRES_DB: deepclean
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v3
      - uses: pnpm/action-setup@v2
      - uses: actions/setup-node@v3
        with:
          node-version: 18
          cache: 'pnpm'
      
      - name: Install deps
        run: pnpm install
      
      - name: Run tests
        run: ./run-tests.sh ci
        env:
          DATABASE_URL: postgres://postgres:deepclean@localhost:5432/deepclean
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
          QUARANTINE_PACKAGE_ID: ${{ secrets.QUARANTINE_PACKAGE_ID }}
```

---

## 📚 Test Results

Test results are logged to `./test-results/` directory:

```
test-results/
├── unit-tests-20240516_143022.log
├── integration-tests-20240516_143522.log
├── load-tests-20240516_144522.log
├── coverage-20240516_145022.log
└── test-summary.txt
```

View results:
```bash
tail -f test-results/*.log
cat test-results/test-summary.txt
```

---

## 🎓 Best Practices

1. **Run quick tests frequently** during development
2. **Run full tests before push** to ensure no regressions
3. **Monitor coverage** to catch untested code
4. **Use load tests before deployment** to ensure scalability
5. **Keep tests maintainable** - update when code changes
6. **Isolate external dependencies** - mock Gemini/Walrus in unit tests
7. **Test error paths** - most bugs hide in error handling

---

## 🆘 Troubleshooting

### "Cannot find module 'vitest'"
```bash
pnpm install --save-dev vitest
```

### "Server not running"
```bash
./run.sh  # Start server in background
sleep 5   # Wait for server to start
./run-tests.sh integration
```

### "Port 8080 already in use"
```bash
lsof -ti:8080 | xargs kill -9
./run.sh
```

### "Database connection failed"
```bash
# Check DATABASE_URL
cat .env | grep DATABASE_URL

# Test connection
psql $DATABASE_URL -c "SELECT 1"
```

### "Tests timeout"
```bash
# Increase timeout
export TEST_TIMEOUT=60000  # 60 seconds
./run-tests.sh integration
```

---

## 📞 Support

For issues or questions:
1. Check logs in `test-results/`
2. Run with verbose output: `--reporter=verbose`
3. Check server logs for errors
4. Verify environment variables

---

**Test coverage = Code confidence** ✅
