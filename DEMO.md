# DeepClean Demo — Clean & Verify Workflow

This guide walks you through **cleaning the demo wallet** and **verifying it's actually clean**.

## Overview

After injecting 5 spam objects into the wallet with `inject_junk.sh`, you now need to:
1. **Clean** the wallet (removes on-chain objects + marks DB records as burned)
2. **Verify** the clean worked (checks on-chain AND in database)

## Quick Start

### Prerequisites

- ✅ Spam objects already injected into `0xdf91e28e5ce7bddfa06f7f924db73003501d1d65192c489bb84056e1a7d628a5`
- ✅ DeepClean API running at `http://localhost:8080`
- ✅ Sui CLI installed and on testnet

### One-time Setup

```bash
chmod +x setup-demo.sh
./setup-demo.sh
```

This will:
- Make scripts executable
- Install `@mysten/sui` dependency
- Verify your environment

### Run the Full Demo

#### Option 1: With Private Key (Recommended)

Get your private key:
```bash
sui keytool export --key-identity 0x8cb08623b2514d8e90994ac4800d5c05d01775dfec7e324150be638b74e9932e
```

Then run:
```bash
./demo.sh --key suiprivkey1abc123...
```

#### Option 2: Test Mode (requires `NODE_ENV=test` on API server)

```bash
./demo.sh --skip-auth
```

#### Option 3: Manual Steps

**Step 1: Clean the wallet**
```bash
node clean-wallet.mjs \
  --address 0xdf91e28e5ce7bddfa06f7f924db73003501d1d65192c489bb84056e1a7d628a5 \
  --key suiprivkey1abc123... \
  --api http://localhost:8080
```

**Step 2: Verify it's clean**
```bash
node test-clean.mjs \
  --address 0xdf91e28e5ce7bddfa06f7f924db73003501d1d65192c489bb84056e1a7d628a5 \
  --api http://localhost:8080 \
  --network testnet
```

## What Each Script Does

### `clean-wallet.mjs`

Performs the actual cleanup:
1. Authenticates with the API (challenge → sign → JWT)
2. Fetches all quarantined threats for the wallet
3. Builds a Sui transaction (PTB) to transfer objects to `0x0`
4. Signs with your private key and executes on-chain
5. POSTs the burn transaction digest to the API
6. Database marks all threats as `status=burned`

**Output**: Transaction digest on Suiscan, shows all burned objects

### `test-clean.mjs`

Verifies the cleanup was successful:

**Suite A — On-chain (RPC checks)**
- ✓ Confirms all 5 spam object types are gone from wallet
- ✓ Confirms zero package objects remain
- ✓ Checks Suiscan

**Suite B — Database (API checks)**
- ✓ No quarantined threats remain
- ✓ All threats marked as `status=burned`
- ✓ Each burned threat has a valid `burnTxDigest`
- ✓ Per-type verification (each spam type fully cleaned)

**Suite C — Edge Cases**
- ✓ Running clean again with empty threats returns 0
- ✓ GET `/threats?status=quarantined` returns empty

**Output**: Pass/fail count, burn TX links for manual verification

## Troubleshooting

### `clean-wallet.mjs` fails with "No quarantined threats found"

This likely means:
- The threats haven't been **seeded** yet (not detected by the scanner)
- You need to open DeepClean in the browser and click "Scan" or "Seed spam" first

**Fix**: 
1. Open `http://localhost:3000` (or your DeepClean frontend URL)
2. Connect the demo wallet `0xdf91e28e5ce7bddfa06f7f924db73003501d1d65192c489bb84056e1a7d628a5`
3. Click "Scan Wallet" or "Populate" to seed threats
4. Then run `clean-wallet.mjs`

### `clean-wallet.mjs` fails with "API unreachable"

Make sure the API server is running:
```bash
# From the api-server directory
pnpm run dev
# or
npm run dev
```

### `test-clean.mjs` shows failures

**If on-chain checks fail**: The burn transaction didn't complete successfully. Check the burn TX digest on Suiscan.

**If database checks fail**: The API didn't record the burn. Check:
- API logs for errors
- Database connection
- The `burnTxDigest` is real and was confirmed on-chain

## Files

| File | Purpose |
|------|---------|
| `demo.sh` | Master workflow (clean + verify) |
| `setup-demo.sh` | One-time environment setup |
| `clean-wallet.mjs` | Executes the on-chain burn transaction |
| `test-clean.mjs` | Verifies wallet is clean (comprehensive test suite) |
| `inject_junk.sh` | (Already run) Seeds spam objects |

## Full Workflow (Day 1)

```
┌─────────────────────────────────────────────┐
│ 1. Inject spam objects                      │
│    ./inject_junk.sh 0xdf91...              │
│    → 5 real on-chain objects created       │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ 2. Demo in browser                          │
│    • Wallet shows 5 threats                 │
│    • Click "Clean"                          │
│    • Sign transaction                       │
│    • Objects disappear                      │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ 3. Verify (headless)                        │
│    ./demo.sh --key ...                      │
│    → Runs clean + verify in one command    │
└─────────────────────────────────────────────┘
```

## API Endpoints Used

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/health` | Health check |
| GET | `/api/auth/challenge?address=...` | Get challenge message |
| POST | `/api/auth/login` | Exchange signature for JWT |
| GET | `/api/threats?status=quarantined&walletAddress=...` | Fetch threats to clean |
| POST | `/api/clean-wallet` | Mark threats as burned |

## Security Notes

- Private key is **never** sent to the API
- Signature is created locally with your Sui keypair
- The API only receives the **signature** + **address** (standard auth pattern)
- Burn transactions are **irreversible** on-chain (objects sent to `0x0`)

## Exit Codes

- `0` — Everything passed ✓
- `1` — One or more checks failed ✗

## Questions?

Check the demo output or run with `-vvv` for verbose logging:
```bash
node clean-wallet.mjs --address ... --key ... --api ... 2>&1 | tee clean.log
node test-clean.mjs --address ... --api ... 2>&1 | tee verify.log
```
