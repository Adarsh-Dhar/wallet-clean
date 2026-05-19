# DeepClean: 100% On-Chain Threat Quarantine

## ⚡ Status: Production Ready (100% On-Chain)

This system analyzes real Sui wallet objects for threats and records quarantine actions **directly on-chain** using Move smart contracts. No synthetic test fixtures—everything is real blockchain data.

### Key Capabilities
- 🔍 **Real-time threat analysis** — AI analyzes actual wallet objects from Sui RPC
- 🔐 **On-chain quarantine records** — Immutable logs via Move smart contract
- 🔄 **Automatic cleanup** — Malicious objects sent to dead address (0x0) after recording
- 📊 **Full audit trail** — Track via transaction digests and event IDs

---

## Quick Start

### Deploy Move Contract
```bash
cd move
sui client publish --network testnet
# Extract QUARANTINE_PACKAGE_ID and QUARANTINE_ADMIN_CAP_ID from output
```

### Configure Environment
```bash
# Copy env vars from deployment output
export QUARANTINE_PACKAGE_ID=0x...
export QUARANTINE_ADMIN_CAP_ID=0x...
export AGENT_PRIVATE_KEY=suiprivkey1...
export SUI_NETWORK=testnet
export DATABASE_URL=postgres://...
```

### Apply Database Migration
```bash
cd lib/db
npx prisma migrate deploy
```

### Start API
```bash
cd artifacts/api-server
npm install && npm run dev
# API listens on port 8080
```

### Test Threat Analysis
```bash
curl -X POST http://localhost:8080/api/threats/populate-wallet \
  -H "Content-Type: application/json" \
  -d '{
    "targetAddress": "0x<wallet_address>"
  }'
```

---

## Documentation

| Document | Purpose |
|----------|---------|
| [ONCHAIN_MIGRATION_COMPLETE.md](./ONCHAIN_MIGRATION_COMPLETE.md) | Summary of migration from synthetics to production |
| [PRODUCTION_CHECKLIST.md](./PRODUCTION_CHECKLIST.md) | Pre-deployment validation checklist |
| [THREAT_FLOW_ANALYSIS.md](./THREAT_FLOW_ANALYSIS.md) | Detailed threat analysis methodology |
| [move/README.md](./move/README.md) | Move contract documentation |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Frontend / CLI                                          │
│ (clean-wallet.mjs, full-demo.mjs, deepclean UI)       │
└────────────────┬────────────────────────────────────────┘
                 │
                 ↓ POST /api/threats/populate-wallet
┌─────────────────────────────────────────────────────────┐
│ API Server (Node.js)                                    │
│ ├─ Fetch real wallet objects from Sui RPC              │
│ ├─ Analyze with Google AI (Gemini model)               │
│ ├─ Record metadata + risk scores in DB                 │
│ └─ Submit quarantine transactions to Sui network       │
└────────────────┬───────────┬────────────────────────────┘
                 │           │
        ┌────────┘           └────────┐
        ↓                             ↓
┌──────────────────┐      ┌──────────────────────┐
│ Sui RPC (Read)   │      │ Sui RPC (Write)      │
│ • getOwnedObjects│      │ • signAndExecute     │
│ • queryEvents    │      │ • move_call         │
└──────────────────┘      └──────────────────────┘
        ↑                             ↓
        │                    ┌────────────────────┐
        │                    │ Move Smart Contract│
        │                    │ quarantine_vault   │
        │                    │ • quarantine()     │
        │                    │ • send_to_dead()   │
        │                    │ • emit events      │
        │                    └────────────────────┘
        │                             ↓
        └──────────────────────────────┘
                Immutable on-chain
                threat records & logs
```

---

## Threat Lifecycle

### Analysis Phase
1. **Fetch**: Query Sui RPC for all objects in target wallet
2. **Enrich**: Get metadata (Display objects, module ABIs)
3. **Analyze**: Send to AI model with risk indicators
4. **Score**: AI returns risk_score (0-100) + verdict (SAFE/SUSPICIOUS/MALICIOUS)

### Recording Phase
5. **Quarantine**: Call `quarantine_vault::quarantine()` on Move contract
   - Creates immutable on-chain record with threat metadata
   - Emits `AssetQuarantined` event
   - Returns transaction digest

6. **Extract**: Query blockchain for event ID from transaction digest
7. **Destroy**: Call `quarantine_vault::send_to_dead()` to send object to 0x0
   - Removes object from user's wallet
   - Emits `AssetBurned` event
   - Returns burn transaction digest

### Tracking Phase
8. **Record**: Store threat in database with both tx digests
9. **Audit**: Full trail visible via transaction explorer (Sui Scan)

---

## File Structure

```
.
├── README.md (this file)
├── ONCHAIN_MIGRATION_COMPLETE.md ← migration details
├── PRODUCTION_CHECKLIST.md ← deployment validation
├── move/
│   ├── Move.toml
│   ├── sources/
│   │   ├── quarantine_vault.move (main contract)
│   │   ├── rug_token.move (test malicious token)
│   │   └── ... (other test contracts)
│   └── tests/
├── artifacts/
│   ├── api-server/
│   │   ├── src/
│   │   │   ├── routes/populate.ts (threat analysis endpoint)
│   │   │   ├── lib/
│   │   │   │   ├── onchain.ts (quarantine & destroy logic)
│   │   │   │   ├── gemini.ts (AI analysis)
│   │   │   │   └── walrus.ts (immutable blob storage)
│   │   │   └── ...
│   │   └── package.json
│   ├── deepclean/ (React UI)
│   └── mockup-sandbox/
├── lib/
│   ├── db/
│   │   ├── prisma/schema.prisma (data model)
│   │   └── migrations/
│   ├── api-spec/ (OpenAPI docs)
│   └── ...
├── scripts/
│   ├── populate-wallet.ts (test data)
│   ├── test-ai.ts (AI testing)
│   └── ...
└── tests/
    ├── integration.test.ts
    └── onchain.test.ts
```

---

## API Endpoints

### Analyze Wallet for Threats
```bash
POST /api/threats/populate-wallet

Request:
{
  "targetAddress": "0x..."  // Sui wallet address
}

Response:
{
  "threats": [
    {
      "objectId": "0x...",
      "objectType": "0x...",
      "verdict": "MALICIOUS",
      "riskScore": 95,
      "threatId": "uuid",
      "quarantineTxDigest": "0x...",  // On-chain record
      "burnTxDigest": "0x..."         // Object destroyed
    },
    ...
  ]
}
```

---

## Environment Variables

```bash
# Database
DATABASE_URL=postgres://user:pass@localhost/deepclean

# API
PORT=8080
GITHUB_MODELS_TOKEN=ghu_...  # GitHub Models API token

# On-Chain Configuration (REQUIRED for production)
QUARANTINE_PACKAGE_ID=0x...         # Your Move contract
QUARANTINE_ADMIN_CAP_ID=0x...       # Admin capability object
AGENT_PRIVATE_KEY=suiprivkey1...    # Agent keypair for signing
SUI_NETWORK=testnet|mainnet|devnet
DEAD_ADDRESS=0x0000000000000000000000000000000000000000000000000000000000000000
```

---

## Development

### Run Tests
```bash
npm run test              # Unit tests
npm run test:integration  # With testnet contracts
npm run test:e2e          # Full threat analysis flow
```

### Build for Production
```bash
npm run build
npm run start
```

### Debug
```bash
# Verbose logging
DEBUG=* npm run dev

# Prisma studio
cd lib/db && npx prisma studio
```

---

## Deployment

**For production deployment:**

1. ✅ Follow [PRODUCTION_CHECKLIST.md](./PRODUCTION_CHECKLIST.md)
2. ✅ Review [ONCHAIN_MIGRATION_COMPLETE.md](./ONCHAIN_MIGRATION_COMPLETE.md)
3. ✅ Deploy Move contract to mainnet/testnet
4. ✅ Configure all environment variables
5. ✅ Apply database migrations
6. ✅ Run E2E tests
7. ✅ Deploy API container

---

## Testing with Malicious Objects

### Create Test Objects (Move)
```move
// Hardcoded in move/sources/ for testing:
// - rug_token.move → _freeze_all() + _drain_funds()
// - honeypot_defi.move → _sweep_all()
// - fake_cetus.move → spoofed LP receipt
```

### Publish and Test
```bash
cd move && sui client publish --network testnet
# Then use the published package IDs in testnet wallet
```

---

## Known Limitations

- ⚠️ Objects without `key + store` ability cannot be destroyed by third parties
  - Workaround: Only record metadata on-chain (no burn)
- ⚠️ Dust attack detection is pattern-based
  - May have false positives (small legitimate transfers)
- ⚠️ AI model may have model-specific latency
  - Typical threat analysis: 2-10 seconds

---

## Support & Issues

- **Contract bugs**: Check [move/README.md](./move/README.md)
- **API errors**: Check [THREAT_FLOW_ANALYSIS.md](./THREAT_FLOW_ANALYSIS.md)
- **Deployment issues**: Refer to [PRODUCTION_CHECKLIST.md](./PRODUCTION_CHECKLIST.md)
- **Migration questions**: See [ONCHAIN_MIGRATION_COMPLETE.md](./ONCHAIN_MIGRATION_COMPLETE.md)

---

## License

[Add license info]
