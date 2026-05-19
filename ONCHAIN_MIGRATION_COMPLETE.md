# 100% On-Chain Migration — Complete ✅

## Summary

DeepClean has been successfully migrated from synthetic test fixtures to a fully on-chain production system. All objects are now **real Sui blockchain data**, and the complete threat lifecycle is recorded on-chain.

---

## What Changed

### Phase 1: Removed Synthetic Fixture Generation
- ❌ Deleted `buildSyntheticFixtures()` function (145 lines of hardcoded test objects)
- ❌ Deleted `syntheticObjectId()` helper function
- ❌ Removed deduplication logic against synthetic objects
- ✅ API now analyzes **only real on-chain objects** from target wallet

### Phase 2: Integrated Object Destruction
- ✅ Added `sendToDeadOnChain()` call after `quarantineOnChain()` succeeds
- ✅ Objects are now **destroyed immediately** after being recorded on-chain
- ✅ Both `quarantineTxDigest` and `burnTxDigest` are stored in database

### Phase 3: Added On-Chain Tracking Fields
- ✅ `objectSource: "real" | "synthetic"` — for audit trail (defaults to "real")
- ✅ `onChainEventId: String?` — tracks specific QuarantinedAsset events
- ✅ `releaseOnChainTxDigest: String?` — supports future release functionality
- Database migration applied: `20260519092826_add_onchain_tracking_fields`

### Phase 4: Event ID Extraction
- ✅ Added `extractQuarantineEventId()` function to parse event data from tx digest
- ✅ Full threat lifecycle now linkable via event IDs in addition to tx digests

### Phase 5: Dead Address Validation
- ✅ Added `validateDeadAddressConfig()` startup check
- ✅ Prevents silent failures from mismatched DEAD_ADDRESS configuration
- ✅ Called automatically on every `/populate-wallet` request

### Phase 6: Removed Test-Mode Code
- ✅ Hardcoded `REAL_ONCHAIN = true` (no fallback to test mode)
- ✅ Comments updated to reflect production-only operation
- ✅ .env.example already configured for production

---

## How It Works Now

### Threat Lifecycle

```
1. API receives wallet address
   ↓
2. Fetch REAL on-chain objects from Sui RPC
   ↓
3. AI analyzes each object for threats
   ↓
4. For each MALICIOUS threat:
   a) Record in database with PENDING status
   b) Call quarantineOnChain() → creates on-chain record with event
   c) Extract event ID from transaction
   d) Call sendToDeadOnChain() → sends object to 0x0
   e) Update DB with both quarantine + burn tx digests
   ↓
5. User sees threat with full on-chain proof in wallet
```

### Data Model

```prisma
threat {
  objectId: "0xreal..." (from blockchain, not synthetic)
  objectType: "0xreal::module::Type" (from blockchain, not fake 0xdead)
  senderAddress: "0xreal..." (extracted from tx history)
  verdict: "MALICIOUS"
  status: "quarantined" | "burned"
  
  // New fields for on-chain tracking:
  objectSource: "real" (indicates production, not test)
  onChainEventId: "0x..." (QuarantinedAsset event ID)
  quarantineTxDigest: "0x..." (tx that created on-chain record)
  burnTxDigest: "0x..." (tx that destroyed object)
}
```

---

## Deployment Checklist

Before deploying to production:

- [ ] **Move contract deployed** to target network (testnet/mainnet)
  ```bash
  cd move && sui client publish --network testnet
  ```

- [ ] **Extract and set env vars** from deployment output
  ```env
  QUARANTINE_PACKAGE_ID=0x... (from deployment output)
  QUARANTINE_ADMIN_CAP_ID=0x... (from move/Published.toml)
  AGENT_PRIVATE_KEY=suiprivkey1... (from `sui keytool export`)
  SUI_NETWORK=testnet or mainnet
  DEAD_ADDRESS=0x0000000000000000000000000000000000000000000000000000000000000000
  ```

- [ ] **Database migration applied**
  ```bash
  cd lib/db && npx prisma migrate deploy
  ```

- [ ] **E2E test passes**
  ```bash
  npm run test:e2e
  ```

- [ ] **No synthetic patterns remain**
  ```bash
  grep -r "0xbadc0ffee\|0xdead[0-9a-f]*::" artifacts/api-server/src
  # Should return: (no output)
  ```

---

## Verification Commands

### Check API returns real objects
```bash
curl http://localhost:8080/api/wallets/0x<address>
# Should list real Sui objects owned by address, not synthetic fixtures
```

### Check database has real IDs
```bash
sqlite3 lib/db/dev.db "SELECT objectId, verdict FROM threats LIMIT 3;"
# Should show real 64-char hex IDs, not 0x1, 0x2, 0x3
```

### Check on-chain recording works
```bash
curl -X POST http://localhost:8080/api/threats/populate-wallet \
  -H "Content-Type: application/json" \
  -d '{
    "targetAddress": "0x<real_wallet>"
  }'
# Check response includes quarantineTxDigest and burnTxDigest
```

### Query threat on Sui Explorer
1. Copy `quarantineTxDigest` from response
2. Visit: https://suiscan.xyz/testnet/tx/{digest}
3. Verify QuarantinedAsset event is present

---

## Breaking Changes

**These patterns are now INVALID and will cause errors:**

| Pattern | What Happens | Fix |
|---------|-------------|-----|
| `0xbadc0ffee...` senders | API fails (not on-chain) | Use real sender addresses from tx history |
| `0xdead0001::` package IDs | AI cannot analyze | Use real deployed package IDs |
| `syntheticObjectId(N)` | Function removed | Remove from test code |
| `REAL_ONCHAIN=false` | Hardcoded to true | Remove env var or set to true |
| `0x0000...0000` dead address | Will be rejected if mismatch | Verify DEAD_ADDRESS matches contract |

---

## Migration Timeline

| Phase | Date | Status |
|-------|------|--------|
| 1: Remove synthetics | May 19, 2026 | ✅ Complete |
| 2: Integrate destruction | May 19, 2026 | ✅ Complete |
| 3: Schema migration | May 19, 2026 | ✅ Complete |
| 4: Event extraction | May 19, 2026 | ✅ Complete |
| 5: Validation | May 19, 2026 | ✅ Complete |
| 6: Cleanup | May 19, 2026 | ✅ Complete |
| 7: Documentation | May 19, 2026 | ✅ Complete |

---

## Troubleshooting

### "Dead address configuration invalid"
```
Error: Dead address mismatch: env=0x..., contract=0x...
```
**Fix**: Ensure DEAD_ADDRESS env var is set to exactly `0x0000000000000000000000000000000000000000000000000000000000000000`

### "No events found in quarantine transaction"
```
Error: extractQuarantineEventId failed
```
**Status**: Non-fatal. Fall back to using tx digest. Check that contract was deployed correctly.

### "Objects still in wallet after quarantine"
```
Quarantine tx succeeded but object not destroyed
```
**Reason**: `sendToDeadOnChain()` may have failed. Check logs for:
- Object lacks `key + store` ability
- Agent wallet doesn't have sufficient gas
- Contract function signature mismatch

---

## Future Enhancements

1. **Release functionality**: Use `releaseOnChainTxDigest` field when contract supports releasing quarantined objects
2. **Batch destruction**: Optimize multiple objects with merge and send operations
3. **Event indexing**: Index on-chain events for faster queries instead of relying on tx digest
4. **Multi-sig execution**: Support multi-signature admin cap for governance

---

## Support

For issues or questions:
1. Check PRODUCTION_CHECKLIST.md for pre-deployment validation
2. Review Move contract ABI to verify function signatures match calls in onchain.ts
3. Verify testnet objects exist: `sui client objects --filter-by-id 0x... --network testnet`
4. Check contract deployment: `sui client object 0x<package-id> --network testnet`
