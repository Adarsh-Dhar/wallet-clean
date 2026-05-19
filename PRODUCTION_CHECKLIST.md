# Production Deployment Checklist

## Pre-Deployment Validation

Complete these checks **before** deploying to production:

---

## 1. Move Contract Deployment ✅

- [ ] **Contract Published**
  ```bash
  cd move && sui client publish --network testnet
  # Copy PACKAGE_ID and ADMIN_CAP_ID from output
  ```

- [ ] **Verify on-chain**
  ```bash
  sui client object 0x<PACKAGE_ID> --network testnet
  # Should show code, types, and owner
  ```

- [ ] **Entry functions accessible**
  ```bash
  sui move build --network testnet
  # Should compile without errors
  ```

---

## 2. Environment Configuration ✅

- [ ] **QUARANTINE_PACKAGE_ID set**
  ```bash
  echo $QUARANTINE_PACKAGE_ID
  # Should output: 0x<64 hex chars>
  ```

- [ ] **QUARANTINE_ADMIN_CAP_ID set**
  ```bash
  echo $QUARANTINE_ADMIN_CAP_ID
  # Should output: 0x<64 hex chars>
  ```

- [ ] **AGENT_PRIVATE_KEY set (and exported correctly)**
  ```bash
  # Export from Sui CLI:
  sui keytool export --key-identity $(sui client active-address)
  # Copy exportedPrivateKey → AGENT_PRIVATE_KEY
  ```

- [ ] **SUI_NETWORK set to target**
  ```bash
  echo $SUI_NETWORK
  # Should be: testnet or mainnet
  ```

- [ ] **DEAD_ADDRESS matches contract**
  ```bash
  echo $DEAD_ADDRESS
  # Should be: 0x0000000000000000000000000000000000000000000000000000000000000000
  ```

- [ ] **GITHUB_MODELS_TOKEN set**
  ```bash
  curl https://api.github.com/repos -H "Authorization: Bearer $GITHUB_MODELS_TOKEN"
  # Should succeed (returns 200)
  ```

- [ ] **DATABASE_URL points to production**
  ```bash
  psql "$DATABASE_URL" -c "SELECT version();"
  # Should connect successfully
  ```

---

## 3. Database Migrations ✅

- [ ] **Backup production database**
  ```bash
  pg_dump "$DATABASE_URL" > deepclean_backup_$(date +%Y%m%d_%H%M%S).sql
  # Store safely for recovery
  ```

- [ ] **Apply Prisma migrations**
  ```bash
  cd lib/db && npx prisma migrate deploy
  # Should apply 20260519092826_add_onchain_tracking_fields
  ```

- [ ] **Verify new fields exist**
  ```bash
  npx prisma studio
  # Check Threat model has: objectSource, onChainEventId, releaseOnChainTxDigest
  ```

---

## 4. Code Quality ✅

- [ ] **No synthetic patterns remain**
  ```bash
  grep -r "0xbadc0ffee\|0xdead[0-9a-f]*::" artifacts/api-server/src
  # Should output: (no results)
  ```

- [ ] **No hardcoded addresses**
  ```bash
  grep -r "0x0000000000" artifacts/api-server/src --include="*.ts"
  # Should only appear in comments or validation code
  ```

- [ ] **TypeScript compiles**
  ```bash
  cd artifacts/api-server && npm run build
  # Should complete without errors
  ```

- [ ] **No lint errors**
  ```bash
  cd artifacts/api-server && npm run lint
  # Should pass all checks
  ```

---

## 5. Testing ✅

- [ ] **Unit tests pass**
  ```bash
  npm run test
  # All tests should pass
  ```

- [ ] **Integration tests pass**
  ```bash
  npm run test:integration
  # Tests with real testnet contracts
  ```

- [ ] **E2E test passes**
  ```bash
  npm run test:e2e
  # Full workflow: analyze → quarantine → destroy
  ```

---

## 6. On-Chain Verification ✅

- [ ] **Can connect to RPC**
  ```bash
  curl "https://testnet-rpc.sui.io/" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"sui_getChainIdentifier","params":[]}'
  # Should return chain identifier
  ```

- [ ] **Agent wallet has gas**
  ```bash
  sui client gas --network testnet
  # Should show coins with > 0 balance
  ```

- [ ] **Admin cap exists and is owned**
  ```bash
  sui client object 0x<ADMIN_CAP_ID> --network testnet
  # Should show: "ObjectRef" with owner = agent address
  ```

- [ ] **Can execute quarantine transaction**
  ```bash
  # Create a test PTB without submitting
  node -e "
    const { Transaction } = require('@mysten/sui/transactions');
    const tx = new Transaction();
    tx.setSender('0x...');
    console.log('PTB valid');
  "
  # Should not throw errors
  ```

---

## 7. API Integration ✅

- [ ] **API starts without errors**
  ```bash
  npm run dev
  # Should listen on configured PORT
  ```

- [ ] **Health check endpoint responds**
  ```bash
  curl http://localhost:8080/health
  # Should return 200
  ```

- [ ] **Can fetch wallet objects**
  ```bash
  curl http://localhost:8080/api/wallets/0x<test_wallet>
  # Should return array of real objects
  ```

- [ ] **Dead address validation passes**
  ```bash
  # API logs should show: "Dead address validation passed"
  # When making /populate-wallet request
  ```

- [ ] **Threat analysis works**
  ```bash
  curl -X POST http://localhost:8080/api/threats/populate-wallet \
    -H "Content-Type: application/json" \
    -d '{"targetAddress":"0x<test_wallet>"}'
  # Should return array of analyzed threats
  ```

---

## 8. On-Chain Recording ✅

- [ ] **Quarantine transaction succeeds**
  ```bash
  # Check API response for quarantineTxDigest
  # Should be non-null 64-char hex string
  ```

- [ ] **Event ID extracted**
  ```bash
  # Check database: SELECT onChainEventId FROM threats LIMIT 1;
  # Should be non-null
  ```

- [ ] **Can view on Sui Explorer**
  ```bash
  # Go to: https://suiscan.xyz/testnet/tx/{quarantineTxDigest}
  # Should show QuarantinedAsset event
  ```

- [ ] **Burn transaction succeeds**
  ```bash
  # Check API response for burnTxDigest
  # Should be non-null 64-char hex string
  ```

---

## 9. Monitoring & Alerts ✅

- [ ] **Logging configured**
  ```bash
  grep -n "logger\|req.log" artifacts/api-server/src/routes/populate.ts
  # Should show structured logging calls
  ```

- [ ] **Error alerts working**
  ```bash
  # Simulate error: kill -9 to api-server
  # Should trigger alert/log
  ```

- [ ] **Database query performance acceptable**
  ```bash
  # Run analyze-heavy queries and check response times
  # Should be < 1s for typical threat
  ```

---

## 10. Security ✅

- [ ] **Private key not in version control**
  ```bash
  git log --all --oneline -- AGENT_PRIVATE_KEY
  # Should show: (no results)
  ```

- [ ] **Secrets loaded from env, not code**
  ```bash
  grep -r "AGENT_PRIVATE_KEY.*=" artifacts/api-server/src --include="*.ts"
  # Should only reference process.env, not hardcoded values
  ```

- [ ] **Database credentials not logged**
  ```bash
  grep -r "DATABASE_URL\|password" artifacts/api-server/src --include="*.ts" | grep -v "process.env"
  # Should show: (no matches)
  ```

- [ ] **API auth enabled** (in production)
  ```bash
  # Verify: NODE_ENV=production (not test)
  # Verify: Auth middleware enabled on routes
  ```

---

## 11. Backup & Recovery ✅

- [ ] **Database backup created**
  ```bash
  ls -lh deepclean_backup_*.sql
  # Should show recent backup file
  ```

- [ ] **Backup tested (restore to staging)**
  ```bash
  createdb test_restore && \
  psql test_restore < deepclean_backup_*.sql && \
  psql test_restore -c "SELECT COUNT(*) FROM threats;"
  # Should restore successfully
  ```

- [ ] **Rollback plan documented**
  - Previous API version stored
  - Previous contract bytecode archived
  - Database schema change is reversible

---

## 12. Communication ✅

- [ ] **Deployment window scheduled**
  - [ ] Low-traffic time window chosen
  - [ ] Team notified of maintenance window
  - [ ] Rollback procedure reviewed

- [ ] **Change log updated**
  ```bash
  git log --oneline | head -1
  # Should reference this migration
  ```

- [ ] **Documentation reviewed**
  ```bash
  [ -f ONCHAIN_MIGRATION_COMPLETE.md ] && echo "✓"
  [ -f PRODUCTION_CHECKLIST.md ] && echo "✓"
  ```

---

## Post-Deployment Monitoring (24hrs)

- [ ] **No errors in logs**
  ```bash
  # Review API logs, database logs, blockchain logs
  # Should show normal operation
  ```

- [ ] **Threat detection working**
  ```bash
  # Trigger with known malicious object
  # Should analyze and quarantine correctly
  ```

- [ ] **On-chain recording working**
  ```bash
  # Verify events emitted on-chain
  # Check Sui Explorer for transactions
  ```

- [ ] **Database growth normal**
  ```bash
  SELECT COUNT(*) FROM threats;
  # Should increment as new threats analyzed
  ```

- [ ] **Performance acceptable**
  ```bash
  # Threat analysis response time < 10s
  # Database queries < 1s
  # API uptime 99.9%+
  ```

---

## Rollback Plan (If Issues Found)

### Immediate Actions
1. Stop API server: `killall node`
2. Restore database from backup: `psql ... < deepclean_backup_*.sql`
3. Deploy previous API version
4. Verify health: `curl http://localhost:8080/health`

### Database Rollback
```bash
# If schema migration failed:
cd lib/db && npx prisma migrate resolve --rolled-back 20260519092826_add_onchain_tracking_fields

# If transaction integrity compromised:
# Use backup from before migration
psql "$DATABASE_URL" < deepclean_backup_pre_migration.sql
```

### Contract Rollback
```bash
# If Move contract has issues:
# Revert QUARANTINE_PACKAGE_ID env var to previous contract
# Update endpoint to call old package ID
# Redeploy API pointing to old package
```

---

## Sign-Off

- [ ] All checks passed
- [ ] Backup verified
- [ ] Team notified
- [ ] Ready for production

**Deployment Date**: ___________
**Deployed By**: ___________
**Verified By**: ___________

---

## References

- [ONCHAIN_MIGRATION_COMPLETE.md](./ONCHAIN_MIGRATION_COMPLETE.md) — Migration details
- [Move Contract Docs](./move/README.md) — Contract structure
- [Sui RPC API](https://docs.sui.io/references/sui-api) — Chain operations
- [Prisma Schema](./lib/db/prisma/schema.prisma) — Database schema
