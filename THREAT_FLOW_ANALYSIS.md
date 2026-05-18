# Threat Flow Analysis: "4 Threats Detected" → DB → Quarantine

## Issue Summary
**Detected threats: 4 | Quarantined threats retrieved from DB: 0**

The threats are created in the database but the wallet's `threatsDetected` counter isn't updated, and the frontend doesn't refresh it after population.

---

## 1. DETECTION: "4 Threats Detected" Display

### Display Logic
**File**: [artifacts/deepclean/src/pages/Wallets.tsx](artifacts/deepclean/src/pages/Wallets.tsx#L657-L674)
```typescript
{(wallet.threatsDetected ?? 0) > 0 ? (
  <>
    <AlertTriangle className="w-3 h-3 text-amber-400" />
    <span className="text-amber-400">
      {wallet.threatsDetected} threat{(wallet.threatsDetected ?? 0) !== 1 ? "s" : ""} detected
    </span>
  </>
) : (
  <span>No threats detected</span>
)}
```

**Source of value**: `wallet.threatsDetected` comes from the API response (watchedWallet table)

### Database Schema
**File**: [lib/db/prisma/schema.prisma](lib/db/prisma/schema.prisma#L42)
```prisma
model WatchedWallet {
  id              Int       @id @default(autoincrement())
  address         String    @unique @db.VarChar(66)
  label           String?   @db.VarChar(255)
  threatsDetected Int       @default(0)   @map("threats_detected")  // ← The counter
  isActive        Boolean   @default(true)
  createdAt       DateTime  @default(now())
}
```

---

## 2. POPULATE OPERATION: Adding Threats via `/populate-wallet`

### Populate Endpoint
**File**: [artifacts/api-server/src/routes/populate.ts](artifacts/api-server/src/routes/populate.ts#L164-L227)

#### What it DOES:
- Fetches real wallet objects from chain
- Analyzes them with Gemini AI
- **Creates threat records** with status "quarantined" or "safe"

```typescript
prisma.threat.create({
  data: {
    objectId:      obj.objectId,
    objectType:    obj.objectType,
    senderAddress: obj.senderAddress,
    walletAddress: targetAddress,  // ← Wallet link exists
    displayName:   obj.displayName ?? null,
    displayUrl:    obj.displayUrl  ?? null,
    riskScore:     verdict.risk_score,
    verdict:       verdict.verdict,
    reasonCode:    verdict.reason_code,
    confidence:    verdict.confidence,
    flags:         verdict.flags,
    reasoning:     verdict.reasoning,
    status:        verdict.verdict === "MALICIOUS" && verdict.risk_score >= 75 
                   ? "quarantined" 
                   : "safe",
  },
})
```

#### **🔴 BUG #1: Missing Counter Update**
The populate endpoint **does NOT** update `watchedWallet.threatsDetected`

**Missing code** (should be after creating threats):
```typescript
// NOT IN THE CODE - THIS IS MISSING!
await prisma.watchedWallet.update({
  where: { address: targetAddress },
  data: { threatsDetected: { increment: quarantined } }
});
```

### Response Example
**Endpoint returns**: `{ injected: 4, quarantined: 4, threats: [...] }`

But the database `watchedWallet.threatsDetected` remains **0**

---

## 3. THREAT STORAGE: Creating Records in Database

### Threat Table
**File**: [lib/db/prisma/schema.prisma](lib/db/prisma/schema.prisma)
```prisma
model Threat {
  id                 Int       @id @default(autoincrement())
  objectId           String    @db.VarChar(66)
  objectType         String    @db.Text
  senderAddress      String    @db.VarChar(255)
  walletAddress      String    @db.VarChar(66)  // ← Links to wallet
  displayName        String?   @db.Text
  displayUrl         String?   @db.Text
  riskScore          Int
  verdict            String    // "SAFE" | "SUSPICIOUS" | "MALICIOUS"
  reasonCode         Int?
  confidence         Float?
  flags              String[]  @db.Text[]
  reasoning          String?   @db.Text
  status             String    @default("quarantined")  // "quarantined" | "safe"
  walrusBlobId       String?   @db.Text
  quarantineTxDigest String?   @db.Text
  detectedAt         DateTime  @default(now())
  updatedAt          DateTime  @updatedAt
}
```

### Create Path (Populate)
**File**: [artifacts/api-server/src/routes/populate.ts](artifacts/api-server/src/routes/populate.ts#L218-L240)
```typescript
// For MALICIOUS + score >= 75
if (verdict.verdict === "MALICIOUS" && verdict.risk_score >= 75) {
  const [walrusBlobId, threat] = await Promise.all([
    storeThreatLog(logPayload),
    prisma.threat.create({
      data: {
        // ... all fields ...
        status: "quarantined",  // ← Created as quarantined
      },
    }),
  ]);
  threatId = threat.id;
  // Store Walrus blob ID linking
  if (walrusBlobId) {
    await prisma.threat.update({ where: { id: threatId }, data: { walrusBlobId } });
  }
}
```

---

## 4. QUARANTINE RETRIEVAL: Fetching from DB

### Query Path (Clean Operation)
**File**: [artifacts/deepclean/src/pages/Wallets.tsx](artifacts/deepclean/src/pages/Wallets.tsx#L356-L370)

```typescript
async function performDeepClean(walletId: number, walletAddress: string): Promise<...> {
  appendSeedLog(walletId, mkLog("info", "  Fetching quarantined threats from DB for wallet…"));

  const threats = await apiJson<QuarantinedThreat[]>(
    `/api/threats?status=quarantined&limit=200&walletAddress=${encodeURIComponent(walletAddress)}`,
  );

  if (threats.length === 0) {
    appendSeedLog(walletId, mkLog("info", "No quarantined threats to clean"));
    appendSeedLog(walletId, mkLog("success", "✓ Deep clean complete — 0 threats burned"));
    return true;
  }
  // ...
}
```

### API Query Endpoint
**File**: [artifacts/api-server/src/routes/threats.ts](artifacts/api-server/src/routes/threats.ts#L19-L43)

```typescript
router.get("/threats", async (req, res) => {
  const query = ListThreatsQueryParams.safeParse(req.query);
  // ...
  const threats = await prisma.threat.findMany({
    where: {
      ...(verdict ? { verdict } : {}),
      ...(status  ? { status }  : {}),
      ...(walletAddress ? { walletAddress: { equals: walletAddress, mode: "insensitive" } } : {}),
    },
    orderBy: { detectedAt: "desc" },
    take: limit,
    skip: offset,
  });
  // Returns threats with status = "quarantined"
});
```

✅ **This query works fine** — it finds quarantined threats in the DB

---

## 5. THE MISMATCH: Two-Part Bug

### 🔴 Bug Part 1: Populate doesn't update threatsDetected counter

**File**: [artifacts/api-server/src/routes/populate.ts](artifacts/api-server/src/routes/populate.ts#L298-L320)

The endpoint returns:
```typescript
res.json({
  injected:      threats.length,
  quarantined,    // ← Says "4 threats quarantined"
  txDigest:      callerTxDigest ?? null,
  onChainDigest: onChainDigests[0] ?? null,
  threats,
});
```

**But never updates the wallet counter:**
```typescript
// MISSING:
// await prisma.watchedWallet.update({
//   where: { address: targetAddress },
//   data: { threatsDetected: { increment: quarantined } }
// });
```

---

### 🔴 Bug Part 2: Frontend doesn't refresh wallet list after populate

**File**: [artifacts/deepclean/src/pages/Wallets.tsx](artifacts/deepclean/src/pages/Wallets.tsx#L508-L521)

After populate succeeds:
```typescript
onSuccess: async (result, { address }) => {
  // ... logs to UI ...
  
  // Invalidates THREATS and DASHBOARD queries
  queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
  queryClient.invalidateQueries({ queryKey: getGetDashboardStatsQueryKey() });
  
  // ❌ MISSING: Does NOT invalidate watched wallets list!
  // Should be:
  // queryClient.invalidateQueries({ queryKey: getListWatchedWalletsQueryKey() });
}
```

**Result**: Even if the API updated the counter, the frontend wouldn't fetch the new value.

---

## 6. COMPARISON: Monitor Path (Works Correctly)

The **monitor** system correctly updates the counter:

**File**: [artifacts/api-server/src/lib/monitor.ts](artifacts/api-server/src/lib/monitor.ts#L254-L259)

```typescript
// When a threat is detected through monitoring:
await prisma.watchedWallet.update({
  where: { address: walletAddress },
  data:  { threatsDetected: { increment: 1 } },
});

logger.warn({ id: inserted.id, objectId, riskScore: verdict.risk_score }, 
  "Threat auto-quarantined");
```

✅ Monitor increments the counter AND the frontend would see it

---

## Flow Diagram

```
POPULATE ENDPOINT (/populate-wallet)
    ↓
Fetch 4 real wallet objects
    ↓
Analyze with AI → 4 MALICIOUS (score >= 75)
    ↓
Create 4 threat records in DB with status="quarantined"
    ↓
Return { injected: 4, quarantined: 4, threats: [...] }
    ↓
❌ BUT: watchedWallet.threatsDetected still = 0
    ↓
FRONTEND POPULATE MUTATION
    ↓
Invalidate: threats query ✓
Invalidate: dashboard stats ✓
❌ Invalidate: wallets list ✗ (MISSING)
    ↓
UI still shows "0 threats detected"

CLEAN OPERATION (queries quarantined threats)
    ↓
GET /api/threats?status=quarantined&walletAddress=...
    ↓
Query finds 4 threat records ✓
    ↓
But they're only visible if you directly query the database
They're NOT reflected in the wallet card display
```

---

## Summary Table

| Component | File | Status | Issue |
|-----------|------|--------|-------|
| **Display "X threats detected"** | Wallets.tsx:657 | ✓ Works | Gets value from `wallet.threatsDetected` |
| **Database counter (threatsDetected)** | schema.prisma:42 | ✅ Exists | Never updated by populate endpoint |
| **Create threat records** | populate.ts:218 | ✓ Works | Creates 4 records with walletAddress link |
| **Query quarantined threats** | threats.ts:19 | ✓ Works | Finds records in DB correctly |
| **Update wallet counter after populate** | populate.ts:298 | 🔴 MISSING | No update to watchedWallet.threatsDetected |
| **Refresh wallet list in UI** | Wallets.tsx:508 | 🔴 MISSING | Doesn't invalidate getListWatchedWalletsQueryKey() |
| **Monitor path** | monitor.ts:255 | ✓ Works | Updates counter correctly for monitored threats |

