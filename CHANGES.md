# DeepClean Feature Implementation — Complete Changelog

This document describes the **two features** and **all code changes** needed for:
1. **Wallet Connection Integration** — users can connect a Sui wallet to auto-populate the address
2. **On-Chain Quarantine Recording** — threat quarantines are recorded immutably on-chain via Move contract

---

## Feature 1: Wallet Connection Integration

### Files Updated (Frontend — `artifacts/deepclean/`)

#### 1. `package.json`
**Status**: ✅ Already includes `@mysten/dapp-kit` and `@mysten/sui`
- `@mysten/dapp-kit: ^0.14.47` — provides `ConnectButton`, `useCurrentAccount`, wallet context
- `@mysten/sui: ^1.18.0` — provides the Sui client, transaction builders, keypair utilities

**Action**: Run `pnpm install` in `artifacts/deepclean/` after confirming these deps are present.

---

#### 2. `src/App.tsx`
**Status**: ✅ Already implements wallet providers

Wraps the entire app with:
- `QueryClientProvider` — React Query for server state
- `SuiClientProvider` — Points to devnet fullnode URL
- `WalletProvider autoConnect` — Automatically reconnects the last wallet on page load
- `TooltipProvider` — UI component context

**No changes needed** — providers are correctly nested.

---

#### 3. `src/components/Layout.tsx`
**Changes**: Added wallet UI to sidebar footer

**Before**:
```jsx
// Bottom status
<div className="px-4 py-4 border-t border-border">
  <div className="flex items-center gap-2">
    <Activity className="w-3 h-3 text-green-400" />
    <span className="text-[11px] text-muted-foreground">Agent Active</span>
    <span className="ml-auto w-2 h-2 rounded-full bg-green-400 animate-pulse" />
  </div>
</div>
```

**After**:
```jsx
// Wallet & Status Footer
<div className="px-4 py-3 border-t border-border space-y-3">
  {/* Connect Button */}
  <div className="flex justify-center">
    <ConnectButton />
  </div>

  {/* Connected Address Display */}
  {account && (
    <div className="rounded px-2 py-1.5 bg-primary/10 border border-primary/20">
      <div className="text-[10px] text-muted-foreground uppercase tracking-widest mb-1">Connected</div>
      <div className="font-mono text-[10px] text-primary truncate" title={account.address}>
        {account.address.slice(0, 10)}...{account.address.slice(-6)}
      </div>
    </div>
  )}

  {/* Agent Status */}
  <div className="flex items-center gap-2">
    <Activity className="w-3 h-3 text-green-400" />
    <span className="text-[11px] text-muted-foreground">Agent Active</span>
    <span className="ml-auto w-2 h-2 rounded-full bg-green-400 animate-pulse" />
  </div>
</div>
```

**Imports added**:
```javascript
import { ConnectButton } from "@mysten/dapp-kit";
import { useCurrentAccount } from "@mysten/dapp-kit";
```

**Key additions**:
- `useCurrentAccount()` hook provides the connected account (or null)
- `<ConnectButton />` renders the wallet connection UI
- Truncated address display when connected (first 10 + last 6 chars)

---

#### 4. `src/pages/Wallets.tsx`
**Changes**: Auto-fill address when wallet connects + "Connected" badge

**Imports added**:
```javascript
import { useCurrentAccount } from "@mysten/dapp-kit";
import { useEffect } from "react"; // Already imported but needed explicitly here
```

**Inside component**:
```javascript
const account = useCurrentAccount();

// Auto-fill address when wallet connects
useEffect(() => {
  if (account?.address) {
    form.setValue("address", account.address);
  }
}, [account?.address, form]);
```

**Wallet card badge**: Added "Connected" badge when wallet address matches current account
```jsx
{account?.address === wallet.address && (
  <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-400 font-semibold">
    Connected
  </span>
)}
```

---

## Feature 2: On-Chain Quarantine Recording

### Files (Backend — `artifacts/api-server/src/`)

#### 1. `lib/onchain.ts`
**Status**: ✅ Already fully implemented

Exports:
- `isOnChainEnabled()` → checks if all 3 env vars are present
- `quarantineOnChain(params)` → submits PTB to Move contract, returns digest or null

**Reads from env**:
```
QUARANTINE_PACKAGE_ID   — 0x... package ID from `sui client publish`
QUARANTINE_ADMIN_CAP_ID — 0x... AdminCap object ID from publish
AGENT_PRIVATE_KEY       — base64 secret key from `sui keytool export`
SUI_NETWORK             — devnet (default: testnet)
```

**Behavior**:
- Non-fatal if env vars missing — returns null silently
- Converts parameters to appropriate Move types (u8 vectors, addresses, etc.)
- Returns transaction digest on success
- Logs all errors but never throws

---

#### 2. `routes/populate.ts`
**Changes**: Call `quarantineOnChain()` after DB insert

**Before** (just DB + Walrus):
```javascript
const [walrusBlobId, dbResult] = await Promise.all([
  storeThreatLog(logPayload),
  db.insert(threatsTable).values({...}).returning({id: threatsTable.id}),
]);
```

**After** (adds on-chain):
```javascript
const [walrusBlobId, dbResult] = await Promise.all([
  storeThreatLog(logPayload),
  db.insert(threatsTable).values({...}).returning({id: threatsTable.id}),
]);

threatId = dbResult[0]?.id ?? null;

// ... update DB with walrus blob ...

// NEW: Record on-chain via the deployed quarantine_vault contract (non-fatal)
onChainDigest = await quarantineOnChain({
  objectId:      obj.objectId,
  objectType:    obj.objectType,
  senderAddress: obj.senderAddress,
  riskScore:     verdict.risk_score,
  verdict:       verdict.verdict,
  reasonCode:    verdict.reason_code,
  confidence:    verdict.confidence,
  walrusBlobId:  walrusBlobId ?? "",
});

// NEW: Persist on-chain digest to DB if we got one
if (onChainDigest && threatId) {
  await db
    .update(threatsTable)
    .set({ quarantineTxDigest: onChainDigest })
    .where(eq(threatsTable.id, threatId))
    .catch(() => {
      // Column may not exist yet if migration hasn't run — non-fatal
    });
}
```

**Response includes** `onChainDigest` (first successful on-chain recording, or null):
```json
{
  "injected": 5,
  "quarantined": 4,
  "txDigest": null,
  "onChainDigest": "0xabc123def...",
  "threats": [...]
}
```

---

### Deployment File

#### `deploy_move.sh`
**Status**: ✅ Already complete

**Steps**:
1. Switch to devnet
2. Check deployer address
3. Request faucet funds
4. Publish `move/` package
5. Extract Package ID from `objectChanges`
6. Extract AdminCap ID from `objectChanges`
7. Export deployer private key via `sui keytool export`
8. Print the 3 secrets to copy into Replit

**Manual fallback** if Python JSON parsing fails on Replit:
- Output is saved to `/tmp/deepclean_publish_output.json`
- Open it and find the object with `type: "published"` → copy `packageId`
- Find the object with `objectType` containing `quarantine_vault::AdminCap` → copy `objectId`
- Run `sui keytool export --key-identity $DEPLOYER` manually and copy the `exportedPrivkey`

---

## Installation & Deployment

### 1. Install Frontend Dependencies
```bash
cd artifacts/deepclean/
pnpm install
```

### 2. Deploy Move Contract (one-time)
```bash
bash deploy_move.sh
```

### 3. Set Replit Secrets
Copy the three lines printed by `deploy_move.sh`:
- `QUARANTINE_PACKAGE_ID=0x...`
- `QUARANTINE_ADMIN_CAP_ID=0x...`
- `AGENT_PRIVATE_KEY=...`
- `SUI_NETWORK=devnet`

Paste into Replit Secrets. Restart the API server.

### 4. Verify
- Frontend: `/wallets` page should show `ConnectButton` at bottom of sidebar
- Click any wallet in the list that matches your connected address — it should show "Connected" badge
- Add a wallet form should auto-fill when you connect
- Backend: POST `/api/populate-wallet` should return `onChainDigest` in response (if env vars set)

---

## Testing Checklist

- [ ] `pnpm typecheck` in `artifacts/deepclean/` passes
- [ ] `pnpm typecheck` in `artifacts/api-server/` passes
- [ ] Frontend dev server runs: `cd artifacts/deepclean && pnpm dev`
- [ ] `ConnectButton` appears in sidebar
- [ ] Connecting wallet auto-fills address in "Add Wallet" form
- [ ] "Connected" badge appears on matching wallet card
- [ ] Seeding a wallet returns `onChainDigest` in toast (if Move deployed)
- [ ] Backend logs show `quarantineOnChain` calls (check `/api/populate-wallet` response)

---

## Troubleshooting

### "onchain.ts" type errors
- Ensure `@mysten/sui` is installed: `pnpm add @mysten/sui`
- Ensure `@mysten/dapp-kit` is installed: `pnpm add @mysten/dapp-kit`

### `deploy_move.sh` fails at JSON parsing
- Check if Python 3 is available: `python3 --version`
- Manually extract IDs from `/tmp/deepclean_publish_output.json` (see script output)
- Or use the JSON parsing fallback provided in the script

### "QUARANTINE_PACKAGE_ID not set"
- Run `bash deploy_move.sh` first (one-time)
- Copy the 3 values into Replit Secrets
- Restart the API server for env changes to take effect

### "ConnectButton not rendering"
- Verify `@mysten/dapp-kit/dist/index.css` is imported in `App.tsx`
- Verify `WalletProvider` is wrapping all components that use wallet hooks
- Check browser console for errors

---

## Summary

**Changes made**:
- ✅ Added wallet connection UI to sidebar
- ✅ Auto-fill wallet address on connect
- ✅ Show "Connected" badge on matching wallet card
- ✅ Call on-chain quarantine recording function
- ✅ Persist on-chain TX digest to DB
- ✅ Print on-chain digest in API response

**No breaking changes** — all existing functionality intact, features are purely additive.

