# DeepClean

An autonomous Sui blockchain spam & phishing filter agent. It monitors wallet addresses for incoming malicious assets, runs AI-powered threat analysis via Gemini 2.5 Flash, and auto-quarantines high-risk objects. Users can release or burn quarantined assets from the dashboard.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 5000)
- `pnpm --filter @workspace/deepclean run dev` — run the frontend (uses PORT env var)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string
- Required env: `GEMINI_API_KEY` — Gemini API key for threat analysis

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)
- Frontend: React + Vite + Tailwind CSS + shadcn/ui + Recharts
- AI: Gemini 2.5 Flash via REST API

## Where things live

- DB schema: `lib/db/src/schema/` — `threats.ts`, `wallets.ts`
- API contract: `lib/api-spec/openapi.yaml`
- Generated hooks: `lib/api-client-react/src/generated/`
- Generated Zod schemas: `lib/api-zod/src/generated/`
- API routes: `artifacts/api-server/src/routes/` — threats, wallets, stats, health
- Gemini AI service: `artifacts/api-server/src/lib/gemini.ts`
- Frontend pages: `artifacts/deepclean/src/pages/`
- Frontend components: `artifacts/deepclean/src/components/`

## Architecture decisions

- Threat analysis uses Gemini 2.5 Flash with structured JSON output (`responseMimeType: "application/json"`)
- Assets with `risk_score >= 65` are auto-quarantined and saved to the DB
- Mock analysis fallback when `GEMINI_API_KEY` is missing (deterministic based on URL patterns)
- The quarantine vault concept mirrors the Sui Move smart contract design — status field tracks quarantined/released/burned
- Walrus blob IDs stored on threats link to the verifiable off-chain AI logs

## Product

- **Dashboard** — live threat stats, risk breakdown chart, recent activity feed
- **Threats** — filterable table of all detected objects with verdict/risk/status and release/burn actions
- **Threat Detail** — full AI reasoning, flags, metadata, Walrus blob ID with copy button
- **Analyze** — manual form to submit any Sui object for AI analysis (Gemini 2.5 Flash)
- **Wallets** — manage monitored wallet addresses with add/remove

## User preferences

- Uses Gemini 2.5 Flash model (`gemini-2.5-flash`) via Gemini REST API
- Dark theme by default — deep navy/black with electric cyan primary and violet secondary

## Gotchas

- Run `pnpm --filter @workspace/api-spec run codegen` after every OpenAPI spec change
- `pnpm --filter @workspace/db run push` applies schema to dev DB (Replit handles prod on publish)
- The `zod` import in schema files must use `zod/v4`
- Font: Space Mono (mono) is used throughout for the security terminal aesthetic

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
