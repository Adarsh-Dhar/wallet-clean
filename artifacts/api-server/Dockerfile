FROM node:24-alpine
RUN corepack enable && corepack prepare pnpm@9.10.0 --activate
WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY lib/ lib/
COPY artifacts/api-server/ artifacts/api-server/
RUN pnpm install --frozen-lockfile
RUN pnpm --filter @workspace/api-server run build
# Push DB schema on startup
CMD sh -c "pnpm --filter @workspace/db run push && node --enable-source-maps artifacts/api-server/dist/index.mjs"