FROM node:24-alpine AS builder
RUN corepack enable && corepack prepare pnpm@9.10.0 --activate
WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY lib/ lib/
COPY artifacts/deepclean/ artifacts/deepclean/
ARG VITE_API_BASE=http://localhost:8080
ENV VITE_API_BASE=$VITE_API_BASE
RUN pnpm install --frozen-lockfile
RUN pnpm --filter @workspace/deepclean run build

FROM nginx:alpine
COPY --from=builder /app/artifacts/deepclean/dist/public /usr/share/nginx/html
EXPOSE 80