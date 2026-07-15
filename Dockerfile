# syntax=docker/dockerfile:1

FROM node:22-bookworm-slim AS builder
ENV ELECTRON_SKIP_BINARY_DOWNLOAD=1
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY index.html vite.config.ts tsconfig.json tsconfig.app.json tsconfig.node.json ./
COPY src ./src
COPY public ./public
COPY admin ./admin
COPY server ./server
COPY scripts/run-production-build.mjs scripts/verify-project-attribution.mjs ./scripts/
RUN npm run build
RUN npm prune --omit=dev

FROM node:22-bookworm-slim AS runtime
ARG PAYLOADER_COMMIT_SHA=""
ENV NODE_ENV=production \
    PAYLOADER_HOST=0.0.0.0 \
    PAYLOADER_PORT=8081 \
    PAYLOADER_DATA_DIR=/app/data \
    PAYLOADER_SEED_DB=/app/server/default-seed.sqlite \
    PAYLOADER_CLIENT_CACHE_DIR=/tmp/payloader-client-cache \
    PAYLOADER_COMMIT_SHA=$PAYLOADER_COMMIT_SHA

WORKDIR /app
COPY --from=builder /app/package.json /app/package-lock.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/admin ./admin
COPY --from=builder /app/server ./server
COPY --from=builder /app/public ./public
COPY --from=builder /app/src ./src
COPY --from=builder /app/index.html /app/vite.config.ts ./
COPY --from=builder /app/tsconfig.json /app/tsconfig.app.json /app/tsconfig.node.json ./
RUN mkdir -p /app/data && chown -R node:node /app/data

USER node
EXPOSE 8081
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8081/api/ready').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]

CMD ["node", "server/admin-server.mjs"]
