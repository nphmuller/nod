FROM node:24-bookworm-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY server/ ./server/
COPY public/ ./public/
COPY scripts/ ./scripts/

RUN mkdir -p /app/data \
    && chown node:node /app/data \
    && chmod 700 /app/data

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    DATA_DIR=/app/data \
    APP_ORIGIN=http://localhost:3000

USER node

EXPOSE 3000
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node --input-type=module -e 'try { const response = await fetch(`http://127.0.0.1:${process.env.PORT || 3000}/api/v1`, { signal: AbortSignal.timeout(3000) }); process.exit(response.ok ? 0 : 1); } catch { process.exit(1); }'

# Run Node directly so it receives container shutdown signals.
CMD ["node", "server/index.js"]
