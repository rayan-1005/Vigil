# Dockerfile
FROM node:20-alpine AS base
WORKDIR /app

# Install dependencies only
FROM base AS deps
COPY package*.json ./
RUN npm ci --omit=dev

# Final image
FROM base AS runner
ENV NODE_ENV=production

# Non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

COPY --from=deps /app/node_modules ./node_modules
COPY . .

EXPOSE 3001
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://localhost:3001/api/v1/health || exit 1

CMD ["node", "src/server.js"]
