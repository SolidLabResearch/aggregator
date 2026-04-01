# =========================
# 1. Build stage
# =========================
FROM node:22-alpine AS builder

WORKDIR /app

# Install deps (STRICT lockfile)
COPY package*.json ./
RUN npm ci

# Copy source
COPY . .

# Build TypeScript → JS
RUN npm run build


# =========================
# 2. Runtime stage
# =========================
FROM node:22-alpine

WORKDIR /app

# Install production deps (STRICT lockfile)
COPY package*.json ./
RUN npm ci --omit=dev

# Copy built files
COPY --from=builder /app/dist ./dist

ENV NODE_ENV=production

EXPOSE 3000

CMD ["node", "dist/index.js"]
