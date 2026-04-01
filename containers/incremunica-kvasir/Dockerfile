# =========================
# 1. Build stage
# =========================
FROM node:22-alpine AS builder

WORKDIR /app

# Install deps
COPY package*.json ./
RUN npm install

# Copy source
COPY . .

# Build TypeScript → JS
RUN npm run build


# =========================
# 2. Runtime stage
# =========================
FROM node:22-alpine

WORKDIR /app

# Only install production deps
COPY package*.json ./
RUN npm install --omit=dev

# Copy built files
COPY --from=builder /app/dist ./dist

# Environment variable (can be overridden)
ENV NODE_ENV=production

# Expose port
EXPOSE 3000

# Start server
CMD ["node", "dist/index.js"]