# BioFire-MPC v6.0 Production Dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production=false
COPY . .
RUN npm run build

FROM node:20-alpine AS production
RUN apk add --no-cache dumb-init
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./
RUN mkdir -p logs data
RUN addgroup -g 1001 -S biofire && adduser -u 1001 -S biofire -G biofire
RUN chown -R biofire:biofire /app
USER biofire
EXPOSE 3000 9090
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/server.js"]
