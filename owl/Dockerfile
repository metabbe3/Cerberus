# Owl — the Cerberus dashboard, a separate Next.js server (ROADMAP Phase 2).
# Standalone output: the runtime image needs only .next/standalone + static.
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:22-alpine AS run
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
RUN addgroup -S owl && adduser -S owl -G owl
COPY --from=build --chown=owl:owl /app/.next/standalone ./
COPY --from=build --chown=owl:owl /app/.next/static ./.next/static
USER owl
EXPOSE 3000
CMD ["node", "server.js"]
