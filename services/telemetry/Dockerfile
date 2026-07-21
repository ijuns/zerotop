FROM node:24.14.0-bookworm-slim

WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY services/telemetry/package.json services/telemetry/package.json
RUN corepack enable && pnpm install --filter @codegate/telemetry --frozen-lockfile

COPY services/telemetry services/telemetry
RUN chown -R node:node /app
USER node
WORKDIR /app/services/telemetry
EXPOSE 9201

CMD ["node", "src/server.ts"]
