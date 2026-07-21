FROM node:24.14.0-bookworm-slim

WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY services/probe-runner/package.json services/probe-runner/package.json
RUN corepack enable && pnpm install --filter @codegate/probe-runner --frozen-lockfile

COPY services/probe-runner services/probe-runner
RUN chown -R node:node /app
USER node
WORKDIR /app/services/probe-runner

ENTRYPOINT ["node", "src/index.ts"]
