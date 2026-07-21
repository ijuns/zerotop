FROM node:24.14.0-bookworm-slim

# Build from the repository root:
# docker build -f services/desktop-gateway/Dockerfile .
ENV NODE_ENV=production PORT=9001
WORKDIR /workspace
RUN corepack enable && corepack prepare pnpm@11.9.0 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY services/desktop-gateway/package.json services/desktop-gateway/package.json
RUN pnpm install --frozen-lockfile --filter @codegate/desktop-gateway... --prod

COPY services/desktop-gateway/src services/desktop-gateway/src
RUN chown -R node:node /workspace

WORKDIR /workspace/services/desktop-gateway
USER node
EXPOSE 9001
CMD ["node", "src/server.ts"]
