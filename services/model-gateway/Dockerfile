# syntax=docker/dockerfile:1.8
ARG NODE_RUNTIME_IMAGE
FROM ${NODE_RUNTIME_IMAGE}

ENV NODE_ENV=production \
    PORT=9010
WORKDIR /workspace
RUN corepack enable && corepack prepare pnpm@11.9.0 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY services/model-gateway/package.json services/model-gateway/package.json
RUN pnpm install --frozen-lockfile --filter @codegate/model-gateway... --prod

COPY --chown=65532:65532 services/model-gateway/src services/model-gateway/src
WORKDIR /workspace/services/model-gateway
USER 65532:65532
EXPOSE 9010
CMD ["node", "src/server.ts"]
