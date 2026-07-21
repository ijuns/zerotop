FROM gcr.io/projectsigstore/cosign/cosign:v3.0.6 AS cosign

FROM node:24.14.0-bookworm-slim

# Build from the repository root:
# docker build -f services/builder/Dockerfile .
ENV NODE_ENV=production \
    PORT=9004 \
    NODE_EXTRA_CA_CERTS=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
WORKDIR /workspace/services/builder

WORKDIR /workspace
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY services/builder/package.json services/builder/package.json
RUN pnpm install --frozen-lockfile --filter @codegate/builder --prod

COPY services/builder/src services/builder/src
COPY services/builder/migrations services/builder/migrations
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign

RUN groupadd --system --gid 10004 builder \
    && useradd --system --uid 10004 --gid builder --home-dir /nonexistent builder \
    && chown -R builder:builder /workspace

USER builder
WORKDIR /workspace/services/builder
EXPOSE 9004
CMD ["node", "src/index.ts"]
