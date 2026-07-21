FROM node:24-alpine

# Build from the repository root:
# docker build -f services/api/Dockerfile .
WORKDIR /workspace
RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY services/api/package.json services/api/package.json
COPY packages/auth/package.json packages/auth/package.json
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/grading/package.json packages/grading/package.json
COPY packages/reporting/package.json packages/reporting/package.json

RUN pnpm install --frozen-lockfile --filter @codegate/api... --prod

COPY services/api/src services/api/src
COPY services/api/migrations services/api/migrations
COPY packages/auth/src packages/auth/src
COPY packages/contracts/src packages/contracts/src
COPY packages/grading/src packages/grading/src
COPY packages/reporting/src packages/reporting/src

RUN mkdir -p /workspace/services/api/.data && chown -R node:node /workspace

WORKDIR /workspace/services/api
ENV PORT=8080 \
    AUTH_MODE=oidc \
    REPOSITORY_MODE=postgres \
    CODEGATE_DB_PATH=/workspace/services/api/.data/codegate.db

USER node
EXPOSE 8080

CMD ["node", "src/index.ts"]
