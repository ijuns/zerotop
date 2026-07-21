FROM node:24.14.0-bookworm-slim

# Build from the repository root:
# docker build -f services/grader/Dockerfile .
ENV NODE_ENV=production PORT=9002
WORKDIR /workspace
RUN corepack enable && corepack prepare pnpm@11.9.0 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/grading/package.json packages/grading/package.json
COPY services/grader/package.json services/grader/package.json
RUN pnpm install --frozen-lockfile --filter @codegate/grader... --prod

COPY packages/grading/src packages/grading/src
COPY services/grader/src services/grader/src
RUN chown -R node:node /workspace

WORKDIR /workspace/services/grader
USER node
EXPOSE 9002
CMD ["node", "src/server.ts"]
