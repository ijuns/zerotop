FROM node:24.14.0-alpine

# Build from the repository root:
# docker build -f services/runtime/Dockerfile .
WORKDIR /workspace/services/runtime
COPY services/runtime/package.json services/runtime/tsconfig.json ./
COPY services/runtime/src ./src

ENV NODE_ENV=production PORT=9000 RUNTIME_MODE=kubevirt
USER node
EXPOSE 9000
CMD ["node", "src/server.ts"]
