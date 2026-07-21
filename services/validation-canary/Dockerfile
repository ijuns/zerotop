FROM node:24.14.0-alpine

# Build from the repository root:
# docker build -f services/validation-canary/Dockerfile .
ENV NODE_ENV=production PORT=8080
WORKDIR /workspace/services/validation-canary

COPY services/validation-canary/package.json services/validation-canary/tsconfig.json ./
COPY services/validation-canary/src ./src

USER node
EXPOSE 8080
CMD ["node", "src/index.ts"]
