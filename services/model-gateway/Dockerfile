# syntax=docker/dockerfile:1.8
ARG NODE_RUNTIME_IMAGE
FROM ${NODE_RUNTIME_IMAGE}

ENV NODE_ENV=production \
    PORT=9010
WORKDIR /opt/codegate/model-gateway
COPY --chown=65532:65532 services/model-gateway/package.json ./package.json
COPY --chown=65532:65532 services/model-gateway/src ./src
USER 65532:65532
EXPOSE 9010
CMD ["node", "src/server.ts"]
