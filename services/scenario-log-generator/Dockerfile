FROM node:24.14.0-alpine

ENV NODE_ENV=production \
    SCENARIO_LOG_PATH=/var/log/zerotop/scenario.ndjson

WORKDIR /opt/zerotop/scenario-log-generator

COPY services/scenario-log-generator/src/server.mjs ./server.mjs
COPY services/api/src/blue-telemetry.ts ./blue-telemetry.ts

RUN mkdir -p /var/log/zerotop \
    && chown -R 65532:65532 /opt/zerotop/scenario-log-generator /var/log/zerotop

USER 65532:65532

HEALTHCHECK --interval=2s --timeout=2s --retries=30 \
  CMD test -s "$SCENARIO_LOG_PATH"

LABEL ai.zerotop.runtime.role="scenario-log-generator" \
      ai.zerotop.local-only="true"

CMD ["node", "server.mjs"]
