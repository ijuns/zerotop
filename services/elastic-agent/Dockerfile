FROM node:24.14.0-alpine

ENV NODE_ENV=production \
    ELASTICSEARCH_HOST=http://elasticsearch:9200 \
    KIBANA_HOST=http://kibana:5601 \
    ELASTIC_INDEX=zerotop-logs \
    SCENARIO_LOG_PATH=/var/log/zerotop/scenario.ndjson

WORKDIR /opt/zerotop/elastic-agent

COPY services/elastic-agent/src/agent.mjs ./agent.mjs

RUN chown -R 65532:65532 /opt/zerotop/elastic-agent

USER 65532:65532

HEALTHCHECK --interval=3s --timeout=2s --start-period=10s --retries=60 \
  CMD test -f /tmp/zerotop-agent-ready

LABEL ai.zerotop.runtime.role="elastic-agent" \
      ai.zerotop.local-only="true" \
      ai.zerotop.collector.contract="ecs-ndjson-to-elasticsearch-v1"

CMD ["node", "agent.mjs"]
