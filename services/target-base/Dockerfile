# syntax=docker/dockerfile:1.8

# Release builds must supply a digest-pinned Node 24 Linux image, for example:
#   --build-arg NODE_RUNTIME_IMAGE=node@sha256:<verified-multi-arch-digest>
# There is deliberately no mutable default.
ARG NODE_RUNTIME_IMAGE
FROM ${NODE_RUNTIME_IMAGE}

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080 \
    CODEGATE_PACKAGE_ROOT=/opt/codegate/packages \
    CODEGATE_ARTIFACT_ROOT=/opt/codegate/artifacts \
    CODEGATE_COMPONENT_POLICY_PATH=/opt/codegate/component-policy.json

WORKDIR /opt/codegate/target

COPY --chown=65532:65532 services/target-base/src/server.mjs ./server.mjs
COPY --chown=65532:65532 services/target-base/src/component-worker.mjs ./component-worker.mjs
COPY --chown=65532:65532 services/target-base/component.schema.json ./component.schema.json

RUN mkdir -p /opt/codegate/packages /opt/codegate/artifacts \
    && chown -R 65532:65532 /opt/codegate

USER 65532:65532
EXPOSE 8080

LABEL io.codegate.runtime.contract="http-v1" \
      io.codegate.runtime.contract.digest="sha256:0a151d0919b035679822ac54c24a467153b70fbe1110cd10e054ffaf774579ec" \
      io.codegate.runtime.uid="65532" \
      io.codegate.runtime.port="8080"

CMD ["node", "/opt/codegate/target/server.mjs"]
