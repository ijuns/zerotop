FROM gcr.io/projectsigstore/cosign/cosign:v3.0.6 AS cosign
FROM anchore/syft:v1.44.0 AS syft
FROM aquasec/trivy:0.72.0 AS trivy
FROM gcr.io/go-containerregistry/crane:v0.20.7 AS crane

FROM node:24.14.0-bookworm-slim

# Build from the repository root. Release tags are inputs to the image pipeline;
# the deployment overlay must replace the resulting image with a digest pin.
ENV NODE_ENV=production PORT=9003
WORKDIR /workspace/services/validator

COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=crane /ko-app/crane /usr/local/bin/crane

COPY services/validator/package.json services/validator/tsconfig.json ./
COPY services/validator/src ./src

RUN groupadd --system --gid 10001 validator \
    && useradd --system --uid 10001 --gid validator --home-dir /nonexistent validator \
    && mkdir -p /var/cache/codegate-validator /tmp/codegate-validator \
    && chown -R validator:validator /workspace /var/cache/codegate-validator /tmp/codegate-validator

USER validator
EXPOSE 9003
CMD ["node", "src/server.ts"]
