FROM node:24.14.0-bookworm-slim

# Build from the repository root:
# docker build -f services/openvpn-issuer/Dockerfile .
ENV NODE_ENV=production ISSUER_PORT=9100 OPENVPN_RUNTIME_DIR=/run/openvpn
WORKDIR /workspace
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iptables openvpn openssl tini \
    && rm -rf /var/lib/apt/lists/* \
    && corepack enable \
    && corepack prepare pnpm@11.9.0 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY services/openvpn-issuer/package.json services/openvpn-issuer/package.json
RUN pnpm install --frozen-lockfile --filter @codegate/openvpn-issuer... --prod

COPY services/openvpn-issuer/src services/openvpn-issuer/src
COPY services/openvpn-issuer/migrations services/openvpn-issuer/migrations
RUN mkdir -p /run/openvpn \
    && chown -R 10001:10001 /workspace /run/openvpn

WORKDIR /workspace/services/openvpn-issuer
EXPOSE 9100/tcp 1194/udp
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "src/index.ts"]
