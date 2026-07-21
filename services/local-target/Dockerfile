FROM node:24.14.0-alpine

ENV NODE_ENV=production HOST=0.0.0.0 PORT=8080
WORKDIR /opt/codegate/local-target

COPY services/local-target/server.mjs ./server.mjs

USER 65532:65532
EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=2s --start-period=3s --retries=12 \
  CMD node -e "fetch('http://127.0.0.1:8080/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

LABEL io.codegate.runtime.contract="http-v1" \
      io.codegate.local-only="true"

CMD ["node", "server.mjs"]
