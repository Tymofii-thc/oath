# oath: CLI + admission webhook. Runtime dependency: sigstore only. @solana/web3.js is optional and used by the CLI to SEND
# transactions (init, anchor, revoke), never to verify, so the image leaves it out.
FROM node:26-alpine
# fixed OS packages that the base image has not picked up yet (Trivy reported a MEDIUM in zlib on 2026-10-21)
RUN apk upgrade --no-cache
WORKDIR /oath
COPY package.json package-lock.json ./
# npm itself is not needed at runtime: removing it also removes its bundled (and often outdated) dependencies from the image
RUN npm ci --omit=dev --omit=optional --ignore-scripts && npm cache clean --force \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /opt/yarn* /usr/local/bin/yarn*
COPY lib ./lib
COPY bin ./bin
USER 1000:1000
EXPOSE 8443
ENTRYPOINT ["node"]
CMD ["bin/oath-webhook.mjs"]
