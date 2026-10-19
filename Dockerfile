# oath: CLI + admission webhook. Runtime deps: sigstore only (optional web3.js is needed just for anchoring in CI).
FROM node:22-alpine
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
