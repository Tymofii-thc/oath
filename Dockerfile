# oath: CLI + admission webhook. Runtime deps: sigstore, plus @solana/web3.js for the experimental
# OATH_PROGRAM backend (README: "On-chain records") — included even though most installs don't set
# OATH_PROGRAM, because a webhook that silently can't do what its own documented env var promises is
# worse than a slightly larger image. Without OATH_PROGRAM, it is simply unused at runtime.
FROM node:26-alpine
WORKDIR /oath
COPY package.json package-lock.json ./
# npm itself is not needed at runtime: removing it also removes its bundled (and often outdated) dependencies from the image
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /opt/yarn* /usr/local/bin/yarn*
COPY lib ./lib
COPY bin ./bin
USER 1000:1000
EXPOSE 8443
ENTRYPOINT ["node"]
CMD ["bin/oath-webhook.mjs"]
