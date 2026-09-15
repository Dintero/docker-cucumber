ARG DOCKER_REGISTRY=registry-1.docker.io
FROM ${DOCKER_REGISTRY}/library/node:24.14.0-alpine3.22 AS builder
WORKDIR /usr/src
COPY package.json yarn.lock ./
RUN --mount=type=cache,target=/root/yarn/.cache/yarn \
    yarn --silent install --frozen-lockfile --ignore-scripts

FROM ${DOCKER_REGISTRY}/library/node:24.14.0-alpine3.22
WORKDIR /usr/src
COPY --from=builder /usr/src/node_modules ./node_modules
# Install dintero-e2e helpers (har-capture, ...) as a node package so
# consumers can `import { harFetch } from "@dintero/e2e-helpers"`.
# Source files are TypeScript; tsx handles them at runtime via the
# `--import tsx` ENTRYPOINT flag.
COPY helpers ./node_modules/@dintero/e2e-helpers
# Register dintero-zap + dintero-zap-to-asff on PATH. Mirrors what pip
# does for the Python sibling image via [project.scripts]. Shell shims
# execute the TS entry points through tsx (same loader as cucumber-js).
RUN printf '#!/bin/sh\nexec node --import tsx /usr/src/node_modules/@dintero/e2e-helpers/src/zap/cli.ts "$@"\n' \
        > /usr/local/bin/dintero-zap && \
    printf '#!/bin/sh\nexec node --import tsx /usr/src/node_modules/@dintero/e2e-helpers/src/zap/to-asff-cli.ts "$@"\n' \
        > /usr/local/bin/dintero-zap-to-asff && \
    chmod +x /usr/local/bin/dintero-zap /usr/local/bin/dintero-zap-to-asff
COPY package.json yarn.lock ./

WORKDIR /usr/src/app
ENTRYPOINT ["node", "--import", "tsx", "/usr/src/node_modules/.bin/cucumber-js"]
