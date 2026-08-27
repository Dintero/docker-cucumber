ARG DOCKER_REGISTRY=registry-1.docker.io
FROM ${DOCKER_REGISTRY}/library/node:24.14.0-alpine3.22 AS builder
WORKDIR /usr/src
COPY package.json yarn.lock ./
RUN --mount=type=cache,target=/root/yarn/.cache/yarn \
    yarn --silent install --frozen-lockfile --ignore-scripts

FROM ${DOCKER_REGISTRY}/library/node:24.14.0-alpine3.22
WORKDIR /usr/src
COPY --from=builder /usr/src/node_modules ./node_modules
COPY package.json yarn.lock ./

WORKDIR /usr/src/app
ENTRYPOINT ["node", "--import", "tsx", "/usr/src/node_modules/.bin/cucumber-js"]
