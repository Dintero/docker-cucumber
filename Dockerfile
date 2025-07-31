FROM node:22.12.0-alpine3.20
WORKDIR /usr/src
COPY *.json yarn.lock ./
RUN --mount=type=cache,target=/root/yarn/.cache/yarn \
    yarn install --frozen-lockfile ;

WORKDIR /usr/src/app
ENV PATH="/usr/src/node_modules/.bin:$PATH"
ENTRYPOINT ["cucumber-js", "--require-module", "ts-node/register"]
