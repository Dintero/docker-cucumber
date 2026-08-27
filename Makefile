COMPOSE_COMMANDS=down build
COMPOSE_DEFAULT_FLAGS=-f example/docker-compose.yml
REPOSITORY ?= dintero/docker-cucumber
TAG ?= $(REPOSITORY):latest
PLATFORMS ?= linux/amd64,linux/arm64
DOCKER_BUILDKIT ?= 1
BUILDX_CACHE_ARGS ?=
SOURCE_URL ?= https://github.com/Dintero/docker-cucumber
GIT_REVISION := $(shell git rev-parse HEAD)
LABELS ?= \
	--label org.opencontainers.image.source=$(SOURCE_URL) \
	--label org.opencontainers.image.revision=$(GIT_REVISION)

build:
	docker buildx build --platform $(PLATFORMS) --tag $(TAG) $(LABELS) $(BUILDX_CACHE_ARGS) .

.PHONY: down
down:
	docker compose $(COMPOSE_DEFAULT_FLAGS) $@

test:
	docker compose $(COMPOSE_DEFAULT_FLAGS) run --service-ports --rm end-to-end-tests

publish: build
	docker buildx build --platform $(PLATFORMS) --tag $(TAG) $(LABELS) $(BUILDX_CACHE_ARGS) --push .

install: build test
