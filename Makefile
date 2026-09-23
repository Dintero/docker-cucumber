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

# Runs cucumber against the httpstatus example, then feeds the captured
# HAR into a ZAP daemon and produces .zap/junit.xml. Exercises the full
# dintero-zap pipeline (wait/import-har/drain-passive/dump/to-junit)
# end-to-end. `docker compose down` at the end reaps zap-proxy +
# httpstatus so we don't leak them across runs.
.PHONY: test
test:
	rm -rf example/.zap
	docker compose $(COMPOSE_DEFAULT_FLAGS) run --service-ports --rm end-to-end-tests
	docker compose $(COMPOSE_DEFAULT_FLAGS) run --rm zap-scan
	docker compose $(COMPOSE_DEFAULT_FLAGS) down

publish: build
	docker buildx build --platform $(PLATFORMS) --tag $(TAG) $(LABELS) $(BUILDX_CACHE_ARGS) --push .

install: build test
