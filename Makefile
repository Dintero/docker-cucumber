TAG ?= dintero/docker-cucumber
COMPOSE_COMMANDS=down build

COMPOSE_DEFAULT_FLAGS=-f example/docker-compose.yml
DOCKER_BUILDKIT ?= 1
PLATFORMS ?= linux/amd64,linux/arm64

build:
	@docker buildx build --platform $(PLATFORMS) --tag $(TAG) .

.PHONY: down
down:
	docker compose $(COMPOSE_DEFAULT_FLAGS) $@

test:
	docker compose $(COMPOSE_DEFAULT_FLAGS) run --service-ports --rm end-to-end-tests

publish: build
	@docker buildx build --platform $(PLATFORMS) --tag $(TAG) --push .

install: build test
