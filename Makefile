.DEFAULT_GOAL := help
COMPOSE := docker compose
SPEED ?= 1
TENANT ?= default

.PHONY: help build up up-fg down down-v restart logs ps test test-unit fetch replay shell-api smoketest-fresh ui-review rules fmt

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## Build the backend image
	$(COMPOSE) build

up: ## Start the full stack (detached, builds if needed)
	$(COMPOSE) up -d --build

up-fg: ## Start the full stack in the foreground
	$(COMPOSE) up --build

down: ## Stop the stack
	$(COMPOSE) down

down-v: ## Stop the stack AND wipe all volumes (fresh slate)
	$(COMPOSE) down -v

restart: ## Restart api + worker
	$(COMPOSE) restart api worker

logs: ## Tail logs for all services
	$(COMPOSE) logs -f

ps: ## Show service status
	$(COMPOSE) ps

test: ## Run the full backend test suite in Docker (with datastores up)
	$(COMPOSE) build api
	$(COMPOSE) run --rm api pytest

test-unit: ## Run only fast unit tests (no datastores needed)
	$(COMPOSE) build api
	$(COMPOSE) run --rm --no-deps api pytest -m "not integration"

fetch: ## Download public attack datasets (checksum-verified)
	$(COMPOSE) run --rm api sentinel datasets fetch

replay: ## Replay the TeamPCP supply-chain attack (override: make replay SPEED=6 TENANT=demo)
	$(COMPOSE) run --rm api sentinel attack replay teampcp --speed $(SPEED) --tenant $(TENANT)

shell-api: ## Open a shell in a one-off api container
	$(COMPOSE) run --rm api bash

smoketest-fresh: ## SC2 — fresh slate, no API keys, full replay end-to-end + assert
	bash scripts/smoketest_fresh.sh

ui-review: ## Run the dashboard verification stories (needs the stack up)
	@echo "Run /ui-review in Claude Code (discovers verification/stories.yaml)"

rules: ## List loaded detection rules
	$(COMPOSE) run --rm --no-deps api sentinel rules list

fmt: ## Format/lint backend (ruff)
	$(COMPOSE) run --rm --no-deps api sh -c "pip install -q ruff && ruff check --fix sentinel && ruff format sentinel"
