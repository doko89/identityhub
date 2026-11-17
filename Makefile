# IdentityHub — single binary + embedded SPA (see README.md).
# Targets mirror the README "Checks" section; `make check` is the merge gate.
# Config comes from .env (copy .env.example first); see `make setup`.

GO ?= go
NPM ?= npm
BINARY := bin/identityhub

TEST_DATABASE_URL ?= postgres://postgres:postgres@localhost:5434/identityhub
PLAYWRIGHT_BASE_URL ?= http://localhost:8080

-include .env
export

.DEFAULT_GOAL := help

.PHONY: help setup db db-stop db-test build web-install web-build serve worker
.PHONY: migrate migrate-down migrate-status create-admin
.PHONY: vet fmt fmt-write test test-cover test-integration
.PHONY: test-web test-e2e check clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

setup: ## First-time setup: .env, npm deps, dev database
	test -f .env || cp .env.example .env
	cd web && $(NPM) ci
	$(MAKE) db

db: ## Start the dev Postgres (docker, port 5432)
	docker start identityhub-pg 2>/dev/null || docker run -d --name identityhub-pg \
		-e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
		-e POSTGRES_DB=identityhub -p 5432:5432 postgres:16-alpine

db-stop: ## Stop the dev Postgres
	docker stop identityhub-pg 2>/dev/null || true

db-test: ## Start the integration-test Postgres (docker, port 5434)
	docker start identityhub-pg-test 2>/dev/null || docker run -d --name identityhub-pg-test \
		-e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
		-e POSTGRES_DB=identityhub -p 5434:5432 postgres:16-alpine

build: web-build ## Build web/dist + the Go binary into bin/
	$(GO) build -o $(BINARY) ./cmd/identityhub

web-install: ## Install frontend dependencies
	cd web && $(NPM) ci

web-build: ## Production SPA build (embedded via go:embed)
	cd web && $(NPM) run build

serve: ## Run the server (HTTP + LDAP/RADIUS; needs .env)
	$(GO) run ./cmd/identityhub serve

worker: ## Run background jobs (needs .env)
	$(GO) run ./cmd/identityhub worker

migrate: ## Migrate the database up (needs .env)
	$(GO) run ./cmd/identityhub migrate up

migrate-down: ## Migrate the database down one step (needs .env)
	$(GO) run ./cmd/identityhub migrate down

migrate-status: ## Show migration status (needs .env)
	$(GO) run ./cmd/identityhub migrate status

create-admin: ## Bootstrap the first admin, e.g. make create-admin ARGS="--username root"
	$(GO) run ./cmd/identityhub create-admin $(ARGS)

vet: ## go vet over everything
	$(GO) vet ./...

fmt: ## Fail if gofmt would reformat cmd/ or internal/
	test -z "$$(gofmt -l cmd internal)"

fmt-write: ## Apply gofmt to cmd/ and internal/
	gofmt -w cmd internal

test: ## Go unit tests
	$(GO) test ./...

test-cover: ## Usecase coverage (merge gate: each package >= 85%)
	$(GO) test -coverprofile=coverage.out ./internal/usecase/... && $(GO) tool cover -func=coverage.out

test-integration: db-test ## Integration tests against real Postgres (port 5434)
	TEST_DATABASE_URL="$(TEST_DATABASE_URL)" $(GO) test -tags=integration ./...

test-web: ## Frontend gates: typecheck + lint + unit tests
	cd web && $(NPM) run typecheck && $(NPM) run lint && $(NPM) test

test-e2e: ## Playwright e2e against a live server (needs TEST_E2E_USER/PASSWORD)
	cd web && PLAYWRIGHT_BASE_URL="$(PLAYWRIGHT_BASE_URL)" $(NPM) run test:e2e

check: fmt vet test test-web ## Full merge gate (no database needed)
	$(GO) test -cover ./internal/usecase/...

clean: ## Remove build outputs (bin/, coverage; web/dist is kept as fallback)
	rm -rf bin coverage.out coverage.html
