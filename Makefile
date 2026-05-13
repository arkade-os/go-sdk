.PHONY: test vet lint migrate sqlc regtest regtestdown integrationtest smoketest bump-client-lib bump-ark-lib bump-api-spec

GOLANGCI_LINT ?= $(shell \
	echo "docker run --rm -v $$(pwd):/app -w /app golangci/golangci-lint:v2.9.0 golangci-lint"; \
)

COMMIT ?= $(word 2,$(MAKECMDGOALS))

ifneq ($(words $(MAKECMDGOALS)),1)
$(eval $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS)):;@:)
endif

define require_commit
	@if [ -z "$(COMMIT)" ]; then \
		echo "usage: make $@ COMMIT=<git-sha-or-tag>"; \
		echo "   or: make $@ <git-sha-or-tag>"; \
		exit 1; \
	fi
endef

## test: runs unit tests
test:
	@echo "Running unit tests..."
	@go test -v -count=1 -race $$(go list ./... | grep -v '/test/wasm' | grep -v '/test/e2e')

## vet: code analysis
vet:
	@echo "Running code analysis..."
	@go vet $$(go list ./... | grep -v '/\.worktrees/')

## lint: lint codebase
lint:
	@echo "Linting code..."
	@$(GOLANGCI_LINT) run --timeout 5m --fix

## migrate: creates sqlite migration file(eg. make FILE=init migrate)
migrate:
	@docker run --rm -v ./store/sql/migration:/migration migrate/migrate create -ext sql -dir /migration $(FILE)

## sqlc: gen sql
sqlc:
	@echo "gen sql..."
	@docker run --rm -v ./store/sql:/src -w /src sqlc/sqlc generate

regtest:
	@echo "Starting regtest..."
	@docker compose -f test/docker/docker-compose.yml down
	@docker compose -f test/docker/docker-compose.yml up -d --build
	@go run test/docker/setup.go

regtestdown:
	@echo "Stopping regtest..."
	@docker compose -f test/docker/docker-compose.yml down

integrationtest:
	@ARK_ELECTRUM_URL=$${ARK_ELECTRUM_URL:-tcp://127.0.0.1:50001} ARK_ESPLORA_URL=$${ARK_ESPLORA_URL:-http://localhost:5000} go test -v -count=1 -race -timeout 40m ./test/e2e

## smoketest: runs long-running e2e smoke tests (skipped in CI). Smoke
## test files are gated behind the "smoke" build tag and tests follow the
## TestSmoke* naming convention; CI doesn't pass the tag, so they never
## get compiled there.
smoketest:
	@go test -v -count=1 -timeout 60m -tags=smoke -run 'Smoke' ./test/e2e

## bump-client-lib: update client-lib to a specific commit/tag and tidy modules
bump-client-lib:
	$(call require_commit)
	@echo "Bumping client-lib to $(COMMIT)..."
	@go get github.com/arkade-os/arkd/pkg/client-lib@$(COMMIT)
	@go mod tidy

## bump-ark-lib: update ark-lib to a specific commit/tag and tidy modules
bump-ark-lib:
	$(call require_commit)
	@echo "Bumping ark-lib to $(COMMIT)..."
	@go get github.com/arkade-os/arkd/pkg/ark-lib@$(COMMIT)
	@go mod tidy

## bump-api-spec: update api-spec to a specific commit/tag and tidy modules
bump-api-spec:
	$(call require_commit)
	@echo "Bumping api-spec to $(COMMIT)..."
	@go get github.com/arkade-os/arkd/api-spec@$(COMMIT)
	@go mod tidy
