.PHONY: proto test vet lint migrate sqlc bump-client-lib bump-ark-lib

GOLANGCI_LINT ?= $(shell \
		echo "docker run --rm -v $$(pwd):/app -w /app golangci/golangci-lint:v2.9.0 golangci-lint"; \
)

COMMIT ?= $(word 2,$(MAKECMDGOALS))

define require_commit
	@if [ -z "$(COMMIT)" ]; then \
		echo "usage: make $@ COMMIT=<git-sha-or-tag>"; \
		echo "   or: make $@ <git-sha-or-tag>"; \
		exit 1; \
	fi
endef

# Allow positional commit arguments, e.g.:
#   make bump-client-lib <git-sha-or-tag>
%:
	@:

proto:
	@echo "Compiling stubs..."
	@docker build -q -t buf -f buf.Dockerfile . &> /dev/null
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf generate

## test: runs unit tests
test:
	@echo "Running unit tests..."
	@go test -v -count=1 -race $$(go list ./... | grep -v '/test/wasm' | grep -v '/test/e2e')

## vet: code analysis
vet:
	@echo "Running code analysis..."
	@go vet ./...

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

## regtest-full: starts full regtest (arkd + mock-boltz + real Boltz + LN)
up:
	@echo "Starting full regtest with real Boltz..."
	@docker compose -f test/infra/docker-compose.yml down -v
	@docker compose -f test/infra/docker-compose.yml up -d --build
	@bash test/infra/setup_infra.sh

down:
	@echo "Stopping regtest..."
	@docker compose -f test/infra/docker-compose.yml down -v

## balances: show balances for all regtest services
balances:
	@bash test/infra/balances.sh

integrationtest:
	@go test -v -count=1 -race ./test/e2e

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
