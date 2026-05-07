.PHONY: proto test vet lint migrate sqlc regtest regtestdown regtestclean bump-regtest

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
	@./regtest/start-env.sh

regtestdown:
	@echo "Stopping regtest..."
	@./regtest/stop-env.sh

regtestclean:
	@echo "Cleaning regtest..."
	@./regtest/clean-env.sh

## bump-regtest: update the arkade-regtest submodule to its latest remote commit
bump-regtest:
	@echo "Bumping arkade-regtest submodule..."
	@git submodule update --remote --merge regtest
	@echo "arkade-regtest updated to $$(git -C regtest rev-parse HEAD)"
	@echo "Review changes in regtest/ and .env.regtest, then commit with:"
	@echo "  git add regtest && git commit -m 'chore: bump arkade-regtest submodule'"

integrationtest:
	@go test -v -count=1 -race -timeout 40m ./test/e2e

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

## bump-ark-spec: update api-spec to a specific commit/tag and tidy modules
bump-ark-spec:
	$(call require_commit)
	@echo "Bumping api-spec to $(COMMIT)..."
	@go get github.com/arkade-os/arkd/api-spec@$(COMMIT)
	@go mod tidy
