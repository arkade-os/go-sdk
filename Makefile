.PHONY: test vet lint migrate sqlc regtest regtestdown integrationtest integrationtest-swap integrationtest-swap-core integrationtest-wallet integrationtest-tx-exit integrationtest-assets-hd integrationtest-vhtlc integrationtest-stress smokehd bump-client-lib bump-ark-lib bump-api-spec

GOLANGCI_LINT ?= $(shell \
	echo "docker run --rm -v $$(pwd):/app -w /app golangci/golangci-lint:v2.9.0 golangci-lint"; \
)
E2E_TEST ?= go test -v -count=1 -race -timeout 20m

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
	@echo "Starting full regtest (with solver, emulator, boltz)..."
	@bash test/infra/setup.sh

regtestdown:
	@echo "Stopping regtest..."
	@docker compose -f test/infra/docker-compose.yml down -v

integrationtest:
	@go test -v -count=1 -race -timeout 40m ./test/e2e

integrationtest-swap:
	@go test -v -count=1 -timeout 10m -run '^(TestChainSwapArkToBtc|TestChainSwapBtcToArk|TestSubmarineSwap|TestReverseSwap|TestVHTLCClaimDirect|TestVHTLCClaimWithOutpoint|TestVHTLCClaimOldestVtxo|TestRefundSwap)$$' ./test/e2e

integrationtest-swap-core:
	@$(E2E_TEST) -run '^(TestChainSwap.*|TestSubmarineSwap|TestReverseSwap|TestMockBoltzAdminConfig|TestCircularSwap|TestRefundSwap)$$' ./test/e2e

integrationtest-wallet:
	@$(E2E_TEST) -run '^(TestAutoSettle|TestBalance|TestBatchSession|TestTransactionHistory)$$' ./test/e2e

integrationtest-tx-exit:
	@$(E2E_TEST) -run '^(TestOffchainTx|TestCollaborativeExit|TestUnilateralExit|TestSettleAfterRBFBumpFee)$$' ./test/e2e

integrationtest-assets-hd:
	@$(E2E_TEST) -run '^(TestAsset.*|TestProveDustAmountAddedByDefault|TestHDWallet.*|TestE2EVtxoPagination|TestCustomContractHandlerRegistered)$$' ./test/e2e

integrationtest-vhtlc:
	@$(E2E_TEST) -run '^(TestVHTLC.*|TestNonInteractiveClaim)$$' ./test/e2e

integrationtest-stress:
	@$(E2E_TEST) -run '^(TestConcurrentSwaps)$$' ./test/e2e

## smokehd: runs the HD wallet restore smoke test. Optional:
## SMOKE_TIER=N (1-999) | Nk (thousands) | Nm (millions), defaults to 1k.
smokehd:
	@go test -v -count=1 -timeout 300m -tags=smoke -run '^TestSmokeHDWalletRestoreAtScale$$' ./test/e2e

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
