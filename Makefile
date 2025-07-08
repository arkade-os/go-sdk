.PHONY: genrest test vet lint migrate sqlc

ark_client_dir = $(or $(REST_DIR),$(PWD)/client/rest/service)
indexer_client_dir = $(or $(REST_DIR),$(PWD)/indexer/rest/service)

GOLANGCI_LINT ?= $(shell \
	if command -v golangci-lint >/dev/null 2>&1; then \
	  echo golangci-lint; \
	else \
	  echo "docker run --rm -v $$(pwd):/app -w /app golangci/golangci-lint:latest golangci-lint"; \
	fi \
)

SWAGGER ?= $(shell \
  if command -v swagger >/dev/null 2>&1; then \
    echo swagger; \
  else \
    echo "docker run --rm \
      -v $$(PWD):/work -w /work \
      quay.io/goswagger/swagger:latest"; \
  fi \
)

proto:
	@echo "Compiling stubs..."
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf generate buf.build/arkade-os/arkd --exclude-path arkwallet/v1/bitcoin_wallet.proto

## genrest: compiles rest client from stub with https://github.com/go-swagger/go-swagger
genrest:
	@echo "Cleaning existing files..."
	@rm -rf $(ark_client_dir) $(indexer_client_dir)
	@echo "Generating rest client from stub..."
	@mkdir -p $(ark_client_dir) $(indexer_client_dir)
	@$(SWAGGER) generate client -f api-spec/openapi/swagger/ark/v1/service.swagger.json -t $(ark_client_dir) --client-package=arkservice
	@$(SWAGGER) generate client -f api-spec/openapi/swagger/ark/v1/indexer.swagger.json -t $(indexer_client_dir) --client-package=indexerservice

## test: runs unit tests
test:
	@echo "Running unit tests..."
	@go test -v -count=1 -race $$(go list ./... | grep -v '/test/wasm')

## vet: code analysis
vet:
	@echo "Running code analysis..."
	@go vet ./...

## lint: lint codebase
lint:
	@echo "Linting code..."
	@$(GOLANGCI_LINT) run --fix

## migrate: creates sqlite migration file(eg. make FILE=init migrate)
migrate:
	@docker run --rm -v ./store/sql/migration:/migration migrate/migrate create -ext sql -dir /migration $(FILE)

## sqlc: gen sql
sqlc:
	@echo "gen sql..."
	@docker run --rm -v ./store/sql:/src -w /src sqlc/sqlc generate