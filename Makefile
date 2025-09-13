.PHONY: proto genrest test vet lint migrate sqlc

ark_client_dir = $(or $(REST_DIR),client/rest/service)
indexer_client_dir = $(or $(REST_DIR),indexer/rest/service)

GOLANGCI_LINT ?= $(shell \
	echo "docker run --rm -v $$(pwd):/app -w /app golangci/golangci-lint:latest golangci-lint"; \
)

SWAGGER ?= $(shell \
	echo "docker run --rm \
		-v $$(PWD):/work -w /work \
		openapitools/openapi-generator-cli"; \
)

proto:
	@echo "Compiling stubs..."
	@docker build -q -t buf -f buf.Dockerfile . &> /dev/null
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf generate

## genrest: compiles rest client from stub with https://github.com/go-swagger/go-swagger
genrest:
	@if [ "$(CI)" != "true" ]; then \
		$(MAKE) proto; \
	else \
		echo "Skipping proto (CI=true passed)"; \
	fi
	@echo "Cleaning existing files..."
	@rm -rf $(ark_client_dir) $(indexer_client_dir)
	@echo "Generating rest client from stub..."
	@mkdir -p $(ark_client_dir) $(indexer_client_dir)
	@$(SWAGGER) generate -i api-spec/openapi/swagger/ark/v1/service.openapi.json --skip-validate-spec -g go -o $(ark_client_dir) --global-property apis,models,apiDocs=false,apiTests=false,modelDocs=false,modelTests=false,supportingFiles=utils.go:configuration.go:client.go -t .openapi/templates
	@$(SWAGGER) generate -i api-spec/openapi/swagger/ark/v1/indexer.openapi.json --skip-validate-spec -g go -o $(indexer_client_dir) --global-property apis,models,apiDocs=false,apiTests=false,modelDocs=false,modelTests=false,supportingFiles=utils.go:configuration.go:client.go

## test: runs unit tests
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