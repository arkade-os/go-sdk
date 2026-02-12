.PHONY: proto test vet lint migrate sqlc

GOLANGCI_LINT ?= $(shell \
	echo "docker run --rm -v $$(pwd):/app -w /app golangci/golangci-lint:v2.5.0 golangci-lint"; \
)

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
	@$(GOLANGCI_LINT) run --timeout 5m

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
	@go test -v -count=1 -race ./test/e2e