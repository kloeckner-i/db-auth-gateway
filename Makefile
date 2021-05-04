BIN = target/db-auth-gateway
SRC = $(shell find . -type f -name '*.go')

$(BIN): $(SRC)
	@mkdir -p target
	@go build -o $@ cmd/main.go

test: $(SRC)
	@go test ./...

e2e: $(SRC) $(BIN)
	@go test -tags=e2e ./test/...

start_mock: $(SRC)
	@-docker-compose down
	@docker-compose build
	@docker-compose up -d

lint: $(SRC)
	@go mod tidy
	@gofumpt -s -l -w $^
	@gci -w $^
	@golint ./...
	@golangci-lint run --timeout 5m0s --enable-all -D gochecknoglobals -D gomnd ./...

clean:
	@-rm -Rf target/*
	@go clean -testcache
	@-docker-compose down

.PHONY: test e2e start_mock lint clean
