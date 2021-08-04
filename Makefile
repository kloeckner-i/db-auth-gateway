BIN = target/db-auth-gateway
SRC = $(shell find . -type f -name '*.go')

$(BIN): $(SRC)
	@mkdir -p target
	@go build -o $@ cmd/main.go

test: $(SRC) reset_mock
	@go test ./...

e2e: $(SRC) $(BIN) reset_mock
	@go test -tags=e2e ./test/...

start_mock: $(SRC)
	@-docker-compose down
	@docker-compose build
	@docker-compose up -d

reset_mock:
	@docker-compose stop mock
	@docker-compose rm -f -v mock
	@docker-compose up -d
	@sleep 2

lint: $(SRC)
	@go mod tidy
	@gofumpt -s -l -w $^
	@gci -w $^
	@golangci-lint run --timeout 5m0s --enable-all \
		-D gochecknoglobals -D exhaustivestruct -D wrapcheck -D interfacer -D maligned -D scopelint -D golint -D gomnd -D paralleltest ./...

clean:
	@-rm -Rf target/*
	@go clean -testcache
	@-docker-compose down

.PHONY: test e2e start_mock reset_mock lint clean
