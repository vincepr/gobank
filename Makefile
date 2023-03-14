import:
	@go mod tidy

build:
	@go build -o bin/gobank

run: import build
	@./bin/gobank

test:
	@go test -v ./...

