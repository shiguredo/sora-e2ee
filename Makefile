VERSION = 2020.2.1

all:
	GOOS=js GOARCH=wasm go build -ldflags='-X main.Version=$(VERSION)' -o dist/wasm.wasm cmd/wasm/main.go

test:
	@PATH=$(shell go env GOROOT)/misc/wasm:$(PATH) GOOS=js GOARCH=wasm go test -ldflags='-X main.Version=$(VERSION)' -cover -coverprofile=coverage.out -covermode=atomic github.com/shiguredo/sora-e2ee/internal/e2ee
	go tool cover -html=coverage.out -o coverage.html

brotli:
	brotli dist/wasm.wasm -o dist/wasm.wasm.br
