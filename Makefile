all:
	GOOS=js GOARCH=wasm go build -o wasm.wasm cmd/wasm/main.go

test:
	@PATH=$(shell go env GOROOT)/misc/wasm:$(PATH) GOOS=js GOARCH=wasm go test github.com/shiguredo/sora-e2ee-go/internal/e2ee

brotli:
	brotli wasm.wasm
