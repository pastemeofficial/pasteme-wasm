binary_name = pasteme

.PHONY: test wasm release
test:
	go vet ./... && GOOS=js GOARCH=wasm go vet . && go test -race -count=1 ./...

# the module, built reproducibly (no local paths in it)
wasm:
	GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o build/$(binary_name).wasm .

# the Go runtime glue that matches this Go version: copy both into the site (public/pasteme.wasm, public/js/wasm_exec.js)
release: test wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" build/wasm_exec.js
	shasum -a 256 build/$(binary_name).wasm build/wasm_exec.js
