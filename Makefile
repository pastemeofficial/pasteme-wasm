binary_name = pasteme

.PHONY: wasm
wasm:
	GOOS=js GOARCH=wasm go get -t -v
	GOOS=js GOARCH=wasm go build -v -a -gcflags "all=-trimpath=$$PWD;$$HOME" -asmflags "all=-trimpath=$$PWD;$$HOME" -o build/$(binary_name).wasm