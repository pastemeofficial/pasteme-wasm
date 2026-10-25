//go:build js && wasm

// Command pasteme-wasm exposes the paste.me cryptography to the page. The functions keep their names and result
// keys; every call is wrapped so a bad argument returns {error: "..."} and can never stop the Go runtime.
package main

import (
	"fmt"
	"syscall/js"

	"github.com/0x111/pasteme-wasm/internal/pwcrypto"
)

const version = "v0.3.0"

func main() {
	fmt.Printf("Paste.me WASM module %s initialized\n", version)
	c := make(chan struct{})
	js.Global().Set("pasteme_encrypt", safe(encryptText))
	js.Global().Set("pasteme_encryptFile", safe(encryptFile))
	js.Global().Set("pasteme_decrypt", safe(decryptText))
	js.Global().Set("pasteme_decryptFile", safe(decryptFile))
	js.Global().Set("pasteme_passphrase", safe(passphrase))
	js.Global().Set("pasteme_hashPassword", safe(hashPassword))
	js.Global().Set("pasteme_compareHashAndPassword", safe(comparePassword))
	js.Global().Set("pasteme_version", version)
	<-c
}

type result = map[string]interface{}

func fail(msg string) interface{} { return js.ValueOf(result{"error": msg}) }

// safe turns a panic into an error result: one bad call must not kill the module for the rest of the page's life.
func safe(f func(args []js.Value) interface{}) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) (out interface{}) {
		defer func() {
			if r := recover(); r != nil {
				out = fail("Unexpected error in the encryption module!")
			}
		}()
		return f(args)
	})
}

func isString(v js.Value) bool { return v.Type() == js.TypeString }

func passphrase(args []js.Value) interface{} {
	p, err := pwcrypto.GeneratePassphrase()
	if err != nil {
		return fail("Not enough entropy to generate random bytes!")
	}
	return js.ValueOf(result{"passPhrase": p})
}

func encryptText(args []js.Value) interface{} {
	if len(args) < 2 || !isString(args[0]) || !isString(args[1]) || args[0].String() == "" {
		return fail("Please provide some data to encrypt!")
	}
	if args[1].String() == "" {
		return fail("Please provide a passphrase!")
	}
	enc, err := pwcrypto.Encrypt(args[1].String(), []byte(args[0].String()))
	if err != nil {
		return fail("Encryption failed!")
	}
	return js.ValueOf(result{"encrypted": enc})
}

func encryptFile(args []js.Value) interface{} {
	if len(args) < 2 || args[0].Type() != js.TypeObject || args[0].Get("length").Type() != js.TypeNumber {
		return fail("Please provide some data to encrypt!")
	}
	if !isString(args[1]) || args[1].String() == "" {
		return fail("Please provide a passphrase!")
	}
	data := make([]byte, args[0].Length())
	js.CopyBytesToGo(data, args[0])
	enc, err := pwcrypto.Encrypt(args[1].String(), data)
	if err != nil {
		return fail("Encryption failed!")
	}
	return js.ValueOf(result{"encrypted": enc})
}

func decryptText(args []js.Value) interface{} {
	plain, errMsg := decryptArgs(args)
	if errMsg != "" {
		return fail(errMsg)
	}
	return js.ValueOf(result{"decrypt": string(plain)})
}

func decryptFile(args []js.Value) interface{} {
	plain, errMsg := decryptArgs(args)
	if errMsg != "" {
		return fail(errMsg)
	}
	dst := js.Global().Get("Uint8Array").New(len(plain))
	js.CopyBytesToJS(dst, plain)
	return js.ValueOf(result{"decrypt": dst})
}

func decryptArgs(args []js.Value) ([]byte, string) {
	if len(args) < 2 || !isString(args[0]) || !isString(args[1]) {
		return nil, "Please provide a passphrase and encrypted data to decrypt!"
	}
	if args[0].String() == "" {
		return nil, "Please provide a passphrase!"
	}
	if args[1].String() == "" {
		return nil, "Please provide an encrypted HEX string!"
	}
	plain, err := pwcrypto.Decrypt(args[0].String(), args[1].String())
	if err != nil {
		return nil, "Could not decrypt: " + err.Error()
	}
	return plain, ""
}

func hashPassword(args []js.Value) interface{} {
	if len(args) < 1 || !isString(args[0]) || args[0].String() == "" {
		return fail("Please provide a password!")
	}
	h, err := pwcrypto.HashPassword(args[0].String())
	if err == pwcrypto.ErrPasswordTooLong {
		return fail("The password is too long (72 bytes at most)!")
	}
	if err != nil {
		return fail("There was an error while hashing the password! Please try again!")
	}
	return js.ValueOf(result{"hashedPassword": h})
}

func comparePassword(args []js.Value) interface{} {
	if len(args) < 2 || !isString(args[0]) || !isString(args[1]) || args[0].String() == "" || args[1].String() == "" {
		return fail("Please provide a hash and a password to compare!")
	}
	if err := pwcrypto.ComparePassword(args[0].String(), args[1].String()); err != nil {
		return js.ValueOf(result{"error": "The hash and password do not match!", "valid": false})
	}
	return js.ValueOf(result{"valid": true})
}
