package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"strings"
	"syscall/js"
)

const version = "v0.1"

func main() {
	fmt.Printf("Paste.me WASM module %s initialized\n", version)
	c := make(chan struct{}, 0)
	js.Global().Set("pasteme_encrypt", js.FuncOf(EncryptData))
	js.Global().Set("pasteme_decrypt", js.FuncOf(DecryptData))
	<-c
}

func EncryptData(this js.Value, args []js.Value) interface{} {
	sourceData := args[0].String()

	if len(sourceData) == 0 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide some data to encrypt!",
		})
	}

	rb, err := GenerateRandomBytes(28)

	if err != nil {
		return js.ValueOf(map[string]interface{}{
			"error": "Not enough entropy to generate random bytes!",
		})
	}

	h := sha256.New()
	h.Write(rb)
	passPhrase := hex.EncodeToString(h.Sum(nil))
	encryptText := encrypt(passPhrase, []byte(sourceData))

	return js.ValueOf(map[string]interface{}{
		"encrypted":  encryptText,
		"passPhrase": passPhrase,
	})
}

func DecryptData(this js.Value, args []js.Value) interface{} {
	passPhrase := args[0].String()
	encryptedText := args[1].String()

	if len(passPhrase) == 0 {
		return ""
	}

	if len(encryptedText) == 0 {
		return ""
	}

	return js.ValueOf(map[string]interface{}{
		"decrypt": decrypt(passPhrase, encryptedText),
	})
}

// @SRC: https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb
// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// @SRC: https://gist.github.com/tscholl2/dc7dc15dc132ea70a98e8542fefffa28
func deriveKey(passPhrase string, salt []byte) ([]byte, []byte) {
	if salt == nil {
		salt = make([]byte, 8)
		// http://www.ietf.org/rfc/rfc2898.txt
		// Salt.
		rand.Read(salt)
	}
	return pbkdf2.Key([]byte(passPhrase), salt, 1000, 32, sha256.New), salt
}

// @SRC: https://gist.github.com/tscholl2/dc7dc15dc132ea70a98e8542fefffa28
func encrypt(passphrase string, plaintext []byte) string {
	key, salt := deriveKey(passphrase, nil)
	iv := make([]byte, 12)
	// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	// Section 8.2
	rand.Read(iv)
	b, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(b)
	data := aesgcm.Seal(nil, iv, plaintext, nil)
	return hex.EncodeToString(salt) + "-" + hex.EncodeToString(iv) + "-" + hex.EncodeToString(data)
}

func decrypt(passphrase, ciphertext string) string {
	arr := strings.Split(ciphertext, "-")
	salt, _ := hex.DecodeString(arr[0])
	iv, _ := hex.DecodeString(arr[1])
	data, _ := hex.DecodeString(arr[2])
	key, _ := deriveKey(passphrase, salt)
	b, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(b)
	data, _ = aesgcm.Open(nil, iv, data, nil)
	return string(data)
}
