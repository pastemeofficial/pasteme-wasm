package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"strings"
	"syscall/js"
)

const version = "v0.2.1"

func main() {
	fmt.Printf("Paste.me WASM module %s initialized\n", version)
	c := make(chan struct{}, 0)
	js.Global().Set("pasteme_encrypt", js.FuncOf(EncryptData))
	js.Global().Set("pasteme_encryptFile", js.FuncOf(EncryptBinaryData))
	js.Global().Set("pasteme_decrypt", js.FuncOf(DecryptData))
	js.Global().Set("pasteme_decryptFile", js.FuncOf(DecryptBinaryData))
	js.Global().Set("pasteme_passphrase", js.FuncOf(GeneratePassPhrase))
	js.Global().Set("pasteme_hashPassword", js.FuncOf(HashPassword))
	js.Global().Set("pasteme_compareHashAndPassword", js.FuncOf(CompareHashAndPassword))
	<-c
}

func GeneratePassPhrase(this js.Value, args []js.Value) interface{} {
	rb, err := GenerateRandomBytes(28)

	if err != nil {
		return js.ValueOf(map[string]interface{}{
			"error": "Not enough entropy to generate random bytes!",
		})
	}

	h := sha256.New()
	h.Write(rb)
	passPhrase := hex.EncodeToString(h.Sum(nil))

	return js.ValueOf(map[string]interface{}{
		"passPhrase": passPhrase,
	})
}

func EncryptBinaryData(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide some data to encrypt!",
		})
	}

	// sourceData contains 1 file mostly
	sourceData := args[0]

	fileData := make([]byte, args[0].Length())
	js.CopyBytesToGo(fileData, sourceData)

	passPhrase := args[1].String()

	if len(passPhrase) == 0 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide a passphrase!",
		})
	}

	encryptText := encrypt(passPhrase, fileData)

	return js.ValueOf(map[string]interface{}{
		"encrypted": encryptText,
	})
}

func DecryptBinaryData(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide a passphrase and encrypted data to decrypt!",
		})
	}

	passPhrase := args[0].String()
	encryptedText := args[1].String()

	if len(passPhrase) == 0 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide a passphrase!",
		})
	}

	if len(encryptedText) == 0 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide an encrypted HEX string!",
		})
	}
	decryptedFile := decrypt(passPhrase, encryptedText)
	dst := js.Global().Get("Uint8Array").New(len(decryptedFile))

	js.CopyBytesToJS(dst, decryptedFile)

	return js.ValueOf(map[string]interface{}{
		"decrypt": dst,
	})
}

func EncryptData(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide some data to encrypt!",
		})
	}

	sourceData := args[0].String()

	if len(sourceData) == 0 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide some data to encrypt!",
		})
	}

	passPhrase := args[1].String()

	if len(passPhrase) == 0 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide a passphrase!",
		})
	}

	encryptText := encrypt(passPhrase, []byte(sourceData))

	return js.ValueOf(map[string]interface{}{
		"encrypted": encryptText,
	})
}

func DecryptData(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide a passphrase and encrypted data to decrypt!",
		})
	}

	passPhrase := args[0].String()
	encryptedText := args[1].String()

	if len(passPhrase) == 0 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide a passphrase!",
		})
	}

	if len(encryptedText) == 0 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide an encrypted HEX string!",
		})
	}

	return js.ValueOf(map[string]interface{}{
		"decrypt": string(decrypt(passPhrase, encryptedText)),
	})
}

func HashPassword(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide a password that you need to hash!",
		})
	}

	password := args[0].String()

	if len(password) == 0 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide a password!",
		})
	}

	// Hashing the password with the default cost of 10
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return js.ValueOf(map[string]interface{}{
			"error": "There was an error while hashing the password! Please try again!",
		})
	}

	return js.ValueOf(map[string]interface{}{
		"hashedPassword": string(hashedPassword),
	})
}

func CompareHashAndPassword(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide a hash and a password to compare!",
		})
	}

	hash := args[0].String()

	if len(hash) == 0 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide a hash!",
		})
	}

	password := args[1].String()

	if len(password) == 0 {
		return js.ValueOf(map[string]interface{}{
			"error": "Please provide a password!",
		})
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	if err != nil {
		return js.ValueOf(map[string]interface{}{
			"error": "The hash and password do not match!",
			"valid": false,
		})
	}

	return js.ValueOf(map[string]interface{}{
		"valid": true,
	})
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
// @SRC: https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb
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

func decrypt(passphrase, ciphertext string) []byte {
	arr := strings.Split(ciphertext, "-")
	salt, _ := hex.DecodeString(arr[0])
	iv, _ := hex.DecodeString(arr[1])
	data, _ := hex.DecodeString(arr[2])
	key, _ := deriveKey(passphrase, salt)
	b, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(b)
	data, _ = aesgcm.Open(nil, iv, data, nil)

	return data
}
