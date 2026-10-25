// Package pwcrypto is the cryptography of paste.me. It has no browser dependency, so it is tested natively;
// main.go exposes it to the page.
//
// Format (unchanged since v0.1, every existing paste depends on it): "salt-iv-data", each part hex.
// The key is PBKDF2-HMAC-SHA256 (1000 rounds, 32 bytes) of the passphrase and an 8 byte random salt; the data is
// AES-256-GCM with a random 12 byte IV. The passphrase is 224 random bits (hashed to 64 hex characters) that never
// leaves the browser (it lives in the URL fragment), so the low round count does not weaken it.
package pwcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize   = 8
	ivSize     = 12
	kdfRounds  = 1000
	keySize    = 32
	maxBcrypt  = 72 // bcrypt only uses the first 72 bytes of a password
	passRandom = 28
)

// Errors a caller may show.
var (
	ErrEmptyPassphrase = errors.New("empty passphrase")
	ErrMalformed       = errors.New("malformed encrypted data")
	ErrDecrypt         = errors.New("wrong passphrase or damaged data")
	ErrPasswordTooLong = errors.New("password is longer than 72 bytes")
	ErrEmptyPassword   = errors.New("empty password")
)

func deriveKey(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, kdfRounds, keySize, sha256.New)
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// Encrypt returns "salt-iv-data".
func Encrypt(passphrase string, plaintext []byte) (string, error) {
	if passphrase == "" {
		return "", ErrEmptyPassphrase
	}
	salt := make([]byte, saltSize)
	iv := make([]byte, ivSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	aead, err := gcm(deriveKey(passphrase, salt))
	if err != nil {
		return "", err
	}
	data := aead.Seal(nil, iv, plaintext, nil)
	return hex.EncodeToString(salt) + "-" + hex.EncodeToString(iv) + "-" + hex.EncodeToString(data), nil
}

// Decrypt reverses Encrypt. A wrong passphrase or any change to the data is an error, never an empty result.
func Decrypt(passphrase, ciphertext string) ([]byte, error) {
	if passphrase == "" {
		return nil, ErrEmptyPassphrase
	}
	parts := strings.Split(ciphertext, "-")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	salt, err1 := hex.DecodeString(parts[0])
	iv, err2 := hex.DecodeString(parts[1])
	data, err3 := hex.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || len(salt) == 0 || len(iv) != ivSize || len(data) < 16 {
		return nil, ErrMalformed
	}
	aead, err := gcm(deriveKey(passphrase, salt))
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, iv, data, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

// GeneratePassphrase returns 64 hex characters from 28 random bytes.
func GeneratePassphrase() (string, error) {
	rb := make([]byte, passRandom)
	if _, err := rand.Read(rb); err != nil {
		return "", err
	}
	sum := sha256.Sum256(rb)
	return hex.EncodeToString(sum[:]), nil
}

// HashPassword is bcrypt with the default cost, for password protected pastes.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", ErrEmptyPassword
	}
	if len(password) > maxBcrypt {
		return "", ErrPasswordTooLong
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

// ComparePassword says whether the password matches the bcrypt hash.
func ComparePassword(hash, password string) error {
	if hash == "" {
		return errors.New("empty hash")
	}
	if password == "" {
		return ErrEmptyPassword
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
