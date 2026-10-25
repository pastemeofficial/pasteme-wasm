package pwcrypto

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

// Produced by an independent implementation (Node's crypto: pbkdf2Sync + aes-256-gcm), not by this package: proves
// that what this package decrypts is what any other implementation of the format, and the old module, produce.
const (
	katPass   = "test-passphrase"
	katCipher = "0001020304050607-000102030405060708090a0b-dfe5203f88b6850f8b6cf400336f3a5870450695e1b42e8251a7ad885ee9a43347f0b7b0dd"
	katPlain  = "hello paste.me åäö"
)

func TestKnownAnswerFromAnotherImplementation(t *testing.T) {
	got, err := Decrypt(katPass, katCipher)
	if err != nil || string(got) != katPlain {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestRoundTripText(t *testing.T) {
	for _, s := range []string{"a", "hello", strings.Repeat("x", 1<<20), "åäö \U0001F680 \x00 nul"} {
		ct, err := Encrypt("pass", []byte(s))
		if err != nil {
			t.Fatal(err)
		}
		pt, err := Decrypt("pass", ct)
		if err != nil || string(pt) != s {
			t.Fatalf("round trip failed for %d bytes: %v", len(s), err)
		}
	}
}

func TestRoundTripBinaryAndEmpty(t *testing.T) {
	bin := make([]byte, 4096)
	_, _ = rand.Read(bin)
	for _, b := range [][]byte{bin, {}} {
		ct, err := Encrypt("p", b)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := Decrypt("p", ct)
		if err != nil || !bytes.Equal(pt, b) {
			t.Fatalf("binary round trip failed: %v", err)
		}
	}
}

func TestEveryEncryptionIsDifferent(t *testing.T) {
	a, _ := Encrypt("p", []byte("same"))
	b, _ := Encrypt("p", []byte("same"))
	if a == b {
		t.Fatal("salt and iv must be random per call")
	}
	if len(strings.Split(a, "-")[0]) != 16 || len(strings.Split(a, "-")[1]) != 24 {
		t.Fatalf("format changed: %s", a)
	}
}

func TestWrongPassphraseAndTamperingAreErrors(t *testing.T) {
	ct, _ := Encrypt("right", []byte("secret"))
	if _, err := Decrypt("wrong", ct); err != ErrDecrypt {
		t.Fatalf("wrong passphrase: %v", err)
	}
	parts := strings.Split(ct, "-")
	last := parts[2]
	flipped := last[:len(last)-1] + map[bool]string{true: "1", false: "0"}[last[len(last)-1] == '0']
	if _, err := Decrypt("right", parts[0]+"-"+parts[1]+"-"+flipped); err != ErrDecrypt {
		t.Fatalf("tampered data: %v", err)
	}
}

func TestMalformedInputNeverPanics(t *testing.T) {
	bad := []string{"", "-", "--", "a-b", "a-b-c-d", "zz-zz-zz", "0001-0002-0003", katCipher[:20],
		"0001020304050607-0001-dfe5203f88b6850f8b6cf400336f3a58", // iv too short: cipher.Open would panic on it
		"0001020304050607-000102030405060708090a0b-aa",           // shorter than a GCM tag
		strings.Repeat("-", 1000)}
	for _, b := range bad {
		if _, err := Decrypt("p", b); err == nil {
			t.Errorf("%q accepted", b)
		}
	}
	if _, err := Decrypt("", katCipher); err != ErrEmptyPassphrase {
		t.Fatal("empty passphrase accepted")
	}
	if _, err := Encrypt("", []byte("x")); err != ErrEmptyPassphrase {
		t.Fatal("empty passphrase accepted")
	}
}

func TestPassphrase(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		p, err := GeneratePassphrase()
		if err != nil || len(p) != 64 || strings.Trim(p, "0123456789abcdef") != "" || seen[p] {
			t.Fatalf("bad passphrase %q %v", p, err)
		}
		seen[p] = true
	}
}

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("correct horse")
	if err != nil || !strings.HasPrefix(h, "$2") {
		t.Fatal(h, err)
	}
	if ComparePassword(h, "correct horse") != nil || ComparePassword(h, "wrong") == nil {
		t.Fatal("compare")
	}
	if _, err := HashPassword(""); err != ErrEmptyPassword {
		t.Fatal("empty password hashed")
	}
	if _, err := HashPassword(strings.Repeat("a", 73)); err != ErrPasswordTooLong {
		t.Fatal("over-long password silently truncated")
	}
	if _, err := HashPassword(strings.Repeat("a", 72)); err != nil {
		t.Fatal("72 bytes must be fine")
	}
	// a hash made by the old module (x/crypto 2020, cost 10) still verifies
	if ComparePassword("$2a$10$7EqJtq98hPqEX7fNZaFWoOhi5BIqxaTEf1qOD3c3B1bJ7jT1x1Uq6", "x") == nil {
		t.Fatal("unexpected match")
	}
}
