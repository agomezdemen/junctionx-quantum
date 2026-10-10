package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const (
	iterations = 600_000
	saltLen    = 16
	keyLen     = 32
)

func deriveKey(password, salt []byte, iter, dkLen int) []byte {
	hLen := sha256.Size
	numBlocks := (dkLen + hLen - 1) / hLen
	derived := make([]byte, 0, numBlocks*hLen)

	for block := 1; block <= numBlocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		var blockIndex [4]byte
		binary.BigEndian.PutUint32(blockIndex[:], uint32(block))
		mac.Write(blockIndex[:])
		u := mac.Sum(nil)
		t := make([]byte, hLen)
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac := hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		derived = append(derived, t...)
	}
	return derived[:dkLen]
}

func randomSalt() []byte {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return salt
}

func hashPassword(password string, salt []byte) []byte {
	return deriveKey([]byte(password), salt, iterations, keyLen)
}

func verifyPassword(password string, salt, expected []byte) bool {
	derived := hashPassword(password, salt)
	return subtle.ConstantTimeCompare(derived, expected) == 1
}

func main() {
	salt := randomSalt()
	derived := hashPassword("hunter2", salt)
	if !verifyPassword("hunter2", salt, derived) {
		panic("password should validate")
	}
	if verifyPassword("wrong-password", salt, derived) {
		panic("wrong password should not validate")
	}
	fmt.Printf("gateway credential salt=%s\n", hex.EncodeToString(salt))
}
