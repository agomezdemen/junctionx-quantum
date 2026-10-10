package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

func checksum(data []byte) string {
	sum := sha512.Sum384(data)
	return hex.EncodeToString(sum[:])
}

func verifyChecksum(data []byte, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(checksum(data)), []byte(expected)) == 1
}

func signingTag(key, data []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func verifyTag(key, data []byte, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(signingTag(key, data)), []byte(expected)) == 1
}

func main() {
	pkg := []byte("firmware-image-v1.2.3-build42")
	expected := checksum(pkg)
	if !verifyChecksum(pkg, expected) {
		panic("checksum should validate")
	}
	fmt.Printf("package checksum=%s\n", expected)

	key := []byte("shared-signing-key-32-bytes-long")
	tag := signingTag(key, pkg)
	if !verifyTag(key, pkg, tag) {
		panic("tag should validate")
	}
	tampered := []byte("firmware-image-v1.2.3-build43")
	if verifyTag(key, tampered, tag) {
		panic("tag should not validate altered data")
	}
	fmt.Printf("config tag=%s\n", tag)
}
