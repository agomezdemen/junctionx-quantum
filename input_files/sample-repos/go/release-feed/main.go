package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

func checksum(data []byte) string {
	sum := sha1.Sum(data)
	return hex.EncodeToString(sum[:])
}

func verifyChecksum(data []byte, expected string) bool {
	return checksum(data) == expected
}

func main() {
	pkg := []byte("firmware-image-v1.2.3-build42")
	expected := checksum(pkg)
	if !verifyChecksum(pkg, expected) {
		panic("checksum should validate")
	}
	fmt.Printf("package checksum=%s\n", expected)
}
