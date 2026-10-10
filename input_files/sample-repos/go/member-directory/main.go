package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
)

func hashPassword(password string) string {
	sum := md5.Sum([]byte(password))
	return hex.EncodeToString(sum[:])
}

func verifyPassword(password, storedHash string) bool {
	return hashPassword(password) == storedHash
}

func main() {
	stored := hashPassword("hunter2")
	if !verifyPassword("hunter2", stored) {
		panic("password should validate")
	}
	if verifyPassword("wrong-password", stored) {
		panic("wrong password should not validate")
	}
	fmt.Printf("directory hash=%s\n", stored)
}
