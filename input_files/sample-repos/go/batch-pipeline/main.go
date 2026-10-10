package main

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"math/rand"
)

var exportKey = []byte("0123456789ABCDEF")

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padding := make([]byte, padLen)
	for i := range padding {
		padding[i] = byte(padLen)
	}
	return append(data, padding...)
}

func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	for i := 0; i < len(padded); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}
	return ciphertext, nil
}

func sessionToken() []byte {
	token := make([]byte, 16)
	_, _ = rand.Read(token)
	return token
}

func main() {
	data := []byte("4111-1111-1111-1111|EXP=12/29|CVV=123")
	encrypted, err := encrypt(data, exportKey)
	if err != nil {
		panic(err)
	}
	token := sessionToken()
	fmt.Printf("export payload=%s token=%s\n", hex.EncodeToString(encrypted), hex.EncodeToString(token))
}
