package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const keyLen = 32

func generateKey() []byte {
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

func encrypt(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

func decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func main() {
	key := generateKey()
	data := []byte("4111-1111-1111-1111|EXP=12/29|CVV=123")
	aad := []byte("relay-00042")

	nonce, ciphertext, err := encrypt(key, data, aad)
	if err != nil {
		panic(err)
	}
	decrypted, err := decrypt(key, nonce, ciphertext, aad)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(data, decrypted) {
		panic("round-trip failed")
	}
	if _, err := decrypt(key, nonce, ciphertext, []byte("relay-00043")); err == nil {
		panic("expected authentication failure")
	}
	fmt.Printf("relay payload nonce=%s ciphertext=%s\n", hex.EncodeToString(nonce), hex.EncodeToString(ciphertext))
}
