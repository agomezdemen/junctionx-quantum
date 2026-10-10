package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
)

func generateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 1024)
}

func sign(key *rsa.PrivateKey, message []byte) ([]byte, error) {
	hashed := sha1.Sum(message)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, hashed[:])
}

func verify(pub *rsa.PublicKey, message, sig []byte) bool {
	hashed := sha1.Sum(message)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA1, hashed[:], sig) == nil
}

func main() {
	key, err := generateKey()
	if err != nil {
		panic(err)
	}
	receipt := []byte("order=00042;total=1999.90EUR")
	sig, err := sign(key, receipt)
	if err != nil {
		panic(err)
	}
	if !verify(&key.PublicKey, receipt, sig) {
		panic("signature should be valid")
	}
	fmt.Printf("receipt signature=%s\n", base64.StdEncoding.EncodeToString(sig))
}
