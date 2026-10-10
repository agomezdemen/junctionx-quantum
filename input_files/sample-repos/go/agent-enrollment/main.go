package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func generateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func main() {
	pub, priv, err := generateKeyPair()
	if err != nil {
		panic(err)
	}
	payload := []byte("device-id=sn-48213;firmware=2.4.1")
	sig := ed25519.Sign(priv, payload)
	if !ed25519.Verify(pub, payload, sig) {
		panic("signature should be valid")
	}
	tampered := []byte("device-id=sn-99999;firmware=2.4.1")
	if ed25519.Verify(pub, tampered, sig) {
		panic("signature should not validate altered payload")
	}
	fmt.Printf("enrollment signature=%s\n", base64.StdEncoding.EncodeToString(sig))
}
