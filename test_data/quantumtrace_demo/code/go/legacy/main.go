// Static analysis fixture only.
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/rsa"
)

func main() {
    _, _ = rsa.GenerateKey(rand.Reader, 2048)
    _, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
