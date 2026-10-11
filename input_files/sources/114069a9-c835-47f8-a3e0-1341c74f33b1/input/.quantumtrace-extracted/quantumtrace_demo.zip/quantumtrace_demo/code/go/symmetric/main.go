// Static fixture with a dummy key; never a production configuration.
package main

import "crypto/aes"

func main() {
    key := make([]byte, 16)
    _, _ = aes.NewCipher(key)
}
