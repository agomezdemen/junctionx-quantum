import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32
NONCE_LEN = 12


def generate_key() -> bytes:
    return os.urandom(KEY_LEN)


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)


if __name__ == "__main__":
    key = generate_key()
    data = b"4111-1111-1111-1111|EXP=12/29|CVV=123"
    nonce, ciphertext = encrypt(key, data, associated_data=b"transfer-00042")
    decrypted = decrypt(key, nonce, ciphertext, associated_data=b"transfer-00042")
    assert decrypted == data
    try:
        decrypt(key, nonce, ciphertext, associated_data=b"transfer-00043")
        raise AssertionError("expected authentication failure")
    except InvalidTag:
        pass
    print(f"transfer payload nonce={nonce.hex()} ciphertext={ciphertext.hex()}")
