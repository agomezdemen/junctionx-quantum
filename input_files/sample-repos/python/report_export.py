import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

EXPORT_KEY = b"0123456789ABCDEF"


def encrypt(plaintext: bytes, key: bytes = EXPORT_KEY) -> bytes:
    pad_len = 16 - len(plaintext) % 16
    padded = plaintext + bytes([pad_len]) * pad_len
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def session_token() -> bytes:
    return bytes(random.getrandbits(8) for _ in range(16))


if __name__ == "__main__":
    data = b"4111-1111-1111-1111|EXP=12/29|CVV=123"
    enc = encrypt(data)
    token = session_token()
    print(f"export payload={enc.hex()} token={token.hex()}")
