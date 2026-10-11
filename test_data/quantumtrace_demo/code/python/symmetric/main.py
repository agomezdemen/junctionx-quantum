# Static fixture: the current regex scanner does not infer this key length.
from cryptography.hazmat.primitives.ciphers import algorithms

def symmetric_cipher(key: bytes):
    return algorithms.AES(key)
