# Static analysis fixture only; deliberately includes legacy cryptography.
from Crypto.PublicKey import RSA
import hashlib

def legacy_credentials():
    key = RSA.generate(2048)
    digest = hashlib.sha1()
    return key, digest
