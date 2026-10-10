import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 600_000
SALT_LEN = 16
KEY_LEN = 32


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or os.urandom(SALT_LEN)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=ITERATIONS)
    return kdf.derive(password.encode("utf-8")), salt


def verify_password(password: str, derived: bytes, salt: bytes) -> bool:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=ITERATIONS)
    try:
        kdf.verify(password.encode("utf-8"), derived)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    derived, salt = hash_password("hunter2")
    assert verify_password("hunter2", derived, salt)
    assert not verify_password("wrong-password", derived, salt)
    print(f"member credential derived, salt={salt.hex()}")
