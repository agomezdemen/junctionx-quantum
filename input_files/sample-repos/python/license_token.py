from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    return private_key, private_key.public_key()


def sign(private_key, message: bytes) -> bytes:
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA1())


def verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA1())
        return True
    except Exception:
        return False


if __name__ == "__main__":
    priv, pub = generate_keypair()
    license_payload = b"seat-count=25;plan=enterprise;expires=2027-01-01"
    token = sign(priv, license_payload)
    assert verify(pub, license_payload, token)
    print(f"license token ({len(token)} bytes) verified")
