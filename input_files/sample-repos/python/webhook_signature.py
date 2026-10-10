from cryptography.hazmat.primitives.asymmetric import ed25519


def generate_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def sign(private_key, payload: bytes) -> bytes:
    return private_key.sign(payload)


def verify(public_key, payload: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, payload)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    priv, pub = generate_keypair()
    payload = b'{"event":"payment.completed","amount":1999.90,"currency":"EUR"}'
    sig = sign(priv, payload)
    assert verify(pub, payload, sig)
    assert not verify(pub, payload.replace(b"1999.90", b"1.00"), sig)
    print(f"webhook signature ({len(sig)} bytes) verified")
