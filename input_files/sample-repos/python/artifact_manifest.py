import hashlib
import hmac


def checksum(data: bytes) -> str:
    return hashlib.sha384(data).hexdigest()


def verify_checksum(data: bytes, expected: str) -> bool:
    return hmac.compare_digest(checksum(data), expected)


def signing_tag(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_tag(key: bytes, data: bytes, expected: str) -> bool:
    return hmac.compare_digest(signing_tag(key, data), expected)


if __name__ == "__main__":
    package = b"firmware-image-v1.2.3-build42"
    expected = checksum(package)
    assert verify_checksum(package, expected)
    print(f"package checksum={expected}")

    key = b"shared-signing-key-32-bytes-long"
    tag = signing_tag(key, package)
    assert verify_tag(key, package, tag)
    assert not verify_tag(key, package + b"\x00", tag)
    print(f"manifest tag={tag}")
