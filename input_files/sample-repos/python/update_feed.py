import hashlib


def checksum(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def verify_checksum(data: bytes, expected: str) -> bool:
    return checksum(data) == expected


if __name__ == "__main__":
    package = b"firmware-image-v1.2.3-build42"
    expected = checksum(package)
    assert verify_checksum(package, expected)
    print(f"package checksum={expected}")
