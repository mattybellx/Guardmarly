import hashlib


def fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
