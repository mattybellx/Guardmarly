import hashlib


def fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()
