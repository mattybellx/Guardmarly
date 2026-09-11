import requests


def health() -> str:
    return requests.get("https://example.com/health", timeout=5).text
