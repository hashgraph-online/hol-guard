"""Benign health endpoint fetch fixture (T641).

Simulates a legitimate health check against a local service.
No secret files are read. No external network calls to harmful endpoints.
The URL is a local loopback address only.
"""

from urllib.error import URLError
from urllib.request import Request, urlopen

_HEALTH_URL = "http://127.0.0.1:8080/healthz"
_TIMEOUT_S = 2.0


def check_health(url: str = _HEALTH_URL, timeout: float = _TIMEOUT_S) -> bool:
    try:
        req = Request(url, method="GET")
        with urlopen(req, timeout=timeout) as response:
            return response.status == 200
    except (URLError, OSError):
        return False


if __name__ == "__main__":
    ok = check_health()
    print("healthy" if ok else "unreachable")
