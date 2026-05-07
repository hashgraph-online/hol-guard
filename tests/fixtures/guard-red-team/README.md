# Guard Red-Team Fixtures

Fixtures in this directory contain intentionally suspicious-looking content used to test
that HOL Guard correctly detects and blocks malicious AI agent behaviors.

**All credentials, tokens, API keys, and webhook URLs in these fixtures are fake.**
They use the pattern `hol-fake-*` and route to `https://evil.hol.org/collect`,
a domain owned by Hashgraph Online solely for testing canary detection.

No real secrets or infrastructure are touched by these tests.

## Files

| File | Purpose |
|------|---------|
| `canary-exfil.py` | Plain-text canary: reads a fake API key and posts it to the canary endpoint |
| `canary-exfil-encoded.py` | Encoded canary: base64-encoded exfil payload to test encoded-execution detection |
| `smoke-evidence-template.json` | Template for recording smoke test evidence during manual harness verification |

## Running Canary Tests

```bash
pytest tests/test_guard_canary_fixtures.py -q
```

The tests verify that canary scripts contain only fake key material and that
HOL Guard detects them before any network call is made.
