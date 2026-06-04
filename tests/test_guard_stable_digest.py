from __future__ import annotations

import hashlib

from codex_plugin_scanner.guard.stable_digest import stable_digest_hex


def test_stable_digest_is_deterministic_and_not_sha256() -> None:
    payload = b'{"workspace":"demo","harness":"codex"}'

    digest = stable_digest_hex(payload)

    assert digest == stable_digest_hex(payload)
    assert len(digest) == 64
    assert digest != hashlib.sha256(payload).hexdigest()


def test_stable_digest_truncates_from_full_digest() -> None:
    payload = b"guard-local-sync"

    full_digest = stable_digest_hex(payload)

    assert stable_digest_hex(payload, length=24) == full_digest[:24]
