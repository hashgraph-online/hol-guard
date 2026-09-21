from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from ci.native_runtime.probe_installed_runtime_identity import _count_full_validation


@pytest.mark.parametrize("raise_after_digest", (False, True))
def test_hash_instrumentation_preserves_real_digest_protocol_and_restores_after_failure(raise_after_digest):
    content = b"synthetic identity qualification bytes"
    original_sha256 = hashlib.sha256
    expected = original_sha256(content)

    def validate(_path):
        digest = hashlib.sha256()
        digest.update(content[:8])
        digest.update(content[8:])
        assert digest.digest() == expected.digest()
        assert digest.hexdigest() == expected.hexdigest()
        assert digest.copy().digest() == expected.digest()
        if raise_after_digest:
            raise RuntimeError("synthetic validator failure")

    runtime = SimpleNamespace(_validate_binary=validate, hashlib=hashlib)
    try:
        with _count_full_validation(runtime) as counts:
            assert hashlib.sha256(content).digest() == expected.digest()
            assert counts == {"validation_calls": 0, "hashed_bytes": 0}
            if raise_after_digest:
                with pytest.raises(RuntimeError, match="synthetic validator failure"):
                    runtime._validate_binary(None)
            else:
                runtime._validate_binary(None)
            assert counts == {"validation_calls": 1, "hashed_bytes": len(content)}
            if raise_after_digest:
                raise RuntimeError("synthetic context failure")
    except RuntimeError:
        assert raise_after_digest
    assert runtime._validate_binary is validate
    assert hashlib.sha256 is original_sha256
