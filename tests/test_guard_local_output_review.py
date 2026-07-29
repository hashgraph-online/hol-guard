"""Tests for local_output_review — bounded capture and secret scanning.

Focus on:
* Oversized output is truncated with full-length byte_count and full-bytes digest.
* Truncation is detectable via the ``truncated`` flag.
* Secret patterns are redacted to labels only (raw values never appear).
* Byte counts and digests are consistent with raw data.
"""

from __future__ import annotations

import hashlib

import pytest

from codex_plugin_scanner.guard.runtime.local_output_review import (
    BoundedOutput,
    capture_bounded_output,
    scan_output_for_secrets,
)

# ---------------------------------------------------------------------------
# capture_bounded_output — correctness on sizes
# ---------------------------------------------------------------------------


def test_capture_under_max_preserves_all_data_and_not_truncated() -> None:
    data = b"hello world"
    result = capture_bounded_output(data, stream="stdout", max_bytes=65536)
    assert result.byte_count == len(data)
    assert result.digest == hashlib.sha256(data).hexdigest()
    assert not result.truncated
    assert result.stream == "stdout"


def test_capture_stderr_stream() -> None:
    data = b"error output"
    result = capture_bounded_output(data, stream="stderr")
    assert result.stream == "stderr"


def test_capture_exact_max_is_not_truncated() -> None:
    data = b"A" * 100
    result = capture_bounded_output(data, stream="stdout", max_bytes=100)
    assert not result.truncated
    assert result.byte_count == 100


def test_capture_over_max_sets_truncated_true() -> None:
    data = b"B" * 200
    result = capture_bounded_output(data, stream="stderr", max_bytes=100)
    assert result.truncated
    assert result.byte_count == 200


def test_oversized_output_has_full_byte_count() -> None:
    data = b"X" * 100_000
    result = capture_bounded_output(data, stream="stdout", max_bytes=65536)
    assert result.byte_count == 100_000


def test_oversized_output_has_full_bytes_digest() -> None:
    data = b"Y" * 100_000
    result = capture_bounded_output(data, stream="stderr", max_bytes=1024)
    expected_digest = hashlib.sha256(data).hexdigest()
    assert result.digest == expected_digest


def test_truncation_is_detectable() -> None:
    """Truncated output carries a True flag so a downstream verifier can
    tell that the digest covers more data than was retained."""
    data = b"Z" * 1_000_000
    result = capture_bounded_output(data, stream="stdout", max_bytes=1000)
    assert result.truncated is True
    # Digest still covers the million bytes, proving the original was larger.


def test_empty_input() -> None:
    result = capture_bounded_output(b"", stream="stdout")
    assert result.byte_count == 0
    assert not result.truncated
    assert result.digest == hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------------------
# Secret scanning — labels only
# ---------------------------------------------------------------------------


def test_scan_aws_access_key_label_only() -> None:
    data = b"AKIAIOSFODNN7EXAMPLE"
    labels = scan_output_for_secrets(data)
    assert "aws-access-key" in labels
    assert "AKIAIOSFODNN7EXAMPLE" not in str(labels)
    assert isinstance(labels, tuple)


def test_scan_private_key_label_only() -> None:
    marker = b"-----BEGIN RSA PRIVATE KEY-----"  # gitleaks:allow — synthetic PEM marker for redaction test
    labels = scan_output_for_secrets(marker)
    assert "private-key" in labels
    assert b"PRIVATE" not in str(labels).encode()


def test_scan_jwt_label_only() -> None:
    # Construct a plausible JWT token (three base64url segments ≥ 20 chars)
    payload = (
        b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        b"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        b"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    labels = scan_output_for_secrets(payload)
    assert "jwt" in labels
    assert b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in str(labels).encode()


def test_scan_secret_assignment_label_only() -> None:
    data = b"api_key=supersecretvalue123"
    labels = scan_output_for_secrets(data)
    assert "secret-assignment" in labels
    assert "supersecretvalue123" not in str(labels)


def test_scan_multiple_patterns_returns_sorted_labels() -> None:
    data = b"AKIAIOSFODNN7EXAMPLE password=foo bar"
    labels = scan_output_for_secrets(data)
    assert "aws-access-key" in labels
    assert "secret-assignment" in labels
    # Should be sorted alphabetically
    assert labels == tuple(sorted(labels))


def test_scan_no_match_returns_empty_tuple() -> None:
    data = b"nothing secret here, just normal output"
    labels = scan_output_for_secrets(data)
    assert labels == ()


def test_scan_preserves_labels_not_values() -> None:
    """Assert that NO raw secret value ever appears in the returned structure."""
    data = b"AKIAIOSFODNN7EXAMPLE some.jwt.token.here SECRET=s3cret-value\n"
    labels = scan_output_for_secrets(data)
    result_str = str(labels)
    # Verify no raw secret values leaked into labels
    assert "AKIAIOSFODNN7EXAMPLE" not in result_str
    assert "s3cret-value" not in result_str


def test_scan_bytes_must_be_bytes() -> None:
    with pytest.raises(TypeError, match="data must be bytes"):
        scan_output_for_secrets("string data")


# ---------------------------------------------------------------------------
# BoundedOutput — immutability & validation
# ---------------------------------------------------------------------------


def test_boundedoutput_is_immutable() -> None:
    data = b"test"
    result = capture_bounded_output(data)
    with pytest.raises(AttributeError):
        result.stream = "modified"


def test_boundedoutput_stream_must_be_stdout_or_stderr() -> None:
    with pytest.raises(ValueError, match="stream must be"):
        BoundedOutput(stream="syslog", byte_count=0, digest=hashlib.sha256(b"").hexdigest(), truncated=False)


def test_boundedoutput_byte_count_must_be_nonnegative() -> None:
    digest = hashlib.sha256(b"").hexdigest()
    with pytest.raises(ValueError, match="byte_count must be a non-negative"):
        BoundedOutput(stream="stdout", byte_count=-1, digest=digest, truncated=False)


def test_boundedoutput_digest_format() -> None:
    with pytest.raises(ValueError, match="digest must be"):
        BoundedOutput(stream="stdout", byte_count=0, digest="not-a-hash", truncated=False)


def test_boundedoutput_truncated_must_be_bool() -> None:
    digest = hashlib.sha256(b"").hexdigest()
    with pytest.raises(ValueError, match="truncated must be a bool"):
        BoundedOutput(stream="stdout", byte_count=0, digest=digest, truncated="yes")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# capture_bounded_output — input validation
# ---------------------------------------------------------------------------


def test_capture_requires_bytes() -> None:
    with pytest.raises(TypeError, match="data must be bytes"):
        capture_bounded_output("not bytes")  # type: ignore[arg-type]


def test_digest_rejects_uppercase_hex() -> None:
    import pytest

    from codex_plugin_scanner.guard.runtime.local_output_review import BoundedOutput

    with pytest.raises(ValueError, match="lowercase hex"):
        BoundedOutput(
            stream="stdout",
            byte_count=0,
            digest="A" * 64,
            truncated=False,
        )

    with pytest.raises(ValueError, match="lowercase hex"):
        BoundedOutput(
            stream="stdout",
            byte_count=0,
            digest="g" * 64,
            truncated=False,
        )
