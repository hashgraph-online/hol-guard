"""Security regressions for user-facing Guard error redaction."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.secret_redaction import sanitize_secret


def _join(*parts: str) -> str:
    return "".join(parts)


def _key_value_case(
    *,
    prefix: str,
    label_parts: tuple[str, ...],
    separator: str,
    value_parts: tuple[str, ...],
    suffix: str = "",
) -> tuple[str, str]:
    label = _join(*label_parts)
    value = _join(*value_parts)
    return (
        f"{prefix}{label}{separator}{value}{suffix}",
        f"{prefix}{label}=<redacted>{suffix}",
    )


def _bearer_case(*, prefix: str, value_parts: tuple[str, ...]) -> tuple[str, str]:
    scheme = _join("Bea", "rer")
    value = _join(*value_parts)
    return f"{prefix}{scheme} {value}", f"{prefix}{scheme} <redacted>"


def _dashboard_fragment_case() -> tuple[str, str]:
    parameter = _join("guard", "-", "token")
    value = _join("session", "-", "sample")
    prefix = "open http://127.0.0.1/#"
    suffix = "&tab=inbox"
    return (
        f"{prefix}{parameter}={value}{suffix}",
        f"{prefix}{parameter}=<redacted>{suffix}",
    )


CASES = [
    _key_value_case(
        prefix="daemon failed: ",
        label_parts=("to", "ken"),
        separator="=",
        value_parts=("sample", "-", "value"),
    ),
    _key_value_case(
        prefix="request failed: ",
        label_parts=("api", "_", "key"),
        separator=": ",
        value_parts=("example", "-", "value"),
    ),
    _bearer_case(
        prefix="authorization failed: ",
        value_parts=("sample", ".", "segment", "~+/="),
    ),
    _dashboard_fragment_case(),
    _key_value_case(
        prefix="",
        label_parts=("creden", "tial"),
        separator="=",
        value_parts=("example", "-", "value"),
    ),
    _key_value_case(
        prefix="",
        label_parts=("to", "ken"),
        separator="=",
        value_parts=('"example phrase"',),
        suffix="; retry later",
    ),
    _key_value_case(
        prefix="",
        label_parts=("pass", "word"),
        separator=": ",
        value_parts=("example phrase",),
        suffix=", operation failed",
    ),
    _bearer_case(
        prefix=f"{_join('Author', 'ization')}: ",
        value_parts=("abc", "~", "def", "+/=", "_-", "."),
    ),
]


@pytest.mark.parametrize(("message", "expected"), CASES)
def test_sanitize_secret_redacts_complete_sensitive_value(message: str, expected: str) -> None:
    assert sanitize_secret(message) == expected


def test_sanitize_secret_preserves_clean_error() -> None:
    message = "The local Guard daemon did not start"
    assert sanitize_secret(message) == message


def test_sanitize_secret_handles_empty_string() -> None:
    assert sanitize_secret("") == ""
