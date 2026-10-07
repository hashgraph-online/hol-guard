"""Security regressions for user-facing Guard error redaction."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import secret_redaction
from codex_plugin_scanner.guard.secret_redaction import sanitize_secret


def _join(*parts: str) -> str:
    """Construct synthetic credential labels and values at runtime."""
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


@pytest.mark.parametrize(
    "pattern_name",
    ("_SECRET_KV_PATTERN", "_GUARD_TOKEN_FRAGMENT_PATTERN", "_BEARER_PATTERN"),
)
@pytest.mark.parametrize("failure_type", (RuntimeError, MemoryError))
def test_sanitize_secret_never_returns_sensitive_input_when_redaction_fails(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    pattern_name: str,
    failure_type: type[Exception],
) -> None:
    values = tuple(_join("redaction", "-", name) for name in ("one", "two", "three"))
    fragment = _join("guard", "-", "token")
    message = (
        f"daemon failed: {_join('to', 'ken')}={values[0]}, "
        f"open http://127.0.0.1/#{fragment}={values[1]}&tab=inbox, "
        f"{_join('Bea', 'rer')} {values[2]}"
    )

    def failed_substitution(*_args: object, **_kwargs: object) -> str:
        raise failure_type("synthetic redactor failure")

    monkeypatch.setattr(secret_redaction, pattern_name, SimpleNamespace(sub=failed_substitution))
    result = sanitize_secret(message)
    captured = capsys.readouterr()

    assert isinstance(result, str)
    assert result
    # Cover diagnostic output as well as the returned string.
    assert not any(value in result + captured.out + captured.err + caplog.text for value in values)
    failure_records = [
        record
        for record in caplog.records
        if record.name == secret_redaction._LOGGER.name and record.getMessage() == "secret_redaction_failed"
    ]
    assert len(failure_records) == 1
    assert failure_records[0].exc_info is None


@pytest.mark.parametrize("failure_type", (RuntimeError, MemoryError))
def test_sanitize_secret_keeps_safe_fallback_when_failure_logging_raises(
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[Exception],
) -> None:
    def fail(*_args: object, **_kwargs: object) -> str:
        raise failure_type("synthetic failure")

    monkeypatch.setattr(secret_redaction, "_SECRET_KV_PATTERN", SimpleNamespace(sub=fail))
    monkeypatch.setattr(secret_redaction._LOGGER, "warning", fail)
    assert sanitize_secret(f"{_join('to', 'ken')}=synthetic-value") == "<redacted>"


@pytest.mark.parametrize("failure_stage", ("redaction", "logging"))
@pytest.mark.parametrize("control_flow_type", (KeyboardInterrupt, SystemExit))
def test_sanitize_secret_preserves_control_flow_exceptions(
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
    control_flow_type: type[BaseException],
) -> None:
    """Ordinary failures redact diagnostics; control-flow exceptions propagate."""

    def fail_redaction(*_args: object, **_kwargs: object) -> str:
        if failure_stage == "redaction":
            raise control_flow_type()
        raise RuntimeError("synthetic redactor failure")

    def fail_logging(*_args: object, **_kwargs: object) -> None:
        raise control_flow_type()

    monkeypatch.setattr(secret_redaction, "_SECRET_KV_PATTERN", SimpleNamespace(sub=fail_redaction))
    monkeypatch.setattr(secret_redaction._LOGGER, "warning", fail_logging)
    with pytest.raises(control_flow_type):
        sanitize_secret("synthetic diagnostic")
