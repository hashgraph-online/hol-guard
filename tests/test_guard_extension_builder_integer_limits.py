"""Untrusted numeric exports stay bounded without leaking interpreter exceptions."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.extension_builder import io as builder_io
from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import MAX_INTEGER_DIGITS, canonical_json, parse_json


@pytest.mark.parametrize("number", ["0", "-1", "9" * MAX_INTEGER_DIGITS, "-" + "9" * MAX_INTEGER_DIGITS])
def test_supported_integer_boundary_round_trips(number: str) -> None:
    value = parse_json(('{"number":' + number + "}").encode())
    assert value == {"number": int(number)}
    assert parse_json(canonical_json(value).encode()) == value


@pytest.mark.parametrize("length", [MAX_INTEGER_DIGITS + 1, 5_000])
@pytest.mark.parametrize("sign", ["", "-"])
def test_oversized_integer_is_a_stable_domain_error(length: int, sign: str) -> None:
    content = ('{"number":' + sign + "9" * length + "}").encode()
    with pytest.raises(BuilderError) as caught:
        parse_json(content)
    assert caught.value.code == "integer_limit"
    assert caught.value.exit_code == 2
    assert "999999" not in str(caught.value)
    assert len(str(caught.value)) < 100


@pytest.mark.parametrize(
    "content,code",
    [(b'{"x":1,"x":2}', "duplicate_json_key"), (b'{"x":NaN}', "invalid_json"), (b"\xff", "input_encoding")],
)
def test_existing_decoder_domain_errors_keep_their_codes(content: bytes, code: str) -> None:
    with pytest.raises(BuilderError) as caught:
        parse_json(content)
    assert caught.value.code == code


def test_unexpected_decoder_value_error_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    def unsupported_number(*args: object, **kwargs: object) -> object:
        raise ValueError("private-source-value must not appear in diagnostics")

    monkeypatch.setattr(builder_io.json, "loads", unsupported_number)
    with pytest.raises(BuilderError) as caught:
        parse_json(b"{}")
    assert caught.value.code == "invalid_json"
    assert "private-source-value" not in str(caught.value)


def test_cli_oversized_integer_preserves_json_error_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    source = tmp_path / "oversized.json"
    source.write_bytes(b'{"number":' + b"9" * 5_000 + b"}")
    output = tmp_path / "kit"
    status = cli.main(
        [
            "extensions",
            "generate",
            "--from",
            "cli",
            "--input",
            str(source),
            "--output",
            str(output),
            "--slug",
            "integer-fixture",
            "--executable",
            "integer-fixture",
            "--publisher",
            "community.example",
            "--homepage",
            "https://example.test/integer-fixture",
            "--json",
        ]
    )
    captured = capsys.readouterr()
    assert status == 2
    result = json.loads(captured.out)
    assert result["ok"] is False
    assert result["error"]["code"] == "integer_limit"
    assert "999999" not in captured.out + captured.err
    assert not output.exists()
