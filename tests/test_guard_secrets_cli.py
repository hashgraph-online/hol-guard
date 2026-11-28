"""Focused tests for the guarded secret CLI glue."""

from __future__ import annotations

import argparse
import io

from codex_plugin_scanner.guard.cli import secrets_command

REFERENCE = "guard-secret://native/example-scope/api-token"
VALUE = "fixture-value-7"


def _args(command: str, *, value_stdin: bool = False, as_json: bool = True) -> argparse.Namespace:
    return argparse.Namespace(
        secrets_command=command,
        reference=REFERENCE,
        value_stdin=value_stdin,
        json=as_json,
    )


def test_metadata_cli_returns_native_metadata_without_a_value(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_request(request: dict[str, object]) -> dict[str, object]:
        captured.update(request)
        return {
            "ok": True,
            "reference": REFERENCE,
            "reference_digest": "digest",
            "provider": "native",
            "scope": "example-scope",
            "name": "api-token",
            "state": "missing",
            "delivery": ["environment", "stdin", "file_descriptor"],
        }

    monkeypatch.setattr(secrets_command, "_native_request", fake_request)
    output = io.StringIO()
    assert secrets_command.run_secrets_command(_args("metadata"), output_stream=output) == 0
    assert captured == {"command": "metadata", "reference": REFERENCE}
    assert VALUE not in output.getvalue()


def test_set_cli_keeps_value_out_of_rendered_output(monkeypatch, capsys) -> None:
    captured: dict[str, object] = {}

    def fake_set(reference: str, *, from_stdin: bool) -> dict[str, object]:
        captured.update({"reference": reference, "from_stdin": from_stdin})
        return {"ok": True, "reference": REFERENCE, "state": "available"}

    monkeypatch.setattr(secrets_command, "_native_set_interactive", fake_set)
    assert secrets_command.run_secrets_command(_args("set", value_stdin=True), output_stream=io.StringIO()) == 0
    assert captured == {"reference": REFERENCE, "from_stdin": True}
    assert VALUE not in capsys.readouterr().out


def test_set_cli_does_not_accept_a_value_argument(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_set(reference: str, *, from_stdin: bool) -> dict[str, object]:
        captured.update({"reference": reference, "from_stdin": from_stdin})
        return {"ok": True, "reference": REFERENCE, "state": "available"}

    monkeypatch.setattr(secrets_command, "_native_set_interactive", fake_set)
    assert secrets_command.run_secrets_command(_args("set"), output_stream=io.StringIO()) == 0
    assert captured == {"reference": REFERENCE, "from_stdin": False}
