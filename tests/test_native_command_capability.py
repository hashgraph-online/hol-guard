"""Transport contract for the native command-capability owner."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_command_capability as module
from codex_plugin_scanner.guard.native_command_capability import (
    CommandCapabilityUnavailableError,
    native_command_capability,
    native_command_capability_issue,
)
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256

_CONTRACT = Path(__file__).resolve().parents[1] / "rust/crates/guard-contracts/src/command_capability.rs"


def _declared(source: str, constant: str) -> str | None:
    """The string a `pub const` declares, however rustfmt wrapped the declaration.

    A long name and value together exceed the line width, so rustfmt puts the
    value on its own line. Reading one line at a time would make the contract
    depend on how the declaration happens to be formatted.
    """
    match = re.search(rf'pub const {re.escape(constant)}: &str =\s*"([^"]*)";', source)
    return match.group(1) if match else None


def test_rust_schemas_mirror_the_python_client() -> None:
    source = _CONTRACT.read_text(encoding="utf-8")
    for constant, expected in (
        ("COMMAND_CAPABILITY_REQUEST_SCHEMA", module._REQUEST_SCHEMA),
        ("COMMAND_CAPABILITY_RESULT_SCHEMA", module._RESULT_SCHEMA),
        ("COMMAND_CAPABILITY_FEATURE", module.COMMAND_CAPABILITY_FEATURE),
        ("COMMAND_CAPABILITY_ISSUE_REQUEST_SCHEMA", module._ISSUE_REQUEST_SCHEMA),
        ("COMMAND_CAPABILITY_ISSUE_RESULT_SCHEMA", module._ISSUE_RESULT_SCHEMA),
        ("COMMAND_CAPABILITY_ISSUE_FEATURE", module.COMMAND_CAPABILITY_ISSUE_FEATURE),
    ):
        assert _declared(source, constant) == expected


def _capture(monkeypatch: pytest.MonkeyPatch, payload: object) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    def request(**kwargs: Any) -> dict[str, object]:
        seen["wire"] = kwargs["request"]
        seen["operation"] = kwargs["operation"]
        seen["feature"] = kwargs["required_feature"]
        return {"request_id": kwargs["request"]["request_id"], "status": "ok", "code": "ok", "payload": payload}

    monkeypatch.setattr(module, "ensure_resident_prerequisite", lambda home: True)
    monkeypatch.setattr(module, "_resident_request", request)

    def bind(response: Any, bound: Any, home: Any) -> object:
        seen["bound"] = bound
        return response["payload"]

    monkeypatch.setattr(module, "_payload", bind)
    return seen


def _call(**overrides: Any) -> dict[str, object]:
    arguments: dict[str, Any] = {
        "capability": {"signature": "abc"},
        "integrity_key_b64": "c2VjcmV0",
        "integrity_key_id": "key-1",
        "device_id": "device-1",
        "workspace_id": "workspace-1",
        "oauth_error": None,
        "now": "2026-03-01T00:00:00+00:00",
        "job": None,
        "schema_versions": {},
        "replay_items": [],
    }
    arguments.update(overrides)
    return native_command_capability(**arguments)


def test_the_request_carries_the_key_and_the_binding_digest_does_not(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture(monkeypatch, {"capability_valid": True})
    assert _call() == {"capability_valid": True}
    assert seen["operation"] == "command_capability"
    assert seen["feature"] == module.COMMAND_CAPABILITY_FEATURE
    assert seen["wire"]["integrity_key_b64"] == "c2VjcmV0"
    assert seen["bound"]["integrity_key_b64"] is None
    assert seen["bound"]["request_id"] == seen["wire"]["request_id"]
    assert _canonical_request_sha256(seen["bound"]) != _canonical_request_sha256(seen["wire"])


def test_every_contract_field_is_shipped_even_when_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture(monkeypatch, {"capability_valid": False})
    _call(capability=None, integrity_key_b64=None, integrity_key_id=None, device_id=None, workspace_id=None)
    assert set(seen["wire"]) == {
        "schema",
        "request_id",
        "capability",
        "integrity_key_b64",
        "integrity_key_id",
        "device_id",
        "workspace_id",
        "oauth_error",
        "now",
        "job",
        "schema_versions",
        "replay_items",
        "replay_identity",
    }
    assert seen["wire"]["job"] is None
    assert seen["wire"]["replay_identity"] is None


def test_a_job_and_a_replay_identity_are_copied_onto_the_wire(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture(monkeypatch, {"capability_valid": True})
    job = {"operation": "guard.app.status"}
    identity = {"id": "job-1"}
    _call(job=job, replay_identity=identity, schema_versions={"guard.app.status": 1})
    assert seen["wire"]["job"] == job and seen["wire"]["job"] is not job
    assert seen["wire"]["replay_identity"] == identity and seen["wire"]["replay_identity"] is not identity
    assert seen["wire"]["schema_versions"] == {"guard.app.status": 1}


def test_an_unprepared_resident_answers_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "ensure_resident_prerequisite", lambda home: False)
    with pytest.raises(CommandCapabilityUnavailableError):
        _call()


def test_a_transport_failure_answers_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "ensure_resident_prerequisite", lambda home: True)
    monkeypatch.setattr(module, "_resident_request", lambda **kwargs: (_ for _ in ()).throw(OSError("closed")))
    with pytest.raises(CommandCapabilityUnavailableError):
        _call()


def test_an_unbound_reply_answers_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "ensure_resident_prerequisite", lambda home: True)
    monkeypatch.setattr(module, "_resident_request", lambda **kwargs: {"status": "ok"})
    monkeypatch.setattr(module, "_payload", lambda response, bound, home: None)
    with pytest.raises(CommandCapabilityUnavailableError):
        _call()


def _issue_call(**overrides: Any) -> dict[str, object]:
    arguments: dict[str, Any] = {
        "requested": ("read-only",),
        "supported_operations": ("guard.app.status",),
        "issuer": "local-cli",
        "ttl_seconds": 86400,
        "guard_home": Path("/guard"),
    }
    arguments.update(overrides)
    return native_command_capability_issue(**arguments)


def test_the_issue_request_ships_the_words_as_typed(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture(monkeypatch, {"granted": True, "reason": None, "operations": ["guard.app.status"]})
    answer = _issue_call(requested=["read-only, guard.app.update", "guard.app.status"])
    assert answer == {"granted": True, "reason": None, "operations": ["guard.app.status"]}
    assert seen["operation"] == "command_capability_issue"
    assert seen["feature"] == module.COMMAND_CAPABILITY_ISSUE_FEATURE
    assert seen["wire"]["schema"] == module._ISSUE_REQUEST_SCHEMA
    assert seen["wire"]["requested"] == ["read-only, guard.app.update", "guard.app.status"]
    assert seen["wire"]["supported_operations"] == ["guard.app.status"]
    assert seen["wire"]["issuer"] == "local-cli"
    assert seen["wire"]["ttl_seconds"] == 86400
    assert seen["bound"] == seen["wire"]


def test_an_unprepared_resident_issues_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "ensure_resident_prerequisite", lambda home: False)
    with pytest.raises(CommandCapabilityUnavailableError):
        _issue_call()


def test_an_issue_transport_failure_answers_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "ensure_resident_prerequisite", lambda home: True)
    monkeypatch.setattr(module, "_resident_request", lambda **kwargs: (_ for _ in ()).throw(OSError("closed")))
    with pytest.raises(CommandCapabilityUnavailableError):
        _issue_call()


def test_an_unbound_issue_reply_answers_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "ensure_resident_prerequisite", lambda home: True)
    monkeypatch.setattr(module, "_resident_request", lambda **kwargs: {"status": "ok"})
    monkeypatch.setattr(module, "_payload", lambda response, bound, home: None)
    with pytest.raises(CommandCapabilityUnavailableError):
        _issue_call()
