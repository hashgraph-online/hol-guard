"""Transport contract for native skill-directory identity: bound, strict, fail closed."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_skill_directory_identity as transport
from codex_plugin_scanner.guard.skill_directory_identity_contract import (
    SKILL_DIRECTORY_IDENTITY_SCHEMA,
    SkillDirectoryIdentityLimits,
)

_HASH_A = "sha256:" + "a" * 64
_HASH_B = "sha256:" + "b" * 64
_LIMITS = SkillDirectoryIdentityLimits()


def _complete_payload() -> dict[str, Any]:
    return {
        "schema_version": SKILL_DIRECTORY_IDENTITY_SCHEMA,
        "status": "complete",
        "directory_hash": _HASH_A,
        "primary_content_hash": _HASH_B,
        "entry_count": 2,
        "total_bytes": 10,
        "failure_reason": None,
        "incomplete_state_hash": None,
    }


def _incomplete_payload(reason: str = "unreadable_entry") -> dict[str, Any]:
    return {
        **_complete_payload(),
        "status": "incomplete",
        "directory_hash": None,
        "primary_content_hash": None,
        "failure_reason": reason,
        "incomplete_state_hash": _HASH_A,
    }


def _install(monkeypatch: pytest.MonkeyPatch, payload: object, **overrides: object) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []

    def fake_request(**kwargs: Any) -> dict[str, Any]:
        request = kwargs["request"]
        seen.append(request)
        response: dict[str, Any] = {
            "schema": "guard-skill-directory-identity-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + transport._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload,
        }
        response.update(overrides)
        return response

    monkeypatch.setattr(transport, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(transport, "_resident_request", fake_request)
    return seen


def _inspect(tmp_path: Path):
    return transport.native_inspect_skill_directory(
        tmp_path / "skill" / "SKILL.md",
        scope_root=tmp_path,
        limits=_LIMITS,
    )


def test_inspect_decodes_bound_complete_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _install(monkeypatch, _complete_payload())

    identity = _inspect(tmp_path)

    assert identity.status == "complete"
    assert identity.directory_hash == _HASH_A
    assert seen[0]["command"]["kind"] == "inspect"
    assert Path(seen[0]["command"]["skill_document"]).is_absolute()


@pytest.mark.parametrize(
    "override",
    [
        {"request_id": "other"},
        {"request_sha256": _HASH_A},
        {"schema": "guard-skill-directory-identity-result.v0"},
        {"status": "error"},
        {"code": "native_skill_directory_identity_path_invalid"},
    ],
)
def test_inspect_binding_mismatch_is_native_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, override: dict[str, object]
) -> None:
    _install(monkeypatch, _complete_payload(), **override)

    identity = _inspect(tmp_path)

    assert identity.status == "incomplete"
    assert identity.failure_reason == "native_unavailable"
    assert identity.incomplete_state_hash == transport._UNAVAILABLE_STATE_HASH


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.pop("entry_count"),
        lambda p: p.update(extra=1),
        lambda p: p.update(directory_hash="sha256:short"),
        lambda p: p.update(entry_count=True),
        lambda p: p.update(entry_count=-1),
        lambda p: p.update(schema_version="other"),
        lambda p: p.update(status="unknown"),
        lambda p: p.update(failure_reason="made_up"),
        lambda p: p.update(incomplete_state_hash=_HASH_A),
    ],
)
def test_inspect_malformed_complete_payload_is_native_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutate: Any
) -> None:
    payload = _complete_payload()
    mutate(payload)
    _install(monkeypatch, payload)

    assert _inspect(tmp_path).failure_reason == "native_unavailable"


def test_inspect_incomplete_requires_state_hash_and_known_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, _incomplete_payload("tree_changed_during_hash"))
    assert _inspect(tmp_path).failure_reason == "tree_changed_during_hash"

    bad = _incomplete_payload()
    bad["incomplete_state_hash"] = None
    _install(monkeypatch, bad)
    assert _inspect(tmp_path).failure_reason == "native_unavailable"

    # The Python-only sentinel is never accepted from the runtime.
    _install(monkeypatch, _incomplete_payload("native_unavailable"))
    assert _inspect(tmp_path).incomplete_state_hash == transport._UNAVAILABLE_STATE_HASH


def test_runtime_prerequisite_missing_is_native_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport, "ensure_resident_prerequisite", lambda _home: False)

    assert _inspect(tmp_path).failure_reason == "native_unavailable"


def _discovery_payload(root: Path) -> dict[str, Any]:
    return {
        "documents_hex": [b"a/SKILL.md".hex()],
        "issues": [
            {
                "relative_path_hex": b"b".hex(),
                "failure_reason": "unreadable_entry",
                "issue_id": "0123456789abcdef",
                "identity": _incomplete_payload("unreadable_entry"),
            }
        ],
    }


def test_discovery_decodes_documents_and_issues(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _install(monkeypatch, _discovery_payload(tmp_path))

    discovery = transport.native_discover_skill_documents(tmp_path, limits=_LIMITS)

    assert discovery.documents == (tmp_path / "a" / "SKILL.md",)
    assert discovery.issues[0].path == tmp_path / "b"
    assert discovery.issues[0].issue_id == "0123456789abcdef"
    assert seen[0]["command"]["kind"] == "discover"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p["documents_hex"].append(b"../escape/SKILL.md".hex()),
        lambda p: p["documents_hex"].append(b"/abs/SKILL.md".hex()),
        lambda p: p["documents_hex"].append("zz"),
        lambda p: p["issues"][0].update(issue_id="short"),
        lambda p: p["issues"][0].update(failure_reason="unreadable_entry", extra=1),
        lambda p: p["issues"][0]["identity"].update(failure_reason="tree_changed_during_hash"),
        lambda p: p.update(extra=[]),
    ],
)
def test_discovery_malformed_payload_yields_single_native_unavailable_issue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutate: Any
) -> None:
    payload = _discovery_payload(tmp_path)
    mutate(payload)
    _install(monkeypatch, payload)

    discovery = transport.native_discover_skill_documents(tmp_path, limits=_LIMITS)

    assert discovery.documents == ()
    assert len(discovery.issues) == 1
    issue = discovery.issues[0]
    assert issue.failure_reason == "native_unavailable"
    assert issue.issue_id == transport._UNAVAILABLE_ISSUE_ID
    assert issue.path == tmp_path


def test_missing_root_without_a_runtime_is_an_empty_discovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport, "ensure_resident_prerequisite", lambda _home: False)

    discovery = transport.native_discover_skill_documents(tmp_path / "absent", limits=_LIMITS)

    assert discovery.documents == ()
    assert discovery.issues == ()


def test_existing_root_without_a_runtime_is_one_unavailable_issue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(transport, "ensure_resident_prerequisite", lambda _home: False)

    discovery = transport.native_discover_skill_documents(tmp_path, limits=_LIMITS)

    assert discovery.documents == ()
    assert [issue.failure_reason for issue in discovery.issues] == ["native_unavailable"]


def test_portable_python_is_required_on_windows_and_for_non_utf8_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert not transport.portable_python_required(tmp_path / "SKILL.md", tmp_path)
    assert transport.portable_python_required(tmp_path / os.fsdecode(b"bad-\xff-name") / "SKILL.md")
    monkeypatch.setattr(transport, "_is_windows", lambda: True)
    assert transport.portable_python_required(tmp_path)


def test_wrappers_route_to_portable_python_where_native_cannot_serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import skill_directory_discovery as discovery_module
    from codex_plugin_scanner.guard import skill_directory_identity as identity_module

    calls: list[str] = []
    for module, native_name, portable_name in (
        (identity_module, "native_inspect_skill_directory", "portable_inspect_skill_directory"),
        (discovery_module, "native_discover_skill_documents", "portable_discover_skill_documents"),
    ):
        monkeypatch.setattr(module, native_name, lambda *a, **k: calls.append("native"))
        monkeypatch.setattr(module, portable_name, lambda *a, **k: calls.append("portable"))
    monkeypatch.setattr(identity_module, "portable_python_required", lambda *paths: True)
    monkeypatch.setattr(discovery_module, "portable_python_required", lambda *paths: True)

    identity_module.inspect_skill_directory(tmp_path / "SKILL.md", scope_root=tmp_path)
    discovery_module.discover_skill_documents(tmp_path)
    assert calls == ["portable", "portable"]

    monkeypatch.setattr(identity_module, "portable_python_required", lambda *paths: False)
    monkeypatch.setattr(discovery_module, "portable_python_required", lambda *paths: False)
    identity_module.inspect_skill_directory(tmp_path / "SKILL.md", scope_root=tmp_path)
    discovery_module.discover_skill_documents(tmp_path)
    assert calls == ["portable", "portable", "native", "native"]
