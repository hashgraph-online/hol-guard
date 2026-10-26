"""Real caller integration for lossless native skill-tree inspection."""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_skill_directory_identity as client
from codex_plugin_scanner.guard.skill_directory_discovery import discover_skill_documents
from codex_plugin_scanner.guard.skill_directory_identity import inspect_skill_directory

FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "rust/crates/guard-runtime/tests/fixtures/skill_directory_portable_vectors.json"
    ).read_text()
)


@pytest.mark.skipif(os.environ.get("HOL_GUARD_NATIVE_REGRESSION") != "1", reason="Requires the compiled native runtime")
def test_platform_caller_matches_original_basic_digest(tmp_path: Path) -> None:
    case = next(case for case in FIXTURE["inspect"] if case["name"] == "basic")
    document = tmp_path / case["document"]
    document.parent.mkdir(parents=True)
    document.write_bytes(case["entries"][0]["content"].encode())
    if os.name != "nt":
        document.chmod(0o644)
    identity = inspect_skill_directory(document, scope_root=tmp_path)
    expected = case["expected_windows_mode_projection"] if os.name == "nt" else case["expected"]
    assert dataclasses.asdict(identity) == expected
    assert discover_skill_documents(tmp_path).documents == (document,)
    missing = discover_skill_documents(tmp_path / "missing")
    assert missing.documents == () and missing.issues == ()
    document.write_bytes(b"changed")
    assert inspect_skill_directory(document, scope_root=tmp_path).directory_hash != identity.directory_hash


@pytest.mark.skipif(
    os.name == "nt" or not os.sys.platform.startswith("linux"), reason="Requires a byte-name filesystem"
)
def test_non_utf8_root_is_served_by_native_and_invalid_child_is_not_hidden(tmp_path: Path) -> None:
    root = tmp_path / os.fsdecode(b"root-\xff")
    root.mkdir()
    document = root / "SKILL.md"
    document.write_bytes(b"fixture")
    assert inspect_skill_directory(document, scope_root=tmp_path).status == "complete"
    assert discover_skill_documents(root).documents == (document,)
    (root / os.fsdecode(b"child-\xff")).write_bytes(b"fixture")
    identity = inspect_skill_directory(document, scope_root=tmp_path)
    assert identity.status == "incomplete"
    assert identity.failure_reason == "invalid_path_encoding"


def test_native_unavailable_has_no_portable_algorithm(monkeypatch, tmp_path: Path) -> None:
    document = tmp_path / "SKILL.md"
    document.write_bytes(b"fixture")
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _: False)
    identity = inspect_skill_directory(document, scope_root=tmp_path)
    assert identity.status == "incomplete"
    assert identity.failure_reason == "native_unavailable"
    assert identity.directory_hash is None


def test_setup_does_not_restart_skill_request_deadline(monkeypatch, tmp_path: Path) -> None:
    from types import SimpleNamespace

    clock = [0.0]
    monkeypatch.setattr(client, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    def prerequisite(_home):
        clock[0] = 61.0
        return True

    monkeypatch.setattr(client, "ensure_resident_prerequisite", prerequisite)
    monkeypatch.setattr(client, "native_runtime_status", lambda **_: SimpleNamespace(available=True, compatible=True))
    monkeypatch.setattr(client, "_resident_request", lambda **kwargs: pytest.fail("Expired requests must not be sent"))
    assert inspect_skill_directory(tmp_path / "SKILL.md", scope_root=tmp_path).failure_reason == "native_unavailable"
