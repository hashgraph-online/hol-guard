"""Shared legacy-Python vectors, run through the portable Python code and the real resident."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.portable_skill_directory_discovery import (
    discover_skill_documents as portable_discover,
)
from codex_plugin_scanner.guard.portable_skill_directory_identity import (
    inspect_skill_directory as portable_inspect,
)
from codex_plugin_scanner.guard.skill_directory_discovery import discover_skill_documents as native_discover
from codex_plugin_scanner.guard.skill_directory_identity import inspect_skill_directory as native_inspect
from codex_plugin_scanner.guard.skill_directory_identity_contract import SkillDirectoryIdentityLimits

_VECTORS = json.loads(
    (
        Path(__file__).resolve().parent.parent
        / "rust/crates/guard-runtime/tests/fixtures/skill_directory_identity_vectors.json"
    ).read_text(encoding="utf-8")
)
_WIRE_FIELDS = (
    "status",
    "directory_hash",
    "primary_content_hash",
    "entry_count",
    "total_bytes",
    "failure_reason",
    "incomplete_state_hash",
)
_IMPLEMENTATIONS: dict[str, tuple[Callable[..., Any], Callable[..., Any]]] = {
    "portable": (portable_inspect, portable_discover),
    "native": (native_inspect, native_discover),
}

pytestmark = pytest.mark.skipif(os.name == "nt", reason="vectors use POSIX modes, symlinks and fifos")


def _native_forced() -> bool:
    return os.environ.get("HOL_GUARD_NATIVE_REGRESSION") == "1" and bool(os.environ.get("HOL_GUARD_NATIVE_BINARY"))


def _skip_unavailable(implementation: str) -> None:
    if implementation == "native" and not _native_forced():
        pytest.skip("native runtime binary is not provisioned for this run")


def _build(base: Path, spec: dict[str, Any]) -> None:
    directory_modes: list[tuple[Path, int]] = []
    for entry in spec["entries"]:
        path = base / entry["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        kind = entry["type"]
        mode = int(entry.get("mode", "0644"), 8)
        if kind == "dir":
            path.mkdir(exist_ok=True)
            directory_modes.append((path, mode))
        elif kind == "file":
            data = bytes.fromhex(entry["content_hex"]) if "content_hex" in entry else entry["content"].encode()
            path.write_bytes(data)
            path.chmod(mode)
        elif kind == "symlink":
            target = entry["target"]
            path.symlink_to(str(base / target["base_relative"]) if isinstance(target, dict) else target)
        elif kind == "fifo":
            os.mkfifo(path)
        else:  # pragma: no cover - fixture authoring error
            raise AssertionError(kind)
    for path, mode in sorted(directory_modes, key=lambda item: len(item[0].parts), reverse=True):
        path.chmod(mode)


def _restore_modes(base: Path) -> None:
    for current, directories, _files in os.walk(base):
        os.chmod(current, 0o755)
        for name in directories:
            candidate = Path(current, name)
            if not candidate.is_symlink():
                candidate.chmod(0o755)


def _limits(spec: dict[str, Any]) -> SkillDirectoryIdentityLimits:
    return SkillDirectoryIdentityLimits(**spec.get("limits", {}))


def _expected(spec: dict[str, Any]) -> dict[str, Any]:
    expected = dict(spec["expected"])
    if sys.platform.startswith("linux"):
        # A symlink's own lstat mode is hashed and differs by platform.
        expected.update(spec.get("expected_linux", {}))
    return expected


@pytest.mark.parametrize("implementation", sorted(_IMPLEMENTATIONS))
@pytest.mark.parametrize("spec", _VECTORS["inspect"], ids=lambda spec: spec["name"])
def test_inspect_matches_shared_vectors(tmp_path: Path, spec: dict[str, Any], implementation: str) -> None:
    _skip_unavailable(implementation)
    base = tmp_path.resolve() / "case"
    base.mkdir()
    _build(base, spec)
    try:
        inspect, _ = _IMPLEMENTATIONS[implementation]
        identity = inspect(
            base / spec["document"],
            scope_root=base / spec.get("scope", ""),
            limits=_limits(spec),
        )
        expected = _expected(spec)
        assert {field: getattr(identity, field) for field in _WIRE_FIELDS} == {
            field: expected[field] for field in _WIRE_FIELDS
        }
    finally:
        _restore_modes(base)


@pytest.mark.parametrize("implementation", sorted(_IMPLEMENTATIONS))
@pytest.mark.parametrize("spec", _VECTORS["discover"], ids=lambda spec: spec["name"])
def test_discovery_matches_shared_vectors(tmp_path: Path, spec: dict[str, Any], implementation: str) -> None:
    _skip_unavailable(implementation)
    base = tmp_path.resolve() / "case"
    base.mkdir()
    _build(base, spec)
    try:
        _, discover = _IMPLEMENTATIONS[implementation]
        root = base / spec["root"]
        discovery = discover(root, limits=_limits(spec))
        assert [path.relative_to(root).as_posix() for path in discovery.documents] == spec["expected"]["documents"]
        assert [
            {"relative_path": issue.relative_path, "failure_reason": issue.failure_reason, "issue_id": issue.issue_id}
            for issue in discovery.issues
        ] == spec["expected"]["issues"]
        assert all(issue.identity.status == "incomplete" for issue in discovery.issues)
    finally:
        _restore_modes(base)
