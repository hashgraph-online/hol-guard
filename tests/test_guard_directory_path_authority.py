"""What is left in Python once the runtime owns directory trust.

The verdicts themselves moved to the native runtime, which checks them in
`rust/crates/guard-runtime/src/directory_trust_tests.rs`. These cover the
spellings Python still computes for itself: the canonical Guard home a caller
needs before it can reach the resident, and the supply-chain root resolver. The
hook's own workspace spellings are the runtime's to settle, and
`rust/crates/guard-runtime/src/hook_path_rules_tests.rs` covers those rules.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import directory_path_authority
from codex_plugin_scanner.path_support import resolve_path_within_allowed_roots


def test_a_guard_home_keeps_one_spelling_however_it_is_written(tmp_path: Path) -> None:
    guard_home = tmp_path / "home" / ".hol-guard"
    guard_home.mkdir(parents=True)
    canonical = directory_path_authority.canonical_guard_home_path(guard_home)

    assert canonical == str(guard_home.resolve())
    assert directory_path_authority.canonical_guard_home_path(f"{guard_home}/a/..") == canonical


def test_a_guard_home_that_does_not_exist_still_has_one_spelling(tmp_path: Path) -> None:
    missing = tmp_path / "missing" / ".hol-guard"

    assert directory_path_authority.canonical_guard_home_path(missing) == str(missing)


def test_supply_chain_directory_validation_preserves_relative_path_and_existence_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.chdir(tmp_path)

    assert resolve_path_within_allowed_roots("root", (root,), require_exists=True) == root.resolve()
    assert resolve_path_within_allowed_roots("root/missing", (root,)) == root / "missing"
    assert resolve_path_within_allowed_roots("root/missing", (root,), require_exists=True) is None
    assert resolve_path_within_allowed_roots("root", (), require_exists=True) is None


def test_supply_chain_directory_validation_rejects_prefix_collisions_and_traversal(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    for relative in ("root-other", "root/../outside"):
        candidate = tmp_path / relative
        candidate.mkdir(parents=True, exist_ok=True)
        assert resolve_path_within_allowed_roots(str(candidate), (root,), require_exists=True) is None
