"""The incident path must not load an unbounded authenticated manifest."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.codex_hook_integrity import (
    _MAX_HOOK_MANIFEST_BYTES,
    CodexHookIntegrityError,
    load_authenticated_hook_manifest_path,
)


def test_oversized_codex_manifest_is_rejected_before_parsing(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    manifest_path = guard_home / "managed" / "codex" / "oversized.manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_bytes(b" " * (_MAX_HOOK_MANIFEST_BYTES + 1))
    manifest_path.chmod(0o600)

    with pytest.raises(CodexHookIntegrityError) as failure:
        load_authenticated_hook_manifest_path(guard_home, manifest_path)

    assert failure.value.reason == "codex_hook_manifest_invalid"
