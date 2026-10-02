from __future__ import annotations

from pathlib import Path

import pytest

from tests import conftest


def test_native_hook_runtime_requires_explicit_artifact_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOL_GUARD_NATIVE_BINARY", raising=False)

    with pytest.raises(pytest.fail.Exception, match="must explicitly name the compiled Rust runtime"):
        conftest._resolve_native_hook_runtime()


def test_native_hook_runtime_resolves_explicit_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "pinned" / "hol-guard-runtime"
    runtime.parent.mkdir()
    runtime.write_bytes(b"pinned artifact")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(runtime))

    assert conftest._resolve_native_hook_runtime() == runtime.resolve()


def test_native_hook_runtime_rejects_missing_explicit_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "missing" / "hol-guard-runtime"
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(runtime))

    with pytest.raises(pytest.fail.Exception, match="does not name an existing runtime file"):
        conftest._resolve_native_hook_runtime()
