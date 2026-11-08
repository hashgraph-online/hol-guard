from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import install_commands, install_workspace
from codex_plugin_scanner.guard.native_directory_trust import DirectoryTrustVerdict, NativeDirectoryTrustError


def context(tmp_path: Path, *, explicit: bool = True) -> HarnessContext:
    home = tmp_path / "home"
    return HarnessContext(
        home, tmp_path / "other-volume" / "project", home / ".hol-guard", workspace_override_explicit=explicit
    )


def test_rejected_explicit_workspace_stops_before_any_adapter_or_store_write(tmp_path, monkeypatch):
    ctx = context(tmp_path)
    calls = []
    monkeypatch.setattr(install_commands, "assert_transition_mutation_allowed", lambda *_: None)
    monkeypatch.setattr(install_commands, "_resolve_targets", lambda *_: ["claude-code", "codex"])
    monkeypatch.setattr(install_commands, "get_adapter", lambda *_: pytest.fail("adapter reached"))

    def reject(candidates, **kwargs):
        calls.append((candidates, kwargs))
        return [DirectoryTrustVerdict("workspace", None, "unexpected_root")]

    monkeypatch.setattr(install_workspace, "native_directory_trust", reject)
    with pytest.raises(ValueError, match=r"before changing its configuration.*unexpected_root"):
        install_commands._apply_managed_install_owned(
            "install", None, True, ctx, SimpleNamespace(), str(ctx.workspace_dir), "2026-11-08T00:00:00Z"
        )
    assert calls == [
        ([("workspace", str(ctx.workspace_dir))], {"guard_home": ctx.guard_home, "home_dir": ctx.home_dir})
    ]


def test_supported_workspace_uses_native_answer(tmp_path, monkeypatch):
    ctx = context(tmp_path)
    monkeypatch.setattr(
        install_workspace,
        "native_directory_trust",
        lambda *a, **kw: [DirectoryTrustVerdict("workspace", str(ctx.workspace_dir), None)],
    )
    install_workspace.require_supported_codex_workspace(ctx)


def test_native_unavailability_is_not_workspace_clearance(tmp_path, monkeypatch):
    def unavailable(*args, **kwargs):
        raise NativeDirectoryTrustError("native_directory_trust_unavailable")

    monkeypatch.setattr(install_workspace, "native_directory_trust", unavailable)
    with pytest.raises(ValueError, match="could not validate --workspace"):
        install_workspace.require_supported_codex_workspace(context(tmp_path))


def test_implicit_workspace_does_not_add_an_install_gate(tmp_path, monkeypatch):
    monkeypatch.setattr(
        install_workspace, "native_directory_trust", lambda *a, **kw: pytest.fail("implicit workspace was checked")
    )
    install_workspace.require_supported_codex_workspace(context(tmp_path, explicit=False))
