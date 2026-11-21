"""Grok managed-config compatibility merge tests for foreign hook imports."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.shims import PreparedGuardShim
from tests import harness_ops_support as harness_support


def _ctx(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )


class TestGrokManagedCompat:
    def test_install_merges_preexisting_compat_tables(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        managed = ctx.home_dir / ".grok" / "config.toml"
        managed.parent.mkdir(parents=True, exist_ok=True)
        managed.write_text("[compat.claude]\nskills = true\nhooks = true\n", encoding="utf-8")
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.shims.prepare_guard_shim",
            lambda *args, **kwargs: PreparedGuardShim(
                (), {"shim_path": str(ctx.guard_home / "bin" / "guard-grok"), "notes": []}
            ),
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.shims.remove_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-grok"), "notes": []},
        )
        harness_support.install("grok", ctx)
        installed = managed.read_text(encoding="utf-8")
        assert installed.count("[compat.claude]") == 1
        assert "skills = true" in installed
        assert installed.count("hooks = false") >= 1
        harness_support.install("grok", ctx)
        harness_support.uninstall("grok", ctx)
        restored = managed.read_text(encoding="utf-8")
        assert "BEGIN HOL GUARD MANAGED GROK" not in restored
        assert "hooks = true" in restored
        assert "skills = true" in restored
