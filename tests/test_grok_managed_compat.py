"""Grok managed-config compatibility merge tests for foreign hook imports."""

from __future__ import annotations

from pathlib import Path

import tomllib

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter
from codex_plugin_scanner.guard.adapters.grok_config import (
    build_managed_config_block,
    prepare_managed_config_text,
    remove_managed_block,
    restore_compat_hooks,
)


def _ctx(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )


class TestGrokManagedCompat:
    def test_managed_config_disables_foreign_hook_import(self) -> None:
        text = build_managed_config_block("guard hook --json")
        assert "[compat.claude]\nhooks = false" in text
        assert "[compat.cursor]\nhooks = false" in text

    def test_prepare_managed_config_does_not_duplicate_existing_compat_tables(self) -> None:
        existing = "[compat.claude]\nskills = true\nhooks = true\n\n[ui]\nsimple_mode = true\n"
        merged, prior = prepare_managed_config_text(existing, "guard hook --json")
        assert merged.count("[compat.claude]") == 1
        assert merged.count("[compat.cursor]") == 1
        assert prior["claude"] == "true"
        assert prior["cursor"] is None
        claude_block = merged.split("[compat.cursor]")[0]
        assert "hooks = false" in claude_block
        assert "skills = true" in claude_block
        tomllib.loads(merged)

    def test_prepare_managed_config_recognizes_commented_compat_headers(self) -> None:
        existing = "[compat.claude] # imported\nskills = true\nhooks = true\n"
        merged, prior = prepare_managed_config_text(existing, "guard hook --json")
        assert merged.count("[compat.claude]") == 1
        assert prior["claude"] == "true"
        tomllib.loads(merged)

    def test_prepare_managed_config_rewrites_indented_hooks_keys(self) -> None:
        existing = "[compat.claude]\n  hooks = true\n"
        merged, prior = prepare_managed_config_text(existing, "guard hook --json")
        assert prior["claude"] == "true"
        assert merged.count("[compat.claude]") == 1
        tomllib.loads(merged)

    def test_install_merges_preexisting_compat_tables(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        managed = ctx.home_dir / ".grok" / "managed_config.toml"
        managed.parent.mkdir(parents=True, exist_ok=True)
        managed.write_text("[compat.claude]\nskills = true\nhooks = true\n", encoding="utf-8")
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.grok.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-grok"), "notes": []},
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.grok.remove_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-grok"), "notes": []},
        )
        adapter = GrokHarnessAdapter()
        adapter.install(ctx)
        installed = managed.read_text(encoding="utf-8")
        assert installed.count("[compat.claude]") == 1
        assert "skills = true" in installed
        assert installed.count("hooks = false") >= 1
        adapter.install(ctx)
        adapter.uninstall(ctx)
        restored = managed.read_text(encoding="utf-8")
        assert "BEGIN HOL GUARD MANAGED GROK" not in restored
        assert "hooks = true" in restored
        assert "skills = true" in restored

    def test_repeated_install_keeps_original_compat_hooks_value(self) -> None:
        existing = "[compat.claude]\nhooks = true\n"
        first, prior = prepare_managed_config_text(existing, "guard hook --json")
        assert prior["claude"] == "true"
        second, prior_again = prepare_managed_config_text(
            first,
            "guard hook --json",
            saved_prior_hooks=prior,
        )
        assert prior_again["claude"] == "true"
        restored = restore_compat_hooks(remove_managed_block(second), prior_again)
        assert "hooks = true" in restored
