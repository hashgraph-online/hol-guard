"""Regression coverage for Paseo's path, repair, and public coverage boundaries."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.contracts import setup_contract_for
from codex_plugin_scanner.guard.adapters.paseo import PaseoHarnessAdapter
from codex_plugin_scanner.guard.adapters.paseo_config import paseo_providers, require_local_path
from codex_plugin_scanner.guard.adapters.paseo_install import receipt_path
from tests.test_paseo_adapter import configure
from tests.test_paseo_adapter import context as context


@pytest.mark.parametrize("provider", ["opencode", "copilot"])
@pytest.mark.parametrize("origin", ["ambient", "provider"])
@pytest.mark.parametrize("relocated", [False, True])
def test_xdg_config_home_only_rejects_relocated_roots(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch, provider: str, origin: str, relocated: bool
) -> None:
    """Linux's ordinary default XDG root does not silently drop native coverage."""
    value = str(context.home_dir / ("elsewhere" if relocated else ".config"))
    entry = {"enabled": True}
    if origin == "ambient":
        monkeypatch.setenv("XDG_CONFIG_HOME", value)
    else:
        entry["env"] = {"XDG_CONFIG_HOME": value}
    configure(context, {provider: entry})
    profile = next(item for item in paseo_providers(context) if item.provider_id == provider)
    assert bool(profile.unsupported_reason) is relocated


@pytest.mark.security_critical
@pytest.mark.parametrize("inside_home", [False, True])
def test_nonexistent_guard_root_cannot_hide_a_symlinked_ancestor(
    context: HarnessContext, tmp_path: Path, inside_home: bool
) -> None:
    """Reject redirected launcher roots before any shared native installation starts."""
    outside = tmp_path / "escape"
    outside.mkdir()
    ancestor = (context.home_dir if inside_home else tmp_path) / "redirected"
    ancestor.symlink_to(outside, target_is_directory=True)
    redirected = replace(context, guard_home=ancestor / "state" / "guard")
    configure(redirected, {"pi": {"enabled": True}})
    with pytest.raises(ValueError, match="symlink"):
        PaseoHarnessAdapter().install(redirected)
    assert list(outside.iterdir()) == []
    assert not (context.home_dir / ".pi").exists()


def test_symlinked_user_home_remains_an_explicit_path_anchor(tmp_path: Path) -> None:
    """The user's declared home may be a link, but links inside it remain forbidden."""
    actual_home = tmp_path / "actual"
    actual_home.mkdir()
    home = tmp_path / "home"
    home.symlink_to(actual_home, target_is_directory=True)
    root = home / ".local/state/guard"
    require_local_path(root, root / "bin/guard-paseo", home_dir=home)
    (actual_home / ".local").symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        require_local_path(root, root / "bin/guard-paseo", home_dir=home)


def test_failed_repair_keeps_receipt_but_detects_changed_artifacts(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keeping an old receipt cannot hide artifact drift caused by a failed repair."""
    configure(context, {"pi": {"enabled": True}})
    adapter = PaseoHarnessAdapter()
    adapter.install(context)
    original = receipt_path(context).read_bytes()

    def fail_after_write(*_args: object) -> None:
        """Simulate a native installer which changes one file and then fails."""
        (context.home_dir / ".pi/agent/extensions/hol-guard.ts").write_text("changed", encoding="utf-8")
        raise ValueError("installation failed")

    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.paseo.install_native", fail_after_write)
    with pytest.raises(ValueError, match="installation failed"):
        adapter.install(context)
    assert receipt_path(context).read_bytes() == original
    assert adapter.diagnostics(context)["setup_status"] == "broken"


def test_paseo_setup_contract_has_no_composite_browser_fallback() -> None:
    """Approvals remain native-provider-specific, never a claimed Paseo endpoint."""
    contract = setup_contract_for("paseo")
    assert contract is not None
    assert contract.to_dict()["coverage"]["browser_fallback"] is False
