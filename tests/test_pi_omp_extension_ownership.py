"""Current Pi and OMP ownership boundaries after legacy migration removal."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.pi import PiHarnessAdapter
from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.store import GuardStore


def _seed_extension(
    context: HarnessContext,
    *,
    install_harness: str,
    source_harness: str,
    modified: bool = False,
) -> tuple[Path, Path, Path]:
    settings_path = context.home_dir / f".{install_harness}" / "agent" / "settings.json"
    extension_path = settings_path.parent / "extensions" / "hol-guard.ts"
    user_path = extension_path.with_name("user-extension.ts")
    extension_path.parent.mkdir(parents=True, exist_ok=True)
    source = managed_extension_source(
        guard_home=context.guard_home,
        home_dir=context.home_dir,
        settings_path=settings_path,
        harness=source_harness,
        display_name="Pi" if source_harness == "pi" else "Oh My Pi",
    )
    if modified:
        source += "\n// User-owned customization must survive unrelated Pi operations.\n"
    extension_path.write_text(source, encoding="utf-8")
    user_path.write_text("export default 'user-owned';\n", encoding="utf-8")
    settings_path.write_text(
        json.dumps({"extensions": [str(extension_path), "./user-extension.ts"], "theme": "custom"}) + "\n",
        encoding="utf-8",
    )
    return extension_path, settings_path, user_path


@pytest.mark.parametrize("source_harness", ["pi", "omp"])
@pytest.mark.parametrize("modified", [False, True], ids=["original", "user-modified"])
def test_pi_uninstall_preserves_separate_omp_extension_and_user_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_harness: str,
    modified: bool,
) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard-home", workspace_dir=None)
    omp_extension, omp_settings, omp_user = _seed_extension(
        context, install_harness="omp", source_harness=source_harness, modified=modified
    )
    pi_extension, pi_settings, pi_user = _seed_extension(context, install_harness="pi", source_harness="pi")
    preserved = {path: path.read_bytes() for path in (omp_extension, omp_settings, omp_user, pi_user)}
    shim_calls: list[str] = []

    def remove_shim(harness: str, _context: HarnessContext, **_kwargs: object) -> dict[str, object]:
        shim_calls.append(harness)
        return {"notes": []}

    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.pi.remove_guard_shim", remove_shim)

    result = PiHarnessAdapter().uninstall(context)

    assert result["harness"] == "pi"
    assert result["active"] is False
    assert shim_calls == ["pi"]
    assert not pi_extension.exists()
    assert json.loads(pi_settings.read_text(encoding="utf-8")) == {
        "extensions": ["./user-extension.ts"],
        "theme": "custom",
    }
    assert {path: path.read_bytes() for path in preserved} == preserved


@pytest.mark.parametrize("source_harness", ["pi", "omp"])
@pytest.mark.parametrize("modified", [False, True], ids=["original", "user-modified"])
def test_update_does_not_migrate_untracked_omp_extension_from_pi_record(
    tmp_path: Path,
    source_harness: str,
    modified: bool,
) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard-home", workspace_dir=None)
    store = GuardStore(context.guard_home)
    omp_extension, omp_settings, omp_user = _seed_extension(
        context, install_harness="omp", source_harness=source_harness, modified=modified
    )
    pi_extension, _pi_settings, _pi_user = _seed_extension(context, install_harness="pi", source_harness="pi")
    store.set_managed_install("pi", True, None, {"config_path": str(pi_extension)}, "2026-08-05T00:00:00Z")
    preserved = {path: path.read_bytes() for path in (omp_extension, omp_settings, omp_user)}
    assert store.get_managed_install("omp") is None

    repaired, _notes = update_commands._repair_supported_harnesses_in_process(
        context=context,
        store=store,
        workspace=None,
        now="2026-08-05T00:00:01Z",
        dry_run=False,
    )

    assert all(item["harness"] != "omp" for item in repaired)
    assert store.get_managed_install("omp") is None
    assert {path: path.read_bytes() for path in preserved} == preserved
