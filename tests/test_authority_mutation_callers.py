"""Bootstrap, rebind, uninstall, and legacy JSON removal through production callers."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import _hook_command_parts, codex_native_hook_state
from codex_plugin_scanner.guard.cli.bootstrap import _build_bootstrap_install
from codex_plugin_scanner.guard.cli.install_commands import apply_managed_install
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_hook_integrity import hook_manifest_path, hook_secret_path
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-10-02T00:00:00Z"
_LEGACY = "legacy-marker-command"


def _context(tmp_path: Path, name: str) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / name,
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
        home_override_explicit=True,
    )


def _legacy_sources(home: Path) -> None:
    codex = home / ".codex"
    codex.mkdir(parents=True)
    (codex / "config.toml").write_text('[features]\nhooks = true\nmodel = "legacy-marker-model"\n', encoding="utf-8")
    payload = {"hooks": {"FutureAgentEvent": [{"matcher": "Bash", "hooks": [{"type": "command", "command": _LEGACY}]}]}}
    (codex / "hooks.json").write_text(json.dumps(payload) + "\n", encoding="utf-8")


def test_bootstrap_rebind_and_uninstall_preserve_authority_and_legacy_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bootstrap, same-target rebind, and uninstall use the production caller entry points."""

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    guard = tmp_path / "guard-home"
    store = GuardStore(guard)
    first = _context(tmp_path, "first")
    _legacy_sources(first.home_dir)
    legacy_path = first.home_dir / ".codex" / "hooks.json"
    original_config = '[features]\nhooks = true\nmodel = "legacy-marker-model"\n'

    installed = _build_bootstrap_install(
        requested_harness="codex",
        skip_install=False,
        context=first,
        store=store,
    )
    assert installed["installed"] is True
    assert not legacy_path.exists()
    backups = list((guard / "managed" / "codex" / "migration-backups").glob("*.json"))
    assert any(json.loads(path.read_text(encoding="utf-8"))["content"] == original_config for path in backups)
    key = hook_secret_path(guard)
    key_identity = (key.stat().st_dev, key.stat().st_ino)
    assert codex_native_hook_state(first)["protection_active"] is True

    rebound = apply_managed_install("install", "codex", False, first, store, None, _NOW)
    assert rebound["managed_install"]["active"] is True
    assert (key.stat().st_dev, key.stat().st_ino) == key_identity
    assert codex_native_hook_state(first)["protection_active"] is True
    assert not legacy_path.exists()

    apply_managed_install("uninstall", "codex", False, first, store, None, _NOW)
    assert not key.exists()
    assert codex_native_hook_state(first)["protection_active"] is False
    assert not legacy_path.exists()
    journal = (guard / "managed" / "codex" / "authority-mutations.jsonl").read_text(encoding="utf-8")
    events = [json.loads(line) for line in journal.splitlines() if line.strip()]
    actors = {str(event["actor"]) for event in events}
    operations = {str(event["operation"]) for event in events}
    assert {"bootstrap.install", "managed.install", "managed.uninstall"} <= actors
    assert {"begin", "committed", "publish"} <= operations
    for event in events:
        encoded = json.dumps(event, separators=(",", ":"))
        assert event["schema"] == "hol-guard.codex-authority-mutation.v1"
        assert event["operation_id"]
        assert event["pid"] == os.getpid()
        assert _LEGACY not in encoded
        assert "legacy-marker-model" not in encoded
        assert "hook-manifest.key" not in encoded
    print(
        "pass callers=bootstrap,rebind,uninstall legacy_json_removed=true "
        "backup=original_config journal_actors=bootstrap.install,managed.install,managed.uninstall "
        "journal_private=false key_inode_stable=true last_uninstall_removes_key=true"
    )


def test_second_config_public_install_stays_fail_closed_beside_existing_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second config cannot mint authority from a key that already belongs to another install."""

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    guard = tmp_path / "guard-home"
    store = GuardStore(guard)
    first = _context(tmp_path, "first")
    second = _context(tmp_path, "second")
    _legacy_sources(first.home_dir)
    _legacy_sources(second.home_dir)
    second_config = second.home_dir / ".codex" / "config.toml"
    second_legacy = second.home_dir / ".codex" / "hooks.json"
    before_config = second_config.read_bytes()
    before_legacy = second_legacy.read_bytes()

    installed = _build_bootstrap_install(
        requested_harness="codex",
        skip_install=False,
        context=first,
        store=store,
    )
    assert installed["installed"] is True
    key = hook_secret_path(guard)
    key_identity = (key.stat().st_dev, key.stat().st_ino, key.stat().st_mtime_ns, key.stat().st_size)

    with pytest.raises(CodexHookIntegrityError) as failure:
        apply_managed_install("install", "codex", False, second, store, None, _NOW)

    assert failure.value.reason == "codex_hook_manifest_baseline_untrusted"
    cause = failure.value.__cause__
    assert isinstance(cause, CodexHookIntegrityError)
    assert cause.reason == "codex_hook_manifest_missing"
    assert not hook_manifest_path(guard, second_config).exists()
    assert second_config.read_bytes() == before_config
    assert second_legacy.read_bytes() == before_legacy
    after_key = key.stat()
    assert (after_key.st_dev, after_key.st_ino, after_key.st_mtime_ns, after_key.st_size) == key_identity
    assert codex_native_hook_state(first)["protection_active"] is True
    print(
        "H1 pass second_target_public_install=fail_closed "
        "reason=codex_hook_manifest_baseline_untrusted cause=codex_hook_manifest_missing "
        "first_retained=true key_rotated=false"
    )


def test_bootstrapped_hook_denies_a_missing_manifest_without_replacing_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The installed bridge reports the missing manifest and leaves the key in place."""

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    guard = tmp_path / "guard-home"
    context = _context(tmp_path, "home")
    _legacy_sources(context.home_dir)
    installed = _build_bootstrap_install(
        requested_harness="codex",
        skip_install=False,
        context=context,
        store=GuardStore(guard),
    )
    assert installed["installed"] is True
    config = context.home_dir / ".codex" / "config.toml"
    before_config = config.read_bytes()
    secret = hook_secret_path(guard)
    before_secret = secret.stat()
    manifest = hook_manifest_path(guard, config)
    argv = _hook_command_parts(context)
    manifest.unlink()

    result = subprocess.run(
        argv,
        input=json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "true"},
            }
        ),
        capture_output=True,
        text=True,
        timeout=20,
        env={**os.environ, "HOME": str(context.home_dir), "USERPROFILE": str(context.home_dir)},
        check=False,
    )
    assert result.returncode == 0, result.stderr
    response = json.loads(result.stdout)
    diagnostic = json.loads(result.stderr)
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert diagnostic["schema"] == "hol-guard.codex-bridge-failure.v1"
    assert any(cause["reason_code"] == "codex_hook_manifest_missing" for cause in diagnostic["causes"])
    assert config.read_bytes() == before_config
    assert not manifest.exists()
    after_secret = secret.stat()
    assert (after_secret.st_dev, after_secret.st_ino, after_secret.st_mtime_ns, after_secret.st_size) == (
        before_secret.st_dev,
        before_secret.st_ino,
        before_secret.st_mtime_ns,
        before_secret.st_size,
    )
    assert codex_native_hook_state(context)["protection_active"] is False
    print("H1 pass caller=bootstrap bridge_decision=deny reason=codex_hook_manifest_missing key_rotated=false")
