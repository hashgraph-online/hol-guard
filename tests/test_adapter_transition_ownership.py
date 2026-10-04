from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import list_adapters
from codex_plugin_scanner.guard.adapters.base import HarnessAdapter, HarnessContext
from codex_plugin_scanner.guard.codex_install_transaction import require_codex_install_owner
from codex_plugin_scanner.guard.runtime_transition import TransitionError


class WritingAdapter(HarnessAdapter):
    harness = "ownership-fixture"

    def install(self, context, *, surface="fixture"):
        (context.home_dir / "binding").write_text(surface)
        return {"surface": surface}


def context(root):
    return HarnessContext(home_dir=root, guard_home=root / "guard", workspace_dir=None)


def test_direct_adapter_cannot_write_during_pending_transition(tmp_path: Path):
    ctx = context(tmp_path)
    record = ctx.guard_home / "managed/runtime-transition.json"
    record.parent.mkdir(parents=True)
    record.write_text("{}")
    with pytest.raises(TransitionError, match="pending_transition"):
        WritingAdapter().install(ctx, surface="candidate")
    assert not (tmp_path / "binding").exists()


@pytest.mark.parametrize("operation", ["create_key", "write_manifest", "remove_manifest", "remove_key"])
def test_direct_codex_authority_writer_cannot_mutate_pending_inverse(tmp_path: Path, operation: str):
    from codex_plugin_scanner.guard.codex_hook_integrity import (
        hook_manifest_path,
        hook_secret_path,
        load_or_create_hook_secret,
        remove_hook_manifest,
        remove_hook_secret_if_unused,
        write_hook_manifest,
    )

    ctx = context(tmp_path)
    config = tmp_path / "codex-hooks.json"
    if operation != "create_key":
        load_or_create_hook_secret(ctx.guard_home)
    if operation == "remove_manifest":
        write_hook_manifest(ctx.guard_home, config, {"fixture": "previous"})
    paths = [hook_secret_path(ctx.guard_home), hook_manifest_path(ctx.guard_home, config)]
    before = [path.read_bytes() if path.exists() else None for path in paths]
    journal = ctx.guard_home / "managed/runtime-transition.json"
    journal.parent.mkdir(parents=True, exist_ok=True)
    journal.write_bytes(b"pending fixture inverse")
    journal.chmod(0o600)
    with pytest.raises(TransitionError, match="pending_transition"):
        if operation == "create_key":
            load_or_create_hook_secret(ctx.guard_home)
        elif operation == "write_manifest":
            write_hook_manifest(ctx.guard_home, config, {"fixture": "candidate"})
        elif operation == "remove_manifest":
            remove_hook_manifest(ctx.guard_home, config)
        else:
            remove_hook_secret_if_unused(ctx.guard_home)
    assert [path.read_bytes() if path.exists() else None for path in paths] == before
    assert journal.read_bytes() == b"pending fixture inverse"


@pytest.mark.parametrize("harness", [adapter.harness for adapter in list_adapters()])
def test_install_preparation_is_complete_or_explicitly_unavailable(tmp_path: Path, harness: str):
    adapter = next(adapter for adapter in list_adapters() if adapter.harness == harness)
    ctx = context(tmp_path)
    if harness == "codex":
        from codex_plugin_scanner.guard.codex_hook_integrity import CodexHookIntegrityError

        with pytest.raises(CodexHookIntegrityError) as failure:
            adapter.prepare_install(ctx)
        assert failure.value.reason == "codex_hook_manifest_secret_missing"
        assert not ctx.guard_home.exists()
        return
    if harness in {"copilot", "cursor"}:
        with pytest.raises(TransitionError, match="adapter_preparation_authority_missing"):
            adapter.prepare_install(ctx)
        assert not ctx.guard_home.exists()
        return
    supported = {
        "gemini",
        "antigravity",
        "claude-code",
        "kimi",
        "openclaw",
        "grok",
        "zcode",
        "pi",
        "omp",
        "devin",
        "opencode",
    }
    if harness in supported:
        prepared = adapter.prepare_install(ctx)
        expected = {
            "claude-code": 3,
            "kimi": 3,
            "openclaw": 5,
            "grok": 9,
            "zcode": 5,
            "pi": 4,
            "omp": 4,
            "devin": 5,
            "opencode": 9,
        }.get(harness, 2)
        assert len(prepared.files) == expected
        assert prepared.manifest["harness"] == harness
        assert prepared.manifest["active"] is True
        assert all(change.after is not None or change.before == change.after for change in prepared.files)
    else:
        with pytest.raises(TransitionError, match="adapter_preparation_unavailable"):
            adapter.prepare_install(ctx)
    assert not ctx.guard_home.exists()


@pytest.mark.parametrize("harness,expected", [("kimi", 4), ("grok", 10), ("zcode", 6), ("devin", 6)])
def test_frozen_preparation_includes_helper_without_publishing(tmp_path, monkeypatch, harness, expected):
    from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge as bridge
    from codex_plugin_scanner.guard.adapters import get_adapter

    ctx = context(tmp_path)
    monkeypatch.setattr(bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bridge, "isolated_cursor_hook_python", lambda: sys.executable)
    monkeypatch.setattr(bridge, "_trusted_desktop_hook_proxy_command", lambda *args: None)
    prepared = get_adapter(harness).prepare_install(ctx)
    assert len(prepared.files) == expected
    helper = next(change for change in prepared.files if change.path.suffix == ".py")
    assert helper.path == ctx.guard_home / f"managed/bounded-hooks/{harness}.py"
    assert helper.no_follow
    assert helper.before is None and helper.after is not None
    assert helper.after_mode == 0o600
    assert not ctx.guard_home.exists()


@pytest.mark.parametrize("previous_exists", [False, True])
def test_opencode_prepared_generation_matches_normal_install(tmp_path, previous_exists):
    from codex_plugin_scanner.guard.adapters.opencode import OpenCodeHarnessAdapter

    ctx = context(tmp_path)
    config = ctx.home_dir / ".config/opencode/opencode.json"
    config.parent.mkdir(parents=True)
    config.write_text('{"user_setting": true, "mcp": {"user": {"type": "local", "command": ["node", "user.js"]}}}')
    adapter = OpenCodeHarnessAdapter()
    if previous_exists:
        adapter.install(ctx)
    prepared = adapter.prepare_install(ctx)
    manifest = adapter.install(ctx)
    assert prepared.manifest == manifest
    for change in prepared.files:
        if change.after is None:
            assert not change.path.exists()
        else:
            assert change.path.read_bytes() == change.after


@pytest.mark.parametrize("workspace_enabled", [False, True])
def test_frozen_copilot_preparation_plans_helper_without_publication(tmp_path, monkeypatch, workspace_enabled):
    from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge as bridge
    from codex_plugin_scanner.guard.adapters.adapter_state_integrity import authenticate_adapter_state
    from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter

    ctx = HarnessContext(
        home_dir=tmp_path,
        guard_home=tmp_path / "guard",
        workspace_dir=tmp_path / "workspace" if workspace_enabled else None,
    )
    authenticate_adapter_state(ctx.guard_home, harness="copilot", payload={"enrollment": "fixture"})
    monkeypatch.setattr(bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bridge, "isolated_cursor_hook_python", lambda: sys.executable)
    monkeypatch.setattr(bridge, "_trusted_desktop_hook_proxy_command", lambda *args: None)
    prepared = CopilotHarnessAdapter().prepare_install(ctx)
    assert len(prepared.files) == (13 if workspace_enabled else 8)
    helper = next(change for change in prepared.files if change.path.suffix == ".py")
    assert helper.path == ctx.guard_home / "managed/bounded-hooks/copilot.py"
    assert helper.no_follow and helper.after_mode == 0o600
    assert helper.before is None and helper.after is not None
    assert not helper.path.exists()
    assert not (ctx.guard_home / "bin").exists()
    assert not (ctx.home_dir / ".copilot").exists()


@pytest.mark.parametrize("workspace_enabled", [False, True])
def test_copilot_prepared_generation_matches_normal_install(tmp_path, workspace_enabled):
    from codex_plugin_scanner.guard.adapters.adapter_state_integrity import authenticate_adapter_state
    from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter

    ctx = HarnessContext(
        home_dir=tmp_path,
        guard_home=tmp_path / "guard",
        workspace_dir=tmp_path / "workspace" if workspace_enabled else None,
    )
    authenticate_adapter_state(ctx.guard_home, harness="copilot", payload={"enrollment": "fixture"})
    adapter = CopilotHarnessAdapter()
    prepared = adapter.prepare_install(ctx)
    assert adapter.install(ctx) == prepared.manifest
    for change in prepared.files:
        if change.expected_digest is None:
            assert (change.path.read_bytes() if change.path.exists() else None) == change.after


def test_copilot_preparation_preserves_and_distinguishes_invalid_authority(tmp_path):
    from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter

    ctx = context(tmp_path)
    authority = ctx.guard_home / "managed/adapter-state.key"
    authority.parent.mkdir(parents=True, mode=0o700)
    authority.write_bytes(b"invalid fixture authority")
    authority.chmod(0o600)
    before = authority.stat()
    with pytest.raises(TransitionError, match="adapter_preparation_authority_invalid"):
        CopilotHarnessAdapter().prepare_install(ctx)
    assert authority.read_bytes() == b"invalid fixture authority"
    assert authority.stat().st_ino == before.st_ino
    assert authority.stat().st_mtime_ns == before.st_mtime_ns
    assert not (ctx.guard_home / "bin").exists()
    assert not (ctx.home_dir / ".copilot").exists()


@pytest.mark.parametrize("workspace_enabled", [False, True])
def test_cursor_editor_prepared_generation_matches_normal_install(tmp_path, workspace_enabled):
    from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
    from codex_plugin_scanner.guard.adapters.cursor_native_approval import ensure_cursor_hook_attestation_secret

    ctx = HarnessContext(
        home_dir=tmp_path,
        guard_home=tmp_path / "guard",
        workspace_dir=tmp_path / "workspace" if workspace_enabled else None,
    )
    ensure_cursor_hook_attestation_secret(ctx.guard_home)
    adapter = CursorHarnessAdapter()
    prepared = adapter.prepare_install(ctx)
    assert len(prepared.files) == (14 if workspace_enabled else 9)
    assert not (ctx.guard_home / "runtime/python-probe").exists()
    assert not (ctx.home_dir / ".cursor").exists()
    assert adapter.install(ctx) == prepared.manifest
    for change in prepared.files:
        if change.expected_digest is None:
            assert (change.path.read_bytes() if change.path.exists() else None) == change.after
            if change.path.suffix == ".py" and change.after is not None:
                assert change.path.stat().st_mode & 0o777 == change.after_mode


def test_cursor_preparation_rejects_invalid_authority_without_replacing_it(tmp_path):
    from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
    from codex_plugin_scanner.guard.adapters.cursor_native_approval import cursor_hook_attestation_secret_path

    ctx = context(tmp_path)
    authority = cursor_hook_attestation_secret_path(ctx.guard_home)
    authority.parent.mkdir(parents=True, mode=0o700)
    authority.write_bytes(b"invalid fixture authority")
    authority.chmod(0o600)
    before = authority.stat()
    with pytest.raises(TransitionError, match="adapter_preparation_authority_invalid"):
        CursorHarnessAdapter().prepare_install(ctx)
    assert authority.read_bytes() == b"invalid fixture authority"
    assert authority.stat().st_ino == before.st_ino
    assert authority.stat().st_mtime_ns == before.st_mtime_ns
    assert not (ctx.home_dir / ".cursor").exists()


@pytest.mark.parametrize("surface", ["cli", "all"])
def test_cursor_cli_and_all_preparation_matches_normal_install(tmp_path, monkeypatch, surface):
    from codex_plugin_scanner.guard import shims
    from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
    from codex_plugin_scanner.guard.adapters.cursor_native_approval import ensure_cursor_hook_attestation_secret

    ctx = context(tmp_path)
    if surface == "all":
        ensure_cursor_hook_attestation_secret(ctx.guard_home)
    monkeypatch.setattr(shims, "_is_transient_path", lambda path: False)
    monkeypatch.setenv("SHELL", "/bin/zsh")
    adapter = CursorHarnessAdapter()
    prepared = adapter.prepare_install(ctx, surface=surface)
    assert not (ctx.guard_home / "bin").exists()
    assert not (ctx.home_dir / ".zshrc").exists()
    assert adapter.install(ctx, surface=surface) == prepared.manifest
    for change in prepared.files:
        if change.expected_digest is None:
            assert (change.path.read_bytes() if change.path.exists() else None) == change.after


@pytest.mark.parametrize("operation", ["install", "uninstall"])
def test_direct_launcher_writers_reject_pending_transition(tmp_path: Path, operation: str):
    from codex_plugin_scanner.guard.shims import install_guard_shim, remove_guard_shim

    ctx = context(tmp_path)
    receipt = install_guard_shim("gemini", ctx)
    paths = [Path(receipt[key]) for key in ("shim_path", "windows_shim_path")]
    before = [path.read_bytes() for path in paths]
    (ctx.guard_home / "managed/runtime-transition.json").write_text("{}")
    writer = install_guard_shim if operation == "install" else remove_guard_shim
    with pytest.raises(TransitionError, match="pending_transition"):
        writer("gemini", ctx)
    assert [path.read_bytes() for path in paths] == before


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell profiles")
def test_direct_shell_profile_writer_rejects_pending_transition(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard import shims

    ctx = context(tmp_path)
    monkeypatch.setattr(shims, "_is_transient_path", lambda path: False)
    monkeypatch.setenv("SHELL", "/bin/zsh")
    profile = ctx.home_dir / ".zshrc"
    profile.write_text("user profile must survive\n")
    journal = ctx.guard_home / "managed/runtime-transition.json"
    journal.parent.mkdir(parents=True)
    journal.write_text("{}")
    with pytest.raises(TransitionError, match="pending_transition"):
        shims.ensure_guard_shim_path_in_shell_profile(ctx)
    assert profile.read_text() == "user profile must survive\n"


@pytest.mark.parametrize("harness", [adapter.harness for adapter in list_adapters()])
@pytest.mark.parametrize("operation", ["install", "uninstall"])
def test_every_registered_adapter_rejects_pending_transition(tmp_path: Path, harness: str, operation: str):
    adapter = next(adapter for adapter in list_adapters() if adapter.harness == harness)
    method = getattr(adapter, operation)
    # Check the contract before running real adapter code in this fixture.
    assert getattr(method, "_guard_mutation_owned", False)
    ctx = context(tmp_path)
    record = ctx.guard_home / "managed/runtime-transition.json"
    record.parent.mkdir(parents=True)
    record.write_text("{}")
    with pytest.raises(TransitionError, match="pending_transition"):
        method(ctx)
    assert record.read_text() == "{}"
    assert not (ctx.guard_home / "bin").exists()


def test_adapter_owner_covers_body_and_preserves_surface_arguments(tmp_path: Path):
    class OwnerProbe(HarnessAdapter):
        harness = "owner-probe"

        def install(self, ctx, *, surface="fixture"):
            owner = require_codex_install_owner(ctx.guard_home)
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    """
import sys, time
from pathlib import Path
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
home = Path(sys.argv[1])
try:
    with codex_install_transaction(home, home / "managed", actor="competitor",
                                   deadline=time.monotonic() + 0.1):
        print("entered")
except TimeoutError:
    print("excluded")
""",
                    str(ctx.guard_home),
                ],
                capture_output=True,
                timeout=5,
            )
            assert result.returncode == 0, result.stderr.decode(errors="replace")
            assert result.stdout.strip() == b"excluded"
            return {"surface": surface, "actor": owner.actor}

    result = OwnerProbe().install(context(tmp_path), surface="editor")
    assert result == {"surface": "editor", "actor": "adapter.owner-probe.install"}
