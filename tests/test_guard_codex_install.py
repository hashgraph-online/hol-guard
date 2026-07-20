from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.adapters.mcp_servers import managed_stdio_servers
from codex_plugin_scanner.guard.codex_config import dump_toml
from codex_plugin_scanner.guard.codex_hook_file_integrity import (
    CodexHookIntegrityError,
    describe_executable_file,
    describe_regular_file,
    validate_regular_file,
)
from codex_plugin_scanner.guard.codex_hook_integrity import (
    hook_secret_path,
    load_or_create_hook_secret,
    sign_hook_manifest,
    write_hook_manifest,
)
from codex_plugin_scanner.guard.config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission modes are required")
def test_interpreter_identity_accepts_current_owner_group_write_but_rejects_world_write(tmp_path: Path) -> None:
    interpreter = tmp_path / "python"
    interpreter.write_bytes(b"interpreter fixture")
    interpreter.chmod(0o775)

    identity = describe_executable_file(interpreter, role="interpreter")

    target = identity["target"]
    assert isinstance(target, dict)
    assert target["mode"] == 0o775
    interpreter.chmod(0o777)
    with pytest.raises(CodexHookIntegrityError, match="writable by another user"):
        describe_executable_file(interpreter, role="interpreter")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission modes are required")
def test_interpreter_identity_accepts_root_owned_root_group_toolchain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    interpreter = tmp_path / "python"
    interpreter.write_bytes(b"interpreter fixture")
    interpreter.chmod(0o775)
    real_lstat = Path.lstat
    real_metadata = interpreter.lstat()
    root_owned_metadata = os.stat_result(
        (
            real_metadata.st_mode,
            real_metadata.st_ino,
            real_metadata.st_dev,
            real_metadata.st_nlink,
            0,
            0,
            real_metadata.st_size,
            real_metadata.st_atime,
            real_metadata.st_mtime,
            real_metadata.st_ctime,
        )
    )

    def root_owned_lstat(path: Path) -> os.stat_result:
        if path == interpreter:
            return root_owned_metadata
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", root_owned_lstat)
    monkeypatch.setattr(os, "getuid", lambda: 1000)

    metadata = validate_regular_file(interpreter, role="interpreter", executable_required=True)

    assert metadata.st_uid == 0
    assert metadata.st_gid == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission modes are required")
def test_packaged_hook_identity_still_rejects_current_owner_group_write(tmp_path: Path) -> None:
    bridge = tmp_path / "codex_hook_bridge.py"
    bridge.write_bytes(b"bridge fixture")
    bridge.chmod(0o664)

    with pytest.raises(CodexHookIntegrityError, match="writable by another user"):
        describe_regular_file(bridge, role="bridge", executable_required=False)


def _build_guard_fixture(home_dir: Path, workspace_dir: Path) -> None:
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
[mcp_servers.global_tools]
command = "python3"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
approval_policy = "never"

[features]
codex_hooks = true

[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js"]
env = { API_BASE = "https://hol.org", FEATURE_FLAG = "1" }
""".strip()
        + "\n",
    )


def test_guard_codex_hook_command_does_not_pin_custom_guard_home_in_real_global_config(
    tmp_path,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    stale_guard_home = tmp_path / "pytest-stale-guard-home"
    monkeypatch.setattr(codex_adapter.Path, "home", lambda: home_dir)

    command = codex_adapter._hook_command(
        HarnessContext(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            guard_home=stale_guard_home,
        )
    )

    assert "--guard-home" not in shlex.split(command)
    assert str(stale_guard_home) not in command


def test_guard_codex_hook_command_uses_lightweight_authenticated_daemon_bridge(tmp_path):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"

    command = codex_adapter._hook_command(
        HarnessContext(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            guard_home=guard_home,
        )
    )
    tokens = shlex.split(command)
    bridge_config = json.loads(tokens[2])

    assert Path(tokens[1]).name == "codex_daemon_hook_bridge.py"
    assert bridge_config["state_path"] == str(guard_home / "daemon-state.json")
    assert bridge_config["query"].startswith("guard-home=")
    assert bridge_config["fallback_command"][:3] == [
        str(Path(sys.executable).absolute()),
        "-m",
        "codex_plugin_scanner.cli",
    ]
    assert bridge_config["start_command"][0] == str(Path(sys.executable).absolute())
    assert bridge_config["hook_timeouts"]["PreToolUse"] > bridge_config["hook_timeouts"]["UserPromptSubmit"]


def test_guard_codex_native_hook_state_requires_authenticated_manifest(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=home_dir / ".hol-guard")
    direct_argv = list(codex_adapter._local_hook_command_parts(context))
    bridge_config = json.dumps({"fallback_command": direct_argv}, separators=(",", ":"))
    forged_commands = [
        codex_adapter._hook_command(context),
        shlex.join([str(tmp_path / "hol-guard-codex-hook.sh"), "--forged"]),
        shlex.join(
            [
                "python3",
                str(
                    tmp_path
                    / "site-packages"
                    / "codex_plugin_scanner"
                    / "guard"
                    / "adapters"
                    / "codex_daemon_hook_bridge.py"
                ),
                bridge_config,
            ]
        ),
        shlex.join(
            [
                "python3",
                "-c",
                "from codex_plugin_scanner.cli import main;main(['guard','hook','--harness','codex'])",
            ]
        ),
    ]

    for command in forged_commands:
        forged_entry = {
            "type": "command",
            "command": command,
            "timeout": 30,
            "statusMessage": "HOL Guard checking tool action",
        }
        _write_text(
            home_dir / ".codex" / "config.toml",
            dump_toml(
                {
                    "features": {"hooks": True},
                    "hooks": {
                        event_name: [{"matcher": ".*", "hooks": [forged_entry]}]
                        for event_name in ("PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse")
                    },
                },
            ),
        )

        state = codex_adapter.codex_native_hook_state(context)

        assert state["protection_active"] is False
        assert state["managed_hook_installed"] is False
        assert state["integrity_status"] == "missing"
        assert state["integrity_reason"] == "codex_hook_manifest_missing"
        assert state["foreign_hook_entries_present"] is True


def test_guard_codex_native_hook_state_detects_registered_handler_tampering(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = home_dir / ".hol-guard"
    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)
    _build_guard_fixture(home_dir, workspace_dir)

    CodexHarnessAdapter().install(context)
    valid_state = codex_adapter.codex_native_hook_state(context)
    payload = tomllib.loads((home_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    payload["hooks"]["PreToolUse"][-1]["hooks"][0]["statusMessage"] = "HOL Guard checking tool action (forged)"
    _write_text(home_dir / ".codex" / "config.toml", dump_toml(payload))

    tampered_state = codex_adapter.codex_native_hook_state(context)

    assert valid_state["protection_active"] is True
    assert valid_state["integrity_status"] == "valid"
    assert tampered_state["protection_active"] is False
    assert tampered_state["managed_hook_installed"] is False
    assert tampered_state["integrity_status"] == "tampered"
    assert tampered_state["integrity_reason"] == "codex_hook_registration_mismatch"


def test_guard_codex_native_hook_state_reports_missing_config_target(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=home_dir / ".hol-guard")
    adapter = CodexHarnessAdapter()
    adapter.install(context)
    (home_dir / ".codex" / "config.toml").unlink()

    state = codex_adapter.codex_native_hook_state(context)

    assert state["protection_active"] is False
    assert state["integrity_status"] == "missing"
    assert state["integrity_reason"] == "codex_hook_config_target_missing"


def test_guard_codex_native_hook_state_reports_missing_registration(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=home_dir / ".hol-guard")
    adapter = CodexHarnessAdapter()
    adapter.install(context)
    config_path = home_dir / ".codex" / "config.toml"
    payload = tomllib.loads(config_path.read_text(encoding="utf-8"))
    payload.pop("hooks")
    _write_text(config_path, dump_toml(payload))

    state = codex_adapter.codex_native_hook_state(context)

    assert state["protection_active"] is False
    assert state["integrity_status"] == "missing"
    assert state["integrity_reason"] == "codex_hook_registration_missing"


def test_guard_codex_install_refuses_to_replace_bad_manifest_mac(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=home_dir / ".hol-guard")

    adapter = CodexHarnessAdapter()
    adapter.install(context)
    valid_state = codex_adapter.codex_native_hook_state(context)
    manifest_path = Path(str(valid_state["manifest_path"]))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["authentication"]["payload_mac"] = "0" * 64
    _write_text(manifest_path, json.dumps(manifest, sort_keys=True) + "\n")
    tampered_manifest = manifest_path.read_bytes()

    state = codex_adapter.codex_native_hook_state(context)
    with pytest.raises(CodexHookIntegrityError, match="Reinstall hol-guard from a trusted package") as error:
        adapter.install(context)

    assert state["protection_active"] is False
    assert state["integrity_status"] == "tampered"
    assert state["integrity_reason"] == "codex_hook_manifest_mac_invalid"
    assert error.value.reason == "codex_hook_manifest_baseline_untrusted"
    assert manifest_path.read_bytes() == tampered_manifest
    assert codex_adapter.codex_native_hook_state(context)["protection_active"] is False


def test_guard_codex_native_hook_state_rejects_manifest_copied_from_another_guard_home(tmp_path: Path) -> None:
    first_context = HarnessContext(
        home_dir=tmp_path / "first-home",
        workspace_dir=None,
        guard_home=tmp_path / "first-guard",
    )
    second_context = HarnessContext(
        home_dir=tmp_path / "second-home",
        workspace_dir=None,
        guard_home=tmp_path / "second-guard",
    )
    adapter = CodexHarnessAdapter()
    adapter.install(first_context)
    adapter.install(second_context)
    first_state = codex_adapter.codex_native_hook_state(first_context)
    second_state = codex_adapter.codex_native_hook_state(second_context)
    first_manifest = Path(str(first_state["manifest_path"]))
    second_manifest = Path(str(second_state["manifest_path"]))
    _write_text(second_manifest, first_manifest.read_text(encoding="utf-8"))
    foreign_manifest = second_manifest.read_bytes()

    copied_state = codex_adapter.codex_native_hook_state(second_context)
    with pytest.raises(CodexHookIntegrityError, match="Reinstall hol-guard from a trusted package") as error:
        adapter.install(second_context)

    assert copied_state["protection_active"] is False
    assert copied_state["integrity_status"] == "foreign"
    assert copied_state["integrity_reason"] == "codex_hook_manifest_key_mismatch"
    assert error.value.reason == "codex_hook_manifest_baseline_untrusted"
    assert second_manifest.read_bytes() == foreign_manifest


def test_guard_codex_install_and_uninstall_reject_manifest_from_another_workspace(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    first_context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=tmp_path / "first-workspace",
        guard_home=guard_home,
    )
    second_context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=tmp_path / "second-workspace",
        guard_home=guard_home,
    )
    adapter = CodexHarnessAdapter()
    adapter.install(first_context)
    config_path = CodexHarnessAdapter._hook_config_path(first_context)
    state = codex_adapter.codex_native_hook_state(first_context)
    manifest_path = Path(str(state["manifest_path"]))
    original_config = config_path.read_bytes()
    original_manifest = manifest_path.read_bytes()

    with pytest.raises(CodexHookIntegrityError) as install_error:
        adapter.install(second_context)
    with pytest.raises(CodexHookIntegrityError) as uninstall_error:
        adapter.uninstall(second_context)

    assert install_error.value.reason == "codex_hook_manifest_baseline_untrusted"
    assert uninstall_error.value.reason == "codex_hook_manifest_baseline_untrusted"
    assert config_path.read_bytes() == original_config
    assert manifest_path.read_bytes() == original_manifest
    assert codex_adapter.codex_native_hook_state(first_context)["protection_active"] is True


def test_guard_codex_install_refuses_missing_manifest_when_modern_secret_remains(tmp_path: Path) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    adapter = CodexHarnessAdapter()
    adapter.install(context)
    state = codex_adapter.codex_native_hook_state(context)
    Path(str(state["manifest_path"])).unlink()

    with pytest.raises(CodexHookIntegrityError, match="Reinstall hol-guard from a trusted package") as error:
        adapter.install(context)

    missing_state = codex_adapter.codex_native_hook_state(context)
    assert error.value.reason == "codex_hook_manifest_baseline_untrusted"
    assert missing_state["protection_active"] is False
    assert missing_state["integrity_reason"] == "codex_hook_manifest_missing"


def test_guard_codex_native_hook_state_rejects_signed_stale_package_version_and_repair_refreshes_it(
    tmp_path: Path,
) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    adapter = CodexHarnessAdapter()
    adapter.install(context)
    valid_state = codex_adapter.codex_native_hook_state(context)
    manifest_path = Path(str(valid_state["manifest_path"]))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("authentication")
    manifest["package_version"] = "0.0.0-stale"
    secret = load_or_create_hook_secret(context.guard_home)
    stale_manifest = sign_hook_manifest(manifest, secret)
    write_hook_manifest(
        context.guard_home,
        CodexHarnessAdapter._hook_config_path(context),
        stale_manifest,
    )

    stale_state = codex_adapter.codex_native_hook_state(context)
    adapter.install(context)
    repaired_state = codex_adapter.codex_native_hook_state(context)

    assert stale_state["protection_active"] is False
    assert stale_state["integrity_status"] == "stale"
    assert stale_state["integrity_reason"] == "codex_hook_manifest_package_version_stale"
    assert repaired_state["protection_active"] is True
    assert repaired_state["integrity_status"] == "valid"


def test_guard_codex_native_hook_state_detects_bridge_content_mode_and_symlink_changes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    bridge_path = tmp_path / "package" / "codex_daemon_hook_bridge.py"
    bridge_path.parent.mkdir(parents=True)
    bridge_path.write_bytes(Path(codex_adapter.__file__).with_name("codex_daemon_hook_bridge.py").read_bytes())
    bridge_path.chmod(0o644)
    original_command_parts = codex_adapter._hook_command_parts
    original_packaged_paths = codex_adapter._hook_packaged_file_paths

    def relocated_command_parts(hook_context: HarnessContext) -> tuple[str, ...]:
        parts = list(original_command_parts(hook_context))
        parts[1] = str(bridge_path)
        return tuple(parts)

    def relocated_packaged_paths() -> tuple[tuple[str, Path], ...]:
        return tuple((role, bridge_path if role == "bridge" else path) for role, path in original_packaged_paths())

    monkeypatch.setattr(codex_adapter, "_hook_command_parts", relocated_command_parts)
    monkeypatch.setattr(codex_adapter, "_hook_packaged_file_paths", relocated_packaged_paths)
    adapter = CodexHarnessAdapter()
    adapter.install(context)

    original_bytes = bridge_path.read_bytes()
    bridge_path.write_bytes(original_bytes + b"\n# tampered\n")
    content_state = codex_adapter.codex_native_hook_state(context)
    bridge_path.write_bytes(original_bytes)
    bridge_path.chmod(0o744)
    mode_state = codex_adapter.codex_native_hook_state(context)
    bridge_path.chmod(0o644)
    bridge_original = bridge_path.with_suffix(".original.py")
    bridge_path.rename(bridge_original)
    bridge_path.symlink_to(bridge_original)
    symlink_state = codex_adapter.codex_native_hook_state(context)

    assert content_state["integrity_reason"] == "codex_hook_bridge_hash_mismatch"
    assert mode_state["integrity_reason"] == "codex_hook_bridge_mode_mismatch"
    assert symlink_state["integrity_reason"] == "codex_hook_bridge_not_regular"
    assert content_state["protection_active"] is False
    assert mode_state["protection_active"] is False
    assert symlink_state["protection_active"] is False


def test_guard_codex_repair_refuses_to_authenticate_changed_same_version_bridge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    bridge_path = tmp_path / "package" / "codex_daemon_hook_bridge.py"
    bridge_path.parent.mkdir(parents=True)
    bridge_path.write_bytes(Path(codex_adapter.__file__).with_name("codex_daemon_hook_bridge.py").read_bytes())
    bridge_path.chmod(0o644)
    original_command_parts = codex_adapter._hook_command_parts
    original_packaged_paths = codex_adapter._hook_packaged_file_paths

    def relocated_command_parts(hook_context: HarnessContext) -> tuple[str, ...]:
        parts = list(original_command_parts(hook_context))
        parts[1] = str(bridge_path)
        return tuple(parts)

    def relocated_packaged_paths() -> tuple[tuple[str, Path], ...]:
        return tuple((role, bridge_path if role == "bridge" else path) for role, path in original_packaged_paths())

    monkeypatch.setattr(codex_adapter, "_hook_command_parts", relocated_command_parts)
    monkeypatch.setattr(codex_adapter, "_hook_packaged_file_paths", relocated_packaged_paths)
    adapter = CodexHarnessAdapter()
    adapter.install(context)
    valid_state = codex_adapter.codex_native_hook_state(context)
    manifest_path = Path(str(valid_state["manifest_path"]))
    original_manifest = manifest_path.read_bytes()
    bridge_path.write_bytes(bridge_path.read_bytes() + b"\n# attacker-controlled mutation\n")

    with pytest.raises(
        CodexHookIntegrityError,
        match="refused to authenticate changed same-version hook code",
    ) as error:
        adapter.install(context)

    state = codex_adapter.codex_native_hook_state(context)
    assert error.value.reason == "codex_hook_package_reauthentication_refused"
    assert manifest_path.read_bytes() == original_manifest
    assert state["protection_active"] is False
    assert state["integrity_reason"] == "codex_hook_bridge_hash_mismatch"


def test_guard_codex_native_hook_state_binds_interpreter_invocation_symlink_target(
    tmp_path: Path,
    monkeypatch,
) -> None:
    if os.name == "nt":
        return
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    interpreter_link = tmp_path / "guard-python"
    interpreter_link.symlink_to(Path(sys.executable).resolve(strict=True))
    replacement = tmp_path / "replacement-python"
    replacement.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    replacement.chmod(0o755)
    monkeypatch.setattr(codex_adapter.sys, "executable", str(interpreter_link))

    CodexHarnessAdapter().install(context)
    valid_state = codex_adapter.codex_native_hook_state(context)
    interpreter_link.unlink()
    interpreter_link.symlink_to(replacement)

    swapped_state = codex_adapter.codex_native_hook_state(context)

    assert valid_state["protection_active"] is True
    assert swapped_state["protection_active"] is False
    assert swapped_state["integrity_status"] == "tampered"
    assert swapped_state["integrity_reason"] == "codex_hook_interpreter_symlink_target_mismatch"


def test_guard_codex_install_safely_readopts_exact_current_legacy_bridge(tmp_path: Path) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    config_path = CodexHarnessAdapter._hook_config_path(context)
    legacy_group = codex_adapter._managed_hook_groups(context)["PreToolUse"]
    _write_text(
        config_path,
        dump_toml({"features": {"hooks": True}, "hooks": {"PreToolUse": [legacy_group]}}),
    )

    CodexHarnessAdapter().install(context)
    installed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    state = codex_adapter.codex_native_hook_state(context)

    assert len(installed["hooks"]["PreToolUse"]) == 1
    assert state["protection_active"] is True
    assert state["foreign_hook_entries_present"] is False


def test_guard_codex_install_preserves_ambiguous_foreign_direct_hook(tmp_path: Path) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    config_path = CodexHarnessAdapter._hook_config_path(context)
    foreign_command = shlex.join(codex_adapter._local_hook_command_parts(context))
    foreign_group = {
        "matcher": codex_adapter._CODEX_GUARD_TOOL_MATCHER,
        "hooks": [
            {
                "type": "command",
                "command": foreign_command,
                "statusMessage": "HOL Guard checking tool action",
            }
        ],
    }
    _write_text(
        config_path,
        dump_toml({"features": {"hooks": True}, "hooks": {"PreToolUse": [foreign_group]}}),
    )

    CodexHarnessAdapter().install(context)
    installed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    state = codex_adapter.codex_native_hook_state(context)
    commands = [handler["command"] for group in installed["hooks"]["PreToolUse"] for handler in group["hooks"]]

    assert foreign_command in commands
    assert len(installed["hooks"]["PreToolUse"]) == 2
    assert state["protection_active"] is True
    assert state["foreign_hook_entries_present"] is True


def test_guard_codex_authenticated_hook_transaction_rolls_back_after_partial_config_write(
    tmp_path: Path,
    monkeypatch,
) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    adapter = CodexHarnessAdapter()
    adapter.install(context)
    config_path = CodexHarnessAdapter._hook_config_path(context)
    state = codex_adapter.codex_native_hook_state(context)
    manifest_path = Path(str(state["manifest_path"]))
    original_config = config_path.read_bytes()
    original_manifest = manifest_path.read_bytes()
    original_atomic_write = codex_adapter.atomic_write_text
    failed_once = False

    def fail_first_config_write(path: Path, text: str, *, mode: int = 0o600) -> None:
        nonlocal failed_once
        if path == config_path and not failed_once:
            failed_once = True
            raise OSError("injected config write failure")
        original_atomic_write(path, text, mode=mode)

    monkeypatch.setattr(codex_adapter, "atomic_write_text", fail_first_config_write)

    try:
        adapter.install(context)
    except OSError as error:
        assert str(error) == "injected config write failure"
    else:  # pragma: no cover - the injected failure must escape after rollback
        raise AssertionError("Expected the injected config write failure")

    rolled_back_state = codex_adapter.codex_native_hook_state(context)

    assert config_path.read_bytes() == original_config
    assert manifest_path.read_bytes() == original_manifest
    assert rolled_back_state["protection_active"] is True
    assert rolled_back_state["integrity_status"] == "valid"


def test_guard_codex_first_install_failure_rolls_back_new_hook_secret(
    tmp_path: Path,
    monkeypatch,
) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    adapter = CodexHarnessAdapter()
    config_path = CodexHarnessAdapter._hook_config_path(context)
    manifest_path = codex_adapter.hook_manifest_path(context.guard_home, config_path)
    secret_path = hook_secret_path(context.guard_home)
    original_atomic_write = codex_adapter.atomic_write_text
    failed_once = False

    def fail_first_config_write(path: Path, text: str, *, mode: int = 0o600) -> None:
        nonlocal failed_once
        if path == config_path and not failed_once:
            failed_once = True
            raise OSError("injected first-install config failure")
        original_atomic_write(path, text, mode=mode)

    monkeypatch.setattr(codex_adapter, "atomic_write_text", fail_first_config_write)

    with pytest.raises(OSError, match="injected first-install config failure"):
        adapter.install(context)

    assert not config_path.exists()
    assert not manifest_path.exists()
    assert not secret_path.exists()

    installed = adapter.install(context)
    state = codex_adapter.codex_native_hook_state(context)

    assert installed["active"] is True
    assert secret_path.is_file()
    assert state["protection_active"] is True
    assert state["integrity_status"] == "valid"


def test_guard_codex_launch_uses_remote_control_for_dashboard_continuation(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )
    captured: dict[str, object] = {}

    def fake_remote_launch(**kwargs):
        captured.update(kwargs)
        return ["/usr/bin/codex", "--remote", "unix:///guarded.sock", "Fix it."]

    monkeypatch.setattr(codex_adapter, "guarded_codex_launch_command", fake_remote_launch)
    monkeypatch.setattr(CodexHarnessAdapter, "resolved_executable", lambda self, ctx: "/usr/bin/codex")

    command = CodexHarnessAdapter().launch_command(context, ["Fix it."])
    environment = CodexHarnessAdapter().launch_environment(context)

    assert command == ["/usr/bin/codex", "--remote", "unix:///guarded.sock", "Fix it."]
    assert captured == {
        "executable": "/usr/bin/codex",
        "home_dir": home_dir,
        "passthrough_args": ["Fix it."],
    }
    assert environment["CODEX_HOME"] == str(home_dir / ".codex")


def test_guard_codex_does_not_claim_untrusted_bridge_lookalike() -> None:
    command = "python /untrusted/codex_daemon_hook_bridge.py '{}'"

    assert codex_adapter._is_managed_hook_command(command) is False


def test_guard_codex_preserves_user_owned_direct_hook_without_status_message() -> None:
    command = shlex.join(
        [
            sys.executable,
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "hook",
            "--harness",
            "codex",
        ]
    )
    entry = {"type": "command", "command": command}

    assert codex_adapter._is_managed_hook_command(command) is True
    assert codex_adapter._is_unambiguously_managed_hook_command(command) is False
    assert codex_adapter._is_managed_hook_entry(entry) is False


def test_guard_codex_claims_stale_pipx_direct_hook_without_status_message() -> None:
    command = shlex.join(
        [
            "/home/user/.local/pipx/venvs/hol-guard/bin/python",
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "hook",
            "--harness",
            "codex",
        ]
    )
    entry = {"type": "command", "command": command}

    assert codex_adapter._is_managed_hook_entry(entry) is True


def test_guard_codex_does_not_claim_guard_install_path_lookalike() -> None:
    lookalike_python = "/home/user/.local/uv/tools/hol-guard-extra/bin/python"
    command = shlex.join(
        [
            lookalike_python,
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "hook",
            "--harness",
            "codex",
        ]
    )
    entry = {"type": "command", "command": command}

    assert codex_adapter._python_executable_is_guard_install(lookalike_python) is False
    assert codex_adapter._is_managed_hook_entry(entry) is False


def test_guard_codex_detects_direct_hook_with_python_runtime_flags() -> None:
    command_tokens = [
        "python3",
        "-P",
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "hook",
        "--harness",
        "codex",
    ]
    command = shlex.join(command_tokens)
    entry = {
        "type": "command",
        "command": command,
        "statusMessage": "HOL Guard checking tool result",
    }

    assert codex_adapter._argv_is_direct_codex_hook(command_tokens) is True
    assert codex_adapter._is_managed_hook_command(command) is True
    assert codex_adapter._is_managed_hook_entry(entry) is True


def test_guard_codex_detects_bridge_hook_with_python_runtime_flags(tmp_path: Path) -> None:
    bridge_path = (
        tmp_path / "site-packages" / "codex_plugin_scanner" / "guard" / "adapters" / "codex_daemon_hook_bridge.py"
    )
    bridge_path.parent.mkdir(parents=True, exist_ok=True)
    bridge_path.write_text("# bridge\n", encoding="utf-8")
    config = json.dumps(
        {
            "fallback_command": [
                sys.executable,
                "-m",
                "codex_plugin_scanner.cli",
                "guard",
                "hook",
                "--harness",
                "codex",
            ]
        },
        separators=(",", ":"),
    )
    command_tokens = ["python3", "-I", str(bridge_path), config]
    command = shlex.join(command_tokens)
    entry = {"type": "command", "command": command}

    assert codex_adapter._is_daemon_bridge_hook_command(command_tokens) is True
    assert codex_adapter._is_managed_hook_command(command) is True
    assert codex_adapter._is_unambiguously_managed_hook_command(command) is True
    assert codex_adapter._is_managed_hook_entry(entry) is True


def test_guard_install_and_repair_codex_preserve_ambiguous_legacy_post_tool_hooks(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = home_dir / ".hol-guard"
    codex_home = home_dir / ".codex"
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_support_interaction._open_guard_cloud_app",
        lambda **_kwargs: {"status": "test"},
    )
    stale_bridge_path = (
        home_dir
        / ".local"
        / "share"
        / "uv"
        / "tools"
        / "hol-guard"
        / "lib"
        / "python3.12"
        / "site-packages"
        / "codex_plugin_scanner"
        / "guard"
        / "adapters"
        / "codex_daemon_hook_bridge.py"
    )
    stale_bridge_command = shlex.join(
        [
            str(home_dir / ".local" / "share" / "uv" / "tools" / "hol-guard" / "bin" / "python"),
            str(stale_bridge_path),
            json.dumps(
                {
                    "state_path": str(guard_home / "daemon-state.json"),
                    "fallback_command": [
                        str(home_dir / ".local" / "bin" / "python"),
                        "-m",
                        "codex_plugin_scanner.cli",
                        "guard",
                        "hook",
                        "--harness",
                        "codex",
                    ],
                    "start_command": [str(home_dir / ".local" / "bin" / "python"), "-c", "pass"],
                    "query": "guard-home=stale",
                    "hook_timeouts": {"PostToolUse": 30},
                },
                separators=(",", ":"),
            ),
        ]
    )
    stale_direct_command = shlex.join(
        [
            str(home_dir / ".local" / "pipx" / "venvs" / "hol-guard" / "bin" / "python"),
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "hook",
            "--harness",
            "codex",
            "--workspace",
            str(workspace_dir),
        ]
    )
    lean_command = "lean-ctx hook observe"
    _write_text(
        codex_home / "config.toml",
        dump_toml(
            {
                "features": {"hooks": True},
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": ".*",
                            "hooks": [{"type": "command", "command": lean_command}],
                        },
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": stale_bridge_command,
                                    "statusMessage": "HOL Guard checking tool result",
                                }
                            ],
                        },
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": stale_direct_command}],
                        },
                    ]
                },
            }
        ),
    )

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--guard-home",
            str(guard_home),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    installed_payload = tomllib.loads((codex_home / "config.toml").read_text(encoding="utf-8"))
    installed_payload["hooks"]["PostToolUse"].append(
        {
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": stale_direct_command}],
        }
    )
    _write_text(codex_home / "config.toml", dump_toml(installed_payload))
    connect_rc = main(
        [
            "guard",
            "apps",
            "connect",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--guard-home",
            str(guard_home),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    connected_payload = tomllib.loads((codex_home / "config.toml").read_text(encoding="utf-8"))
    connected_commands = [
        hook["command"]
        for group in connected_payload["hooks"]["PostToolUse"]
        for hook in group["hooks"]
        if hook["type"] == "command"
    ]
    assert stale_direct_command in connected_commands
    connected_payload["hooks"]["PostToolUse"].append(
        {
            "matcher": "Bash",
            "hooks": [
                {
                    "type": "command",
                    "command": stale_bridge_command,
                    "statusMessage": "HOL Guard checking tool result",
                }
            ],
        }
    )
    _write_text(codex_home / "config.toml", dump_toml(connected_payload))
    repair_rc = main(
        [
            "guard",
            "apps",
            "repair",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--guard-home",
            str(guard_home),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    config_payload = tomllib.loads((codex_home / "config.toml").read_text(encoding="utf-8"))
    commands = [
        hook["command"]
        for group in config_payload["hooks"]["PostToolUse"]
        for hook in group["hooks"]
        if hook["type"] == "command"
    ]
    command_tokens = [shlex.split(command) for command in commands]
    current_bridge_path = Path(codex_adapter.__file__).with_name("codex_daemon_hook_bridge.py").resolve()
    authenticated_bridge_commands = [
        tokens for tokens in command_tokens if len(tokens) > 1 and Path(tokens[1]).resolve() == current_bridge_path
    ]
    final_state = codex_adapter.codex_native_hook_state(
        HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)
    )

    assert install_rc == 0
    assert connect_rc == 0
    assert repair_rc == 0
    assert lean_command in commands
    assert stale_bridge_command in commands
    assert stale_direct_command in commands
    assert len(authenticated_bridge_commands) == 1
    assert final_state["protection_active"] is True
    assert final_state["foreign_hook_entries_present"] is True


def test_guard_install_codex_rewrites_workspace_config_with_proxy_entries(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    source_root = str(Path(__file__).resolve().parents[1] / "src")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "stale-site-packages"))
    _build_guard_fixture(home_dir, workspace_dir)

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    managed_install = output["managed_install"]
    manifest = managed_install["manifest"]
    config_text = (home_dir / ".codex" / "config.toml").read_text(encoding="utf-8")
    config_payload = tomllib.loads(config_text)
    workspace_config = tomllib.loads((workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    hooks_path = home_dir / ".codex" / "hooks.json"
    hooks_payload = config_payload["hooks"]

    assert rc == 0
    assert managed_install["active"] is True
    assert manifest["mode"] == "codex-mcp-proxy"
    assert manifest["managed_config_path"] == str(home_dir / ".codex" / "config.toml")
    assert manifest["managed_hook_config_path"] == str(home_dir / ".codex" / "config.toml")
    assert manifest["managed_hooks_path"] == str(hooks_path)
    assert manifest["managed_shell_guard_path"] == str(home_dir / "managed" / "codex" / "codex-zshenv-guard.zsh")
    assert manifest["managed_shell_guard_paths"] == {
        "zsh": str(home_dir / "managed" / "codex" / "codex-zshenv-guard.zsh"),
        "bash": str(home_dir / "managed" / "codex" / "codex-bashenv-guard.bash"),
        "fish": str(home_dir / "managed" / "codex" / "codex-fish-guard.fish"),
        "fish_conf": str(home_dir / ".config" / "fish" / "conf.d" / "hol-guard-codex.fish"),
    }
    assert set(manifest["managed_servers"]) == {"global_tools", "workspace_skill"}
    assert "--server-name" in config_text
    assert "guard" in config_text
    assert "codex-mcp-proxy" in config_text
    assert "hooks = true" in config_text
    assert "codex_hooks" not in config_text
    assert workspace_config["approval_policy"] == "never"
    assert "features" not in workspace_config
    assert "hooks" not in workspace_config
    assert "mcp_servers" not in workspace_config
    assert hooks_path.exists() is False
    assert (workspace_dir / ".codex" / "hooks.json").exists() is False
    assert 'API_BASE = "https://hol.org"' in config_text
    assert 'FEATURE_FLAG = "1"' in config_text
    assert hooks_payload["PreToolUse"][0]["matcher"] == codex_adapter._CODEX_GUARD_TOOL_MATCHER
    assert hooks_payload["PermissionRequest"][0]["matcher"] == codex_adapter._CODEX_GUARD_PERMISSION_MATCHER
    assert "UserPromptSubmit" in hooks_payload
    assert "matcher" not in hooks_payload["UserPromptSubmit"][0]
    prompt_handler = hooks_payload["UserPromptSubmit"][0]["hooks"][0]
    assert prompt_handler["type"] == "command"
    assert "codex_plugin_scanner.cli" in prompt_handler["command"]
    assert "hook" in prompt_handler["command"]
    assert "codex" in prompt_handler["command"]
    assert prompt_handler["env"]["PYTHONPATH"] == source_root
    handler = hooks_payload["PreToolUse"][0]["hooks"][0]
    assert handler["type"] == "command"
    assert "codex_plugin_scanner.cli" in handler["command"]
    assert "hook" in handler["command"]
    assert "codex" in handler["command"]
    assert handler["env"]["PYTHONPATH"] == source_root
    permission_handler = hooks_payload["PermissionRequest"][0]["hooks"][0]
    assert permission_handler["type"] == "command"
    assert "codex_plugin_scanner.cli" in permission_handler["command"]
    assert "hook" in permission_handler["command"]
    assert "codex" in permission_handler["command"]
    assert permission_handler["env"]["PYTHONPATH"] == source_root
    zshenv_text = (home_dir / ".zshenv").read_text(encoding="utf-8")
    shell_guard_text = (home_dir / "managed" / "codex" / "codex-zshenv-guard.zsh").read_text(encoding="utf-8")
    bash_guard_text = (home_dir / "managed" / "codex" / "codex-bashenv-guard.bash").read_text(encoding="utf-8")
    fish_guard_text = (home_dir / "managed" / "codex" / "codex-fish-guard.fish").read_text(encoding="utf-8")
    fish_conf_text = (home_dir / ".config" / "fish" / "conf.d" / "hol-guard-codex.fish").read_text(encoding="utf-8")
    assert "HOL Guard Codex shell guard" in zshenv_text
    assert "TRAPDEBUG" in shell_guard_text
    assert "BASH_ENV" in (home_dir / ".bash_profile").read_text(encoding="utf-8")
    assert "BASH_ENV" in (home_dir / ".bashrc").read_text(encoding="utf-8")
    assert (home_dir / ".bash_login").exists() is False
    assert (home_dir / ".profile").exists() is False
    assert "extdebug" in bash_guard_text
    assert "fish_preexec" in fish_guard_text
    assert "codex-fish-guard.fish" in fish_conf_text
    assert ".npmrc" in shell_guard_text


def test_guard_install_codex_detects_wrapped_servers_without_rewrapping(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    detection = CodexHarnessAdapter().detect(
        HarnessContext(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            guard_home=home_dir,
        )
    )
    artifacts = {artifact.artifact_id: artifact for artifact in detection.artifacts}

    assert rc == 0
    assert "codex:global:global_tools" in artifacts
    assert "codex:project:workspace_skill" in artifacts
    assert artifacts["codex:project:workspace_skill"].command == "node"
    assert artifacts["codex:project:workspace_skill"].args == ("workspace-skill.js",)
    assert artifacts["codex:project:workspace_skill"].metadata["guard_managed_proxy"] is True
    assert managed_stdio_servers(detection) == ()


def test_guard_install_codex_replaces_existing_zshenv_guard_block(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    _write_text(
        home_dir / ".zshenv",
        "\n".join(
            [
                "export KEEP_ME=1",
                "",
                "# >>> HOL Guard Codex shell guard >>>",
                "source /tmp/old",
                "# <<< HOL Guard Codex shell guard <<<",
                "",
            ]
        ),
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    zshenv_text = (home_dir / ".zshenv").read_text(encoding="utf-8")

    assert rc == 0
    assert "export KEEP_ME=1" in zshenv_text
    assert "/tmp/old" not in zshenv_text
    assert zshenv_text.count("HOL Guard Codex shell guard") == 2


def test_guard_install_codex_does_not_shadow_existing_bash_profile_precedence(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    _write_text(home_dir / ".profile", "export KEEP_PROFILE=1\n")

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    assert rc == 0
    assert (home_dir / ".bash_profile").exists() is False
    assert (home_dir / ".bash_login").exists() is False
    assert "export KEEP_PROFILE=1" in (home_dir / ".profile").read_text(encoding="utf-8")
    assert "BASH_ENV" in (home_dir / ".profile").read_text(encoding="utf-8")


def test_guard_uninstall_codex_removes_shell_guard_blocks(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / ".zshenv", "export KEEP_ME=1\n")
    _write_text(home_dir / ".bashrc", "export KEEP_BASHRC=1\n")
    _write_text(home_dir / ".bash_profile", "export KEEP_BASH_PROFILE=1\n")
    _write_text(home_dir / ".bash_login", "export KEEP_BASH_LOGIN=1\n")
    _write_text(home_dir / ".profile", "export KEEP_PROFILE=1\n")

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    guard_path = home_dir / "managed" / "codex" / "codex-zshenv-guard.zsh"
    bash_guard_path = home_dir / "managed" / "codex" / "codex-bashenv-guard.bash"
    fish_guard_path = home_dir / "managed" / "codex" / "codex-fish-guard.fish"

    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    assert install_rc == 0
    assert uninstall_rc == 0
    assert guard_path.exists() is False
    assert bash_guard_path.exists() is False
    assert fish_guard_path.exists() is False
    assert (home_dir / ".zshenv").read_text(encoding="utf-8") == "export KEEP_ME=1\n"
    assert (home_dir / ".bashrc").read_text(encoding="utf-8") == "export KEEP_BASHRC=1\n"
    assert (home_dir / ".bash_profile").read_text(encoding="utf-8") == "export KEEP_BASH_PROFILE=1\n"
    assert (home_dir / ".bash_login").read_text(encoding="utf-8") == "export KEEP_BASH_LOGIN=1\n"
    assert (home_dir / ".profile").read_text(encoding="utf-8") == "export KEEP_PROFILE=1\n"
    assert (home_dir / ".config" / "fish" / "conf.d" / "hol-guard-codex.fish").exists() is False


def test_guard_uninstall_codex_deletes_managed_only_shell_startup_files(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    assert install_rc == 0
    assert uninstall_rc == 0
    assert (home_dir / ".zshenv").exists() is False
    assert (home_dir / ".bashrc").exists() is False
    assert (home_dir / ".bash_profile").exists() is False
    assert (home_dir / ".bash_login").exists() is False
    assert (home_dir / ".profile").exists() is False
    assert (home_dir / ".config" / "fish" / "conf.d" / "hol-guard-codex.fish").exists() is False


def test_guard_codex_uninstall_removes_authenticated_baseline_before_reinstall(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = home_dir / ".hol-guard"
    _build_guard_fixture(home_dir, workspace_dir)
    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=guard_home,
    )
    adapter = CodexHarnessAdapter()

    adapter.install(context)
    first_state = codex_adapter.codex_native_hook_state(context)
    manifest_path = Path(str(first_state["manifest_path"]))
    secret_path = hook_secret_path(guard_home)
    assert first_state["integrity_status"] == "valid"
    assert manifest_path.is_file()
    assert secret_path.is_file()

    adapter.uninstall(context)
    assert manifest_path.exists() is False
    assert secret_path.exists() is False

    adapter.install(context)
    reinstalled_state = codex_adapter.codex_native_hook_state(context)
    assert reinstalled_state["integrity_status"] == "valid"
    assert reinstalled_state["integrity_reason"] == "codex_hook_manifest_valid"
    assert Path(str(reinstalled_state["manifest_path"])).is_file()
    assert secret_path.is_file()


def test_guard_codex_shell_guards_block_zsh_and_bash_secret_reads(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    npmrc_path = home_dir / ".npmrc"
    _write_text(npmrc_path, "FAKE_HOL_GUARD_SHOULD_NOT_PRINT\n")

    assert rc == 0
    shell_commands = []
    zsh_path = shutil.which("zsh")
    if zsh_path:
        shell_commands.append((zsh_path, [zsh_path, "-lc", "cat ~/.np''mrc"]))
    bash_path = shutil.which("bash")
    if bash_path:
        shell_commands.append((bash_path, [bash_path, "-lc", "cat ~/.np''mrc"]))
    if not shell_commands:
        return

    for shell_name, command in shell_commands:
        result = subprocess.run(
            command,
            cwd=workspace_dir,
            env={**os.environ, "HOME": str(home_dir), "CODEX_MANAGED_BY_BUN": "1"},
            text=True,
            capture_output=True,
            check=False,
        )
        combined = f"{result.stdout}\n{result.stderr}"
        assert "FAKE_HOL_GUARD_SHOULD_NOT_PRINT" not in combined, shell_name
        assert "HOL Guard blocked Codex before it could read a secret-looking local file." in combined, shell_name


def test_guard_apps_connect_codex_defaults_to_project_scope_when_local_codex_config_exists(
    tmp_path,
    monkeypatch,
    capsys,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    monkeypatch.chdir(workspace_dir)

    rc = main(
        [
            "guard",
            "apps",
            "connect",
            "codex",
            "--home",
            str(home_dir),
            "--guard-home",
            str(home_dir / ".hol-guard"),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["managed_install"]["active"] is True
    assert output["managed_install"]["workspace"] == str(workspace_dir)
    assert output["managed_install"]["manifest"]["managed_config_path"] == str(home_dir / ".codex" / "config.toml")


def test_guard_apps_connect_codex_stays_global_without_local_codex_config(
    tmp_path,
    monkeypatch,
    capsys,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
[mcp_servers.global_tools]
command = "python3"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    monkeypatch.chdir(workspace_dir)

    rc = main(
        [
            "guard",
            "apps",
            "connect",
            "codex",
            "--home",
            str(home_dir),
            "--guard-home",
            str(home_dir / ".hol-guard"),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["managed_install"]["active"] is True
    assert output["managed_install"]["workspace"] is None
    assert output["managed_install"]["manifest"]["managed_config_path"] == str(home_dir / ".codex" / "config.toml")


def test_guard_uninstall_codex_restores_original_workspace_config(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    uninstall_output = json.loads(capsys.readouterr().out)

    assert install_rc == 0
    assert uninstall_rc == 0
    assert uninstall_output["managed_install"]["active"] is False
    workspace_payload = tomllib.loads((workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    assert workspace_payload == {"approval_policy": "never"}
    assert (workspace_dir / ".codex" / "hooks.json").exists() is False


def test_guard_install_codex_refuses_unmanaged_existing_hook_entries(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    original_config = 'approval_policy = "never"\n'
    _write_text(workspace_dir / ".codex" / "config.toml", original_config)
    original_hooks = (
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": codex_adapter._CODEX_GUARD_TOOL_MATCHER,
                            "hooks": [{"type": "command", "command": "python3 custom-pre.py"}],
                        }
                    ],
                    "SessionStart": [
                        {
                            "matcher": "startup|resume",
                            "hooks": [{"type": "command", "command": "python3 custom-start.py"}],
                        }
                    ],
                }
            },
            indent=2,
        )
        + "\n"
    )
    _write_text(
        workspace_dir / ".codex" / "hooks.json",
        original_hooks,
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert "Guard refused to enable existing Codex hook entries without explicit approval" in captured.err
    assert (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == original_config
    assert (workspace_dir / ".codex" / "hooks.json").read_text(encoding="utf-8") == original_hooks


def test_guard_install_codex_allows_unmanaged_hooks_when_hooks_already_enabled(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
approval_policy = "never"

[features]
hooks = true
""".strip()
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "hooks.json",
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "python3 custom-pre.py"}],
                        }
                    ]
                }
            },
            indent=2,
        )
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    home_config = tomllib.loads((home_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    workspace_config = tomllib.loads((workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))

    assert rc == 0
    assert (workspace_dir / ".codex" / "hooks.json").exists() is False
    assert len(workspace_config["hooks"]["PreToolUse"]) == 1
    assert workspace_config["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "python3 custom-pre.py"
    assert len(home_config["hooks"]["PreToolUse"]) == 1
    assert home_config["hooks"]["PreToolUse"][0]["matcher"] == codex_adapter._CODEX_GUARD_TOOL_MATCHER


def test_guard_install_codex_migrates_global_and_workspace_hooks_to_toml(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(home_dir / ".codex" / "config.toml", 'model = "gpt-5.3-codex"\n')
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    context = HarnessContext(home_dir=home_dir, guard_home=home_dir, workspace_dir=workspace_dir)
    legacy_group = codex_adapter._managed_hook_groups(context)["PreToolUse"]
    _write_text(
        home_dir / ".codex" / "hooks.json",
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "hooks": [{"type": "command", "command": "python3 global-start.py"}],
                        }
                    ]
                }
            }
        )
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "hooks.json",
        json.dumps({"hooks": {"PreToolUse": [legacy_group]}}) + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    home_config = tomllib.loads((home_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    workspace_config = tomllib.loads((workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))

    assert rc == 0
    assert (home_dir / ".codex" / "hooks.json").exists() is False
    assert (workspace_dir / ".codex" / "hooks.json").exists() is False
    assert home_config["model"] == "gpt-5.3-codex"
    assert home_config["hooks"]["SessionStart"][0]["hooks"][0]["command"] == "python3 global-start.py"
    assert "hooks" not in workspace_config
    assert len(home_config["hooks"]["PreToolUse"]) == 1
    assert home_config["hooks"]["PreToolUse"][0]["matcher"] == codex_adapter._CODEX_GUARD_TOOL_MATCHER
    assert "codex_plugin_scanner.cli" in home_config["hooks"]["PreToolUse"][0]["hooks"][0]["command"]


def test_guard_install_codex_migrates_legacy_bash_only_managed_hook(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    context = HarnessContext(home_dir=home_dir, guard_home=home_dir, workspace_dir=workspace_dir)
    legacy_group = codex_adapter._managed_hook_groups(context)["PreToolUse"]
    _write_text(
        workspace_dir / ".codex" / "hooks.json",
        json.dumps({"hooks": {"PreToolUse": [legacy_group]}}, indent=2) + "\n",
    )

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    config_payload = tomllib.loads((home_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    workspace_config = tomllib.loads((workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))

    assert install_rc == 0
    assert (workspace_dir / ".codex" / "hooks.json").exists() is False
    assert "hooks" not in workspace_config
    assert len(config_payload["hooks"]["PreToolUse"]) == 1
    assert len(config_payload["hooks"]["PermissionRequest"]) == 1
    assert len(config_payload["hooks"]["UserPromptSubmit"]) == 1
    assert config_payload["hooks"]["PreToolUse"][0]["matcher"] == codex_adapter._CODEX_GUARD_TOOL_MATCHER
    assert config_payload["hooks"]["PreToolUse"][0]["hooks"][0]["statusMessage"] == "HOL Guard checking tool action"
    assert len(config_payload["hooks"]["UserPromptSubmit"]) == 1


def test_guard_install_codex_post_tool_use_hook_timeout_tracks_configured_browser_wait(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = home_dir / ".hol-guard"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(guard_home / "config.toml", "approval_wait_timeout_seconds = 45\n")

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--guard-home",
            str(guard_home),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    config_payload = tomllib.loads((home_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    hook_timeout = config_payload["hooks"]["PostToolUse"][0]["hooks"][0]["timeout"]

    assert install_rc == 0
    assert hook_timeout == 45 + codex_adapter._MANAGED_HOOK_TIMEOUT_GRACE_SECONDS


def test_guard_install_codex_pre_tool_use_hook_timeout_tracks_configured_browser_wait(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = home_dir / ".hol-guard"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(guard_home / "config.toml", "approval_wait_timeout_seconds = 45\n")

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--guard-home",
            str(guard_home),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    config_payload = tomllib.loads((home_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    hook_timeout = config_payload["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"]

    assert install_rc == 0
    assert hook_timeout == 45 + codex_adapter._MANAGED_HOOK_TIMEOUT_GRACE_SECONDS


def test_guard_install_codex_post_tool_use_hook_timeout_covers_max_browser_wait(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = home_dir / ".hol-guard"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(
        guard_home / "config.toml",
        f"approval_wait_timeout_seconds = {MAX_APPROVAL_WAIT_TIMEOUT_SECONDS}\n",
    )

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--guard-home",
            str(guard_home),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    config_payload = tomllib.loads((home_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    hook_timeout = config_payload["hooks"]["PostToolUse"][0]["hooks"][0]["timeout"]

    assert install_rc == 0
    assert hook_timeout == MAX_APPROVAL_WAIT_TIMEOUT_SECONDS + codex_adapter._MANAGED_HOOK_TIMEOUT_GRACE_SECONDS


def test_guard_install_codex_refuses_ambiguous_stale_python_c_hook(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    stale_worktree = tmp_path / "deleted-worktree"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    stale_command = f"{sys.executable} -c " + shlex.quote(
        "import sys;"
        f"sys.path[:0]=[{str(stale_worktree / 'src')!r}];"
        "from codex_plugin_scanner.cli import main;"
        "raise SystemExit(main(["
        '"guard", "hook", "--guard-home", '
        f"{str(home_dir / '.hol-guard')!r}, "
        '"--harness", "codex"'
        "]))"
    )
    _write_text(
        workspace_dir / ".codex" / "hooks.json",
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": stale_command,
                                    "timeoutSec": 30,
                                    "statusMessage": "HOL Guard checking tool action",
                                }
                            ],
                        }
                    ],
                    "UserPromptSubmit": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": stale_command,
                                    "timeoutSec": 30,
                                    "statusMessage": "HOL Guard checking prompt",
                                }
                            ]
                        }
                    ],
                }
            },
            indent=2,
        )
        + "\n",
    )

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    captured = capsys.readouterr()
    preserved_hooks = json.loads((workspace_dir / ".codex" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    preserved_commands = [
        handler["command"] for groups in preserved_hooks.values() for group in groups for handler in group["hooks"]
    ]

    assert install_rc == 1
    assert "Guard refused to enable existing Codex hook entries without explicit approval" in captured.err
    assert stale_command in preserved_commands
    assert (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == 'approval_policy = "never"\n'
    assert (home_dir / ".codex" / "config.toml").exists() is False


def test_guard_install_codex_refuses_ambiguous_legacy_wrapper_script_hook(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    wrapper_command = shlex.join([str(home_dir / ".codex" / "hooks" / "hol-guard-codex-hook.sh"), "--legacy"])
    managed_events = {
        "PreToolUse": {
            "matcher": codex_adapter._CODEX_GUARD_TOOL_MATCHER,
            "hooks": [
                {
                    "type": "command",
                    "command": wrapper_command,
                    "timeout": 30,
                    "statusMessage": "HOL Guard checking tool action",
                }
            ],
        },
        "PermissionRequest": {
            "matcher": "Bash|^apply_patch$|Edit|Write|mcp__.*",
            "hooks": [
                {
                    "type": "command",
                    "command": wrapper_command,
                    "timeout": 30,
                    "statusMessage": "HOL Guard checking Codex approval request",
                }
            ],
        },
        "UserPromptSubmit": {
            "hooks": [
                {
                    "type": "command",
                    "command": wrapper_command,
                    "timeout": 30,
                    "statusMessage": "HOL Guard checking prompt",
                }
            ],
        },
        "PostToolUse": {
            "matcher": "Bash",
            "hooks": [
                {
                    "type": "command",
                    "command": wrapper_command,
                    "timeout": 30,
                    "statusMessage": "HOL Guard checking tool result",
                }
            ],
        },
    }
    _write_text(
        workspace_dir / ".codex" / "hooks.json",
        json.dumps({"hooks": {key: [value] for key, value in managed_events.items()}}, indent=2) + "\n",
    )

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    captured = capsys.readouterr()

    assert install_rc == 1
    assert "Guard refused to enable existing Codex hook entries without explicit approval" in captured.err
    assert wrapper_command in (workspace_dir / ".codex" / "hooks.json").read_text(encoding="utf-8")
    assert (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == 'approval_policy = "never"\n'
    assert (home_dir / ".codex" / "config.toml").exists() is False


def test_guard_install_codex_workspace_refuses_to_rebind_global_managed_hook(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        home_dir / ".codex" / "config.toml",
        '[mcp_servers.global_tools]\ncommand = "python3"\nargs = ["-m", "http.server", "9000"]\n',
    )
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')

    global_install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    workspace_install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    workspace_output = capsys.readouterr()

    home_hooks_path = home_dir / ".codex" / "hooks.json"
    home_config = tomllib.loads((home_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    workspace_config = tomllib.loads((workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))

    assert global_install_rc == 0
    assert workspace_install_rc == 1
    assert workspace_output.out == ""
    assert home_hooks_path.exists() is False
    assert "hooks" not in workspace_config
    assert len(home_config["hooks"]["PreToolUse"]) == 1
    assert len(home_config["hooks"]["PermissionRequest"]) == 1
    assert len(home_config["hooks"]["UserPromptSubmit"]) == 1
    assert len(home_config["hooks"]["PostToolUse"]) == 1
    managed_group = home_config["hooks"]["PreToolUse"][0]
    assert managed_group["matcher"] == codex_adapter._CODEX_GUARD_TOOL_MATCHER
    assert "codex_plugin_scanner.cli" in managed_group["hooks"][0]["command"]


def test_guard_install_codex_workspace_context_mismatch_preserves_all_global_hooks(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(home_dir / ".codex" / "config.toml", 'model = "gpt-5.3-codex"\n')
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')

    global_install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    home_config = tomllib.loads((home_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    home_config["hooks"]["SessionStart"] = [
        {
            "hooks": [
                {
                    "type": "command",
                    "command": "python3 user-session-start.py",
                    "statusMessage": "User session start",
                }
            ]
        }
    ]
    _write_text(home_dir / ".codex" / "config.toml", dump_toml(home_config))

    workspace_install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    workspace_output = capsys.readouterr()
    final_home_config = tomllib.loads((home_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))

    assert global_install_rc == 0
    assert workspace_install_rc == 1
    assert workspace_output.out == ""
    assert final_home_config["model"] == "gpt-5.3-codex"
    hooks = final_home_config["hooks"]
    assert hooks["SessionStart"] == [
        {
            "hooks": [
                {
                    "type": "command",
                    "command": "python3 user-session-start.py",
                    "statusMessage": "User session start",
                }
            ]
        }
    ]
    assert len(hooks["PreToolUse"]) == 1
    assert len(hooks["PermissionRequest"]) == 1
    assert len(hooks["UserPromptSubmit"]) == 1
    assert len(hooks["PostToolUse"]) == 1


def test_guard_uninstall_codex_preserves_user_hooks_in_managed_bash_group(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    hooks_path = workspace_dir / ".codex" / "hooks.json"
    hooks_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": codex_adapter._CODEX_GUARD_TOOL_MATCHER,
                            "hooks": [{"type": "command", "command": "python3 custom-pre.py"}],
                        }
                    ]
                }
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    restored_hooks = json.loads(hooks_path.read_text(encoding="utf-8"))

    assert install_rc == 0
    assert uninstall_rc == 0
    assert restored_hooks["hooks"]["PreToolUse"] == [
        {
            "matcher": codex_adapter._CODEX_GUARD_TOOL_MATCHER,
            "hooks": [{"type": "command", "command": "python3 custom-pre.py"}],
        }
    ]


def test_guard_install_codex_refuses_invalid_alternate_hook_file_before_config_write(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    original_config = 'approval_policy = "never"\n'
    _write_text(workspace_dir / ".codex" / "config.toml", original_config)
    _write_text(home_dir / ".codex" / "hooks.json", '{"hooks": ')

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert "Guard refused to overwrite unreadable Codex hooks file" in captured.err
    assert (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == original_config
    assert (home_dir / ".codex" / "hooks.json").read_text(encoding="utf-8") == '{"hooks": '


def test_guard_install_codex_refuses_non_file_alternate_hook_path_before_config_write(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    original_config = 'approval_policy = "never"\n'
    _write_text(workspace_dir / ".codex" / "config.toml", original_config)
    (home_dir / ".codex" / "hooks.json").mkdir(parents=True)

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert "Guard refused to overwrite non-file Codex hooks file" in captured.err
    assert (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == original_config
    assert (home_dir / ".codex" / "hooks.json").is_dir() is True


def test_guard_uninstall_codex_succeeds_when_alternate_hook_file_is_invalid(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    original_config = 'approval_policy = "never"\n'
    _write_text(workspace_dir / ".codex" / "config.toml", original_config)

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    _write_text(home_dir / ".codex" / "hooks.json", '{"hooks": ')

    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    uninstall_output = json.loads(capsys.readouterr().out)

    assert install_rc == 0
    assert uninstall_rc == 0
    assert uninstall_output["managed_install"]["active"] is False
    assert (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == original_config
    assert (workspace_dir / ".codex" / "hooks.json").exists() is False
    assert (home_dir / ".codex" / "hooks.json").read_text(encoding="utf-8") == '{"hooks": '


def test_guard_uninstall_codex_preserves_invalid_target_hook_file(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    original_config = 'approval_policy = "never"\n'
    _write_text(workspace_dir / ".codex" / "config.toml", original_config)

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    _write_text(workspace_dir / ".codex" / "hooks.json", '{"hooks": ')

    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    uninstall_output = json.loads(capsys.readouterr().out)

    assert install_rc == 0
    assert uninstall_rc == 0
    assert uninstall_output["managed_install"]["active"] is False
    assert (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == original_config
    assert (workspace_dir / ".codex" / "hooks.json").read_text(encoding="utf-8") == '{"hooks": '


def test_guard_install_codex_migrates_read_only_alternate_hook_file(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(home_dir / ".codex" / "config.toml", "[features]\nhooks = true\n")
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    home_hooks_path = home_dir / ".codex" / "hooks.json"
    original_hooks = json.dumps(
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "python3 custom-pre.py"}],
                    }
                ]
            }
        },
        indent=2,
    )
    _write_text(home_hooks_path, original_hooks + "\n")
    os.chmod(home_hooks_path, 0o444)

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    assert install_rc == 0
    assert home_hooks_path.exists() is False
    home_config = tomllib.loads((home_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    assert home_config["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "python3 custom-pre.py"


def test_guard_uninstall_codex_preserves_migrated_alternate_hook_config(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(home_dir / ".codex" / "config.toml", "[features]\nhooks = true\n")
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    home_hooks_path = home_dir / ".codex" / "hooks.json"
    original_hooks = json.dumps(
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "python3 custom-pre.py"}],
                    }
                ]
            }
        },
        indent=2,
    )
    _write_text(home_hooks_path, original_hooks + "\n")

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    assert install_rc == 0
    assert uninstall_rc == 0
    assert home_hooks_path.exists() is False
    home_config = tomllib.loads((home_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    assert home_config["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "python3 custom-pre.py"


def test_guard_install_codex_disables_empty_alternate_hook_config(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=home_dir / ".hol-guard",
    )
    alternate_config_path = workspace_dir / ".codex" / "config.toml"
    _write_text(
        alternate_config_path,
        dump_toml(
            {
                "features": {"experimental": True, "hooks": True},
                "hooks": {
                    event_name: [group]
                    for event_name, group in codex_adapter._managed_hook_groups(context).items()
                },
            }
        ),
    )

    CodexHarnessAdapter().install(context)

    alternate_config = tomllib.loads(alternate_config_path.read_text(encoding="utf-8"))
    assert alternate_config["features"] == {"experimental": True}
    assert "hooks" not in alternate_config


def test_guard_install_codex_removes_empty_alternate_hook_file(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    home_hooks_path = home_dir / ".codex" / "hooks.json"
    original_hooks = '{\n  "hooks": {}\n}\n'
    _write_text(home_hooks_path, original_hooks)

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    assert install_rc == 0
    assert home_hooks_path.exists() is False


def test_guard_uninstall_codex_keeps_empty_alternate_hook_file_removed(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    home_hooks_path = home_dir / ".codex" / "hooks.json"
    original_hooks = '{\n  "hooks": {}\n}\n'
    _write_text(home_hooks_path, original_hooks)

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    assert install_rc == 0
    assert uninstall_rc == 0
    assert home_hooks_path.exists() is False


def test_guard_detect_codex_collects_global_and_workspace_hooks(tmp_path):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        home_dir / ".codex" / "hooks.json",
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "python3 global-pre.py"}],
                        }
                    ]
                }
            },
            indent=2,
        )
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "hooks.json",
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "python3 workspace-pre.py"}],
                        }
                    ]
                }
            },
            indent=2,
        )
        + "\n",
    )

    detection = CodexHarnessAdapter().detect(
        HarnessContext(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            guard_home=tmp_path / "guard-home",
        )
    )

    hook_artifacts = [artifact for artifact in detection.artifacts if artifact.artifact_type == "hook"]

    assert {artifact.command for artifact in hook_artifacts} == {
        "python3 global-pre.py",
        "python3 workspace-pre.py",
    }
    assert {artifact.source_scope for artifact in hook_artifacts} == {"global", "project"}
    assert set(detection.config_paths) == {
        str(home_dir / ".codex" / "hooks.json"),
        str(workspace_dir / ".codex" / "hooks.json"),
    }


def test_guard_install_codex_encodes_dash_prefixed_server_args_safely(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.flagged_tool]
command = "python3"
args = ["server.py", "--marker-path", "marker.json"]
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    config_text = (home_dir / ".codex" / "config.toml").read_text(encoding="utf-8")

    assert rc == 0
    assert "--arg=--marker-path" in config_text


def test_guard_reinstall_codex_preserves_original_backup(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    first_install = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    first_output = json.loads(capsys.readouterr().out)
    second_install = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    backup_path = Path(first_output["managed_install"]["manifest"]["backup_path"])

    assert first_install == 0
    assert second_install == 0
    assert uninstall_rc == 0
    assert backup_path.exists() is False
    workspace_payload = tomllib.loads((workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    assert workspace_payload == {"approval_policy": "never"}


def test_guard_install_codex_preserves_inline_tables_inside_arrays(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
approval_policy = "never"
profiles = [{ name = "default", mode = "safe" }, { name = "strict", mode = "review" }]

[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js"]
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    with (workspace_dir / ".codex" / "config.toml").open("rb") as handle:
        workspace_payload = tomllib.load(handle)
    with (home_dir / ".codex" / "config.toml").open("rb") as handle:
        global_payload = tomllib.load(handle)

    assert rc == 0
    assert workspace_payload["profiles"] == [
        {"name": "default", "mode": "safe"},
        {"name": "strict", "mode": "review"},
    ]
    assert "mcp_servers" not in workspace_payload
    assert "workspace_skill" in global_payload["mcp_servers"]


def test_guard_reinstall_codex_refreshes_backup_after_completed_uninstall(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    first_install = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    first_output = json.loads(capsys.readouterr().out)
    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
approval_policy = "never"

[mcp_servers.workspace_skill]
command = "node"
args = ["edited-workspace-skill.js"]
""".strip()
        + "\n",
    )

    second_install = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    second_output = json.loads(capsys.readouterr().out)
    second_uninstall = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    backup_path = Path(first_output["managed_install"]["manifest"]["backup_path"])

    assert first_install == 0
    assert uninstall_rc == 0
    assert second_install == 0
    assert second_uninstall == 0
    assert backup_path == Path(second_output["managed_install"]["manifest"]["backup_path"])
    assert backup_path.exists() is False
    workspace_payload = tomllib.loads((workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    assert workspace_payload == {"approval_policy": "never"}


def test_guard_install_codex_proxy_entry_boots_outside_dev_shell_when_pythonpath_is_required(
    tmp_path, capsys, monkeypatch
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    marker_path = tmp_path / "marker.json"
    canary_path = Path(__file__).resolve().parent / "fixtures" / "mcp-canary-server.py"
    source_root = Path(__file__).resolve().parents[1] / "src"
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    monkeypatch.setenv("PYTHONPATH", "src")
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        f"""
[mcp_servers.danger_lab]
command = "python3"
args = [{str(canary_path)!r}, "--marker-path", {str(marker_path)!r}]
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    with (home_dir / ".codex" / "config.toml").open("rb") as handle:
        payload = tomllib.load(handle)
    proxy_entry = payload["mcp_servers"]["danger_lab"]
    proxy_env = dict(proxy_entry.get("env", {}))
    result = subprocess.run(
        [proxy_entry["command"], *proxy_entry["args"]],
        input='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}\n',
        text=True,
        capture_output=True,
        cwd=workspace_dir,
        env={
            "PATH": os.environ["PATH"],
            "HOME": str(home_dir),
            **proxy_env,
        },
        check=False,
    )

    assert rc == 0
    assert proxy_env["PYTHONPATH"] == str(source_root)
    assert result.returncode == 0
    assert json.loads(result.stdout)["result"]["serverInfo"]["name"] == "danger-lab"


def test_guard_install_codex_strips_server_python_injection_env_entries(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    source_root = Path(__file__).resolve().parents[1] / "src"
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    monkeypatch.setenv("PYTHONPATH", "src")
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.danger_lab]
command = "python3"
args = ["danger-lab.py"]
env = { PYTHONPATH = "app/src", API_BASE = "https://hol.org" }
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    with (home_dir / ".codex" / "config.toml").open("rb") as handle:
        payload = tomllib.load(handle)
    proxy_env = payload["mcp_servers"]["danger_lab"]["env"]

    assert rc == 0
    assert proxy_env["PYTHONPATH"] == str(source_root)
    assert proxy_env["API_BASE"] == "https://hol.org"


def test_guard_install_codex_ignores_server_attempt_to_clear_launcher_pythonpath(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    source_root = Path(__file__).resolve().parents[1] / "src"
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    monkeypatch.setenv("PYTHONPATH", "src")
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.danger_lab]
command = "python3"
args = ["danger-lab.py"]
env = { PYTHONPATH = "" }
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    with (home_dir / ".codex" / "config.toml").open("rb") as handle:
        payload = tomllib.load(handle)
    proxy_env = payload["mcp_servers"]["danger_lab"]["env"]

    assert rc == 0
    assert proxy_env["PYTHONPATH"] == str(source_root)
