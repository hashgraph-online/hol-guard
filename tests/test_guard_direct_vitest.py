"""Regression coverage for verified direct local JavaScript tool execution."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.runtime import direct_vitest
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


@pytest.fixture(autouse=True)
def _exclude_workspace_virtualenv_from_path(  # pyright: ignore[reportUnusedFunction]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = Path().resolve()
    entries: list[str] = []
    for raw_entry in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(raw_entry or ".").expanduser()
        if not candidate.is_absolute():
            candidate = workspace / candidate
        try:
            _ = candidate.resolve().relative_to(workspace)
        except (OSError, RuntimeError):
            continue
        except ValueError:
            entries.append(raw_entry)
    monkeypatch.setenv("PATH", os.pathsep.join(entries))


def _write_package(root: Path, *, include_lock: bool = True, declares_vitest: bool = True) -> None:
    root.mkdir(parents=True, exist_ok=True)
    dependencies = {"vitest": "^4.1.8"} if declares_vitest else {}
    _ = (root / "package.json").write_text(
        json.dumps({"name": "fixture", "devDependencies": dependencies}),
        encoding="utf-8",
    )
    if include_lock:
        _ = (root / "bun.lock").write_text(
            json.dumps({"packages": {"vitest": ["vitest@4.1.8"]}}),
            encoding="utf-8",
        )


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    home = tmp_path / "home"
    caller = home / "caller"
    workspace = tmp_path / "subject"
    runner_project = home / "runner-project"
    _write_package(workspace)
    _write_package(runner_project)
    caller.mkdir(parents=True)
    test_file = workspace / "tests" / "unit.test.ts"
    test_file.parent.mkdir()
    _ = test_file.write_text("export {};\n", encoding="utf-8")
    package_dir = runner_project / "node_modules" / "vitest"
    package_dir.mkdir(parents=True)
    _ = (package_dir / "package.json").write_text(
        json.dumps({"name": "vitest", "version": "4.1.8", "bin": {"vitest": "./vitest.mjs"}}),
        encoding="utf-8",
    )
    runner = package_dir / "vitest.mjs"
    _ = runner.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    runner.chmod(0o755)
    bin_directory = runner_project / "node_modules" / ".bin"
    bin_directory.mkdir()
    _ = (bin_directory / "vitest").symlink_to("../vitest/vitest.mjs")
    return home, caller, workspace, runner


def _command(workspace: Path, runner: Path, *, suffix: str = "--no-coverage 2>&1 | tail -40") -> str:
    return f"cd {workspace} && {runner} run tests/unit.test.ts {suffix}"


def _trust_fixture_command(command: str, *, cwd: Path, home_dir: Path) -> bool:
    del cwd, home_dir
    return command in {"bun", "grep", "head", "node", "npx", "tail", "wc"}


def _typescript_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    home = tmp_path / "home"
    caller = home / "caller"
    workspace = home / "subject"
    caller.mkdir(parents=True)
    package_dir = workspace / "node_modules" / "typescript"
    compiler = package_dir / "bin" / "tsc"
    compiler.parent.mkdir(parents=True)
    _ = compiler.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    _ = (package_dir / "package.json").write_text(
        json.dumps({"name": "typescript", "version": "5.9.3", "bin": {"tsc": "./bin/tsc"}}),
        encoding="utf-8",
    )
    _ = (workspace / "package.json").write_text(
        json.dumps({"name": "fixture", "devDependencies": {"typescript": "^5.9.3"}}),
        encoding="utf-8",
    )
    _ = (workspace / "bun.lock").write_text(
        json.dumps(
            {
                "packages": {
                    "typescript": [
                        "typescript@5.9.3",
                        "",
                        {"bin": {"tsc": "bin/tsc"}},
                        (
                            "sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQdia"
                            "UpFT4bXlb1RHhLpp8wtm6M5TgSw=="
                        ),
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    return home, caller, workspace


def _trust_typescript_fixture(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identities = dict(direct_vitest._TRUSTED_TYPESCRIPT_PACKAGES)  # pyright: ignore[reportPrivateUsage]
    identity = next(iter(identities))
    identities[identity] = direct_vitest._package_tree_digest(  # pyright: ignore[reportPrivateUsage]
        workspace / "node_modules" / "typescript"
    )
    monkeypatch.setattr(direct_vitest, "_TRUSTED_TYPESCRIPT_PACKAGES", identities)


def _typescript_command(workspace: Path) -> str:
    return (
        f'cd {workspace} && NODE_OPTIONS="--max-old-space-size=8192" '
        "bun --smol ./node_modules/typescript/bin/tsc --noEmit 2>&1 "
        "| grep 'error TS' | wc -l; echo \"MY_TSC_ERRORS_COUNT_DONE\""
    )


def test_verified_direct_typescript_count_is_explicitly_benign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, workspace = _typescript_fixture(tmp_path)
    _trust_typescript_fixture(workspace, monkeypatch)
    command = _typescript_command(workspace)
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trust_fixture_command)

    assert (
        extract_sensitive_tool_action_request(
            "bash",
            {"command": command},
            cwd=caller,
            home_dir=home,
        )
        is None
    )
    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )
    assert (
        _hook_runtime_artifact(
            harness="pi",
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "bash",
                "tool_input": {"command": command},
            },
            action_envelope=None,
            home_dir=home,
            guard_home=home / ".guard",
            workspace=caller,
        )
        is None
    )


@pytest.mark.parametrize(
    "replacement",
    (
        'NODE_OPTIONS="--require=payload"',
        'NODE_OPTIONS="--max-old-space-size=99999"',
        "bun ./node_modules/typescript/bin/tsc --noEmit",
        "bun --smol ./node_modules/typescript/bin/tsc",
        "bun --smol ./node_modules/typescript/bin/tsc --noEmit --outDir output",
        "grep secret",
        "wc -c",
        'echo "DONE"; payload',
    ),
)
def test_direct_typescript_count_rejects_widened_segments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: str,
) -> None:
    home, caller, workspace = _typescript_fixture(tmp_path)
    _trust_typescript_fixture(workspace, monkeypatch)
    command = _typescript_command(workspace)
    original = {
        'NODE_OPTIONS="--require=payload"': 'NODE_OPTIONS="--max-old-space-size=8192"',
        'NODE_OPTIONS="--max-old-space-size=99999"': 'NODE_OPTIONS="--max-old-space-size=8192"',
        "bun ./node_modules/typescript/bin/tsc --noEmit": "bun --smol ./node_modules/typescript/bin/tsc --noEmit",
        "bun --smol ./node_modules/typescript/bin/tsc": "bun --smol ./node_modules/typescript/bin/tsc --noEmit",
        "bun --smol ./node_modules/typescript/bin/tsc --noEmit --outDir output": (
            "bun --smol ./node_modules/typescript/bin/tsc --noEmit"
        ),
        "grep secret": "grep 'error TS'",
        "wc -c": "wc -l",
        'echo "DONE"; payload': 'echo "MY_TSC_ERRORS_COUNT_DONE"',
    }[replacement]
    command = command.replace(original, replacement)
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trust_fixture_command)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )


def test_direct_typescript_count_requires_locked_installed_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, workspace = _typescript_fixture(tmp_path)
    _trust_typescript_fixture(workspace, monkeypatch)
    _ = (workspace / "bun.lock").write_text(
        json.dumps({"packages": {"typescript": ["typescript@5.8.0"]}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trust_fixture_command)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _typescript_command(workspace)},
        cwd=caller,
        home_dir=home,
    )


def test_direct_typescript_count_rejects_compiler_byte_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, workspace = _typescript_fixture(tmp_path)
    _trust_typescript_fixture(workspace, monkeypatch)
    _ = (workspace / "node_modules" / "typescript" / "bin" / "tsc").write_text(
        "#!/usr/bin/env node\nrequire('./payload');\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trust_fixture_command)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _typescript_command(workspace)},
        cwd=caller,
        home_dir=home,
    )


def test_direct_typescript_count_rejects_forged_lock_integrity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, workspace = _typescript_fixture(tmp_path)
    _trust_typescript_fixture(workspace, monkeypatch)
    lockfile = workspace / "bun.lock"
    lock_text = lockfile.read_text(encoding="utf-8")
    integrity = next(iter(direct_vitest._TRUSTED_TYPESCRIPT_PACKAGES))[1]  # pyright: ignore[reportPrivateUsage]
    _ = lockfile.write_text(
        lock_text.replace(integrity, "sha512-" + ("A" * 86) + "=="),
        encoding="utf-8",
    )
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trust_fixture_command)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _typescript_command(workspace)},
        cwd=caller,
        home_dir=home,
    )


def test_direct_typescript_count_allows_install_only_bun_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, workspace = _typescript_fixture(tmp_path)
    _trust_typescript_fixture(workspace, monkeypatch)
    _ = (workspace / "bunfig.toml").write_text(
        '[install]\nlinker = "isolated"\nsmol = true\nlockfile.save = true\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trust_fixture_command)

    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _typescript_command(workspace)},
        cwd=caller,
        home_dir=home,
    )


def test_direct_typescript_count_rejects_bun_auto_install_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, workspace = _typescript_fixture(tmp_path)
    _trust_typescript_fixture(workspace, monkeypatch)
    _ = (workspace / "bunfig.toml").write_text(
        '[install]\nauto = "force"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trust_fixture_command)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _typescript_command(workspace)},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize("config_location", ("workspace", "ancestor", "home", "xdg"))
def test_direct_typescript_count_rejects_bun_preload_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_location: str,
) -> None:
    home, caller, workspace = _typescript_fixture(tmp_path)
    _trust_typescript_fixture(workspace, monkeypatch)
    config_root = {
        "workspace": workspace,
        "ancestor": workspace.parent,
        "home": home,
        "xdg": tmp_path / "xdg",
    }[config_location]
    config_root.mkdir(exist_ok=True)
    if config_location == "xdg":
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_root))
    config_name = "bunfig.toml" if config_location in {"workspace", "ancestor"} else ".bunfig.toml"
    _ = (config_root / config_name).write_text(
        'preload = ["./payload.ts"]\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trust_fixture_command)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _typescript_command(workspace)},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize("lock_kind", ("symlink", "oversized"))
def test_direct_typescript_count_rejects_unbounded_or_indirect_bun_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lock_kind: str,
) -> None:
    home, caller, workspace = _typescript_fixture(tmp_path)
    _trust_typescript_fixture(workspace, monkeypatch)
    lockfile = workspace / "bun.lock"
    if lock_kind == "symlink":
        target = workspace / "indirect-bun.lock"
        _ = target.write_bytes(lockfile.read_bytes())
        lockfile.unlink()
        _ = lockfile.symlink_to(target)
    else:
        monkeypatch.setattr(direct_vitest, "_MAX_METADATA_BYTES", lockfile.stat().st_size - 1)
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trust_fixture_command)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _typescript_command(workspace)},
        cwd=caller,
        home_dir=home,
    )


def test_direct_typescript_count_rejects_inherited_bun_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, workspace = _typescript_fixture(tmp_path)
    _trust_typescript_fixture(workspace, monkeypatch)
    monkeypatch.setenv("BUN_OPTIONS", f"--preload {tmp_path / 'payload.ts'}")
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trust_fixture_command)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _typescript_command(workspace)},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize("untrusted_command", ("bun", "grep", "wc"))
def test_direct_typescript_count_rejects_untrusted_path_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    untrusted_command: str,
) -> None:
    home, caller, workspace = _typescript_fixture(tmp_path)
    _trust_typescript_fixture(workspace, monkeypatch)

    def trust_other_commands(command: str, *, cwd: Path, home_dir: Path) -> bool:
        del cwd, home_dir
        return command != untrusted_command

    monkeypatch.setattr(direct_vitest, "_trusted_path_command", trust_other_commands)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _typescript_command(workspace)},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize(
    ("integrity", "path_active", "expected"),
    (("ok", True, True), ("stale", True, False), ("tampered", True, False), ("ok", False, False)),
)
def test_trusted_path_command_accepts_only_authenticated_active_bun_shims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    integrity: str,
    path_active: bool,
    expected: bool,
) -> None:
    shim = tmp_path / ".hol-guard" / "package-shims" / "bin" / "bun"
    shim.parent.mkdir(parents=True)
    _ = shim.write_text("#!/bin/sh\n", encoding="utf-8")

    def find_shim(_command: str, *, path: str | None = None) -> str:
        del path
        return str(shim)

    def reject_system_binary(_path: Path, *, cwd: Path) -> bool:
        del cwd
        return False

    def shim_status(_context: object, *, path_env: str | None = None) -> dict[str, object]:
        del path_env
        return {
            "manager_details": [
                {
                    "integrity": integrity,
                    "manager": "bun",
                    "path_active": path_active,
                    "shim_path": str(shim),
                }
            ]
        }

    monkeypatch.setattr(shutil, "which", find_shim)
    monkeypatch.setattr(direct_vitest, "git_binary_path_is_trusted", reject_system_binary)
    monkeypatch.setattr(
        direct_vitest,
        "package_shim_status",
        shim_status,
    )

    assert direct_vitest._trusted_path_command("bun", cwd=tmp_path, home_dir=tmp_path) is expected  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("failure", ("invalid-payload", "unexpected-error"))
def test_trusted_path_command_fails_closed_for_shim_status_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    shim = tmp_path / ".hol-guard" / "package-shims" / "bin" / "bun"
    shim.parent.mkdir(parents=True)
    _ = shim.write_text("#!/bin/sh\n", encoding="utf-8")

    def find_shim(_command: str, *, path: str | None = None) -> str:
        del path
        return str(shim)

    def reject_system_binary(_path: Path, *, cwd: Path) -> bool:
        del cwd
        return False

    def broken_status(_context: object, *, path_env: str | None = None) -> object:
        del path_env
        if failure == "unexpected-error":
            raise TypeError("malformed shim state")
        return None

    monkeypatch.setattr(shutil, "which", find_shim)
    monkeypatch.setattr(direct_vitest, "git_binary_path_is_trusted", reject_system_binary)
    monkeypatch.setattr(direct_vitest, "package_shim_status", broken_status)

    assert not direct_vitest._trusted_path_command(  # pyright: ignore[reportPrivateUsage]
        "bun", cwd=tmp_path, home_dir=tmp_path
    )


def test_verified_direct_vitest_identity_does_not_bypass_uncontained_code_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    command = _command(workspace, runner)
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trust_fixture_command)
    request = extract_sensitive_tool_action_request("bash", {"command": command}, cwd=caller, home_dir=home)
    assert request is not None
    assert request.guard_default_action == "require-reapproval"
    assert not is_explicitly_benign_tool_action_request("bash", {"command": command}, cwd=caller, home_dir=home)
    # A verified launch location is not isolation from local credentials.
    assert (
        _hook_runtime_artifact(
            harness="pi",
            payload={"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": command}},
            action_envelope=None,
            home_dir=home,
            guard_home=home / ".guard",
            workspace=caller,
        )
        is not None
    )


def test_verified_npx_vitest_still_requires_execution_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    _ = (workspace / "node_modules").symlink_to(runner.parents[1], target_is_directory=True)
    command = f"cd {workspace} && npx vitest run tests/unit.test.ts 2>&1 | tail -40"
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trust_fixture_command)

    assert (
        extract_sensitive_tool_action_request(
            "bash",
            {"command": command},
            cwd=caller,
            home_dir=home,
        )
        is None
    )
    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )
    assert (
        _hook_runtime_artifact(
            harness="codex",
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "bash",
                "tool_input": {"command": command},
            },
            action_envelope=None,
            home_dir=home,
            guard_home=home / ".guard",
            workspace=caller,
        )
        is not None
    )


@pytest.mark.parametrize(
    "runner_command",
    (
        "npx vitest run tests/unit.test.ts --config attacker.ts",
        "npx --package=vitest vitest run tests/unit.test.ts",
        "npx other run tests/unit.test.ts",
        "npx --no --no-install vitest",
    ),
)
def test_npx_vitest_rejects_unbounded_runner_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runner_command: str,
) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    _ = (workspace / "node_modules").symlink_to(runner.parents[1], target_is_directory=True)
    command = f"cd {workspace} && {runner_command} 2>&1 | tail -40"
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trust_fixture_command)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )


def test_npx_vitest_rejects_retargeted_bin_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    node_modules = runner.parents[1]
    _ = (workspace / "node_modules").symlink_to(node_modules, target_is_directory=True)
    attacker = node_modules / "attacker.mjs"
    _ = attacker.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    bin_entry = node_modules / ".bin" / "vitest"
    bin_entry.unlink()
    _ = bin_entry.symlink_to("../attacker.mjs")
    command = f"cd {workspace} && npx vitest run tests/unit.test.ts 2>&1 | tail -40"
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trust_fixture_command)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )


def test_npx_vitest_requires_installed_local_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, workspace, _runner = _fixture(tmp_path)
    command = f"cd {workspace} && npx vitest run tests/unit.test.ts 2>&1 | tail -40"
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trust_fixture_command)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize(
    "suffix",
    (
        "--config attacker.ts --no-coverage 2>&1 | tail -40",
        "--no-coverage > result.txt",
        "--no-coverage",
        "--no-coverage | tail -40",
        "--no-coverage 2>&1 | tee result.txt",
        "--no-coverage 2>&1 | tail -1001",
        "--no-coverage $(touch marker)",
    ),
)
def test_direct_vitest_rejects_unsafe_options_and_shell_behavior(tmp_path: Path, suffix: str) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, runner, suffix=suffix)},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize("missing", ("workspace-package", "workspace-lock", "runner-package", "runner-lock"))
def test_direct_vitest_requires_manifest_and_lock_evidence(tmp_path: Path, missing: str) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    runner_project = runner.parents[2]
    target = {
        "workspace-package": workspace / "package.json",
        "workspace-lock": workspace / "bun.lock",
        "runner-package": runner_project / "package.json",
        "runner-lock": runner_project / "bun.lock",
    }[missing]
    target.unlink()

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, runner)},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize("evidence", ("workspace-lock", "runner-lock"))
@pytest.mark.parametrize(
    "lock_payload",
    (
        {},
        {"packages": {"vitest": ["vitest@5.0.0"]}},
    ),
)
def test_direct_vitest_requires_bound_lock_version(
    tmp_path: Path,
    evidence: str,
    lock_payload: dict[str, object],
) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    runner_project = runner.parents[2]
    lockfile = workspace / "bun.lock" if evidence == "workspace-lock" else runner_project / "bun.lock"
    _ = lockfile.write_text(json.dumps(lock_payload), encoding="utf-8")

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, runner)},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize(
    "evidence",
    ("workspace-package", "workspace-lock", "runner-package", "runner-lock", "installed-package"),
)
def test_direct_vitest_rejects_symlinked_evidence(tmp_path: Path, evidence: str) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    runner_project = runner.parents[2]
    target = {
        "workspace-package": workspace / "package.json",
        "workspace-lock": workspace / "bun.lock",
        "runner-package": runner_project / "package.json",
        "runner-lock": runner_project / "bun.lock",
        "installed-package": runner.parent / "package.json",
    }[evidence]
    real = target.with_name(f"{target.name}.real")
    _ = target.rename(real)
    _ = target.symlink_to(real)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, runner)},
        cwd=caller,
        home_dir=home,
    )


def test_direct_vitest_rejects_retargeted_runner_package(tmp_path: Path) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    _ = (runner.parent / "package.json").write_text(
        json.dumps({"name": "lookalike", "version": "4.1.8"}),
        encoding="utf-8",
    )

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, runner)},
        cwd=caller,
        home_dir=home,
    )


def test_direct_vitest_rejects_symlinked_runner(tmp_path: Path) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    actual = runner.with_name("actual.mjs")
    _ = runner.rename(actual)
    _ = runner.symlink_to(actual)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, runner)},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize("target", ("tests/missing.test.ts", "../outside.test.ts", "tests/helper.ts"))
def test_direct_vitest_rejects_missing_escaping_and_non_test_targets(tmp_path: Path, target: str) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    outside = workspace.parent / "outside.test.ts"
    _ = outside.write_text("export {};\n", encoding="utf-8")
    _ = (workspace / "tests" / "helper.ts").write_text("export {};\n", encoding="utf-8")
    command = f"cd {workspace} && {runner} run {target} --no-coverage 2>&1 | head -20"

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )


def test_direct_vitest_rejects_arbitrary_javascript_runner(tmp_path: Path) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    arbitrary = runner.parents[2] / "scripts" / "vitest.mjs"
    arbitrary.parent.mkdir()
    _ = arbitrary.write_text("#!/usr/bin/env node\n", encoding="utf-8")

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, arbitrary)},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize("shadowed_command", ("node", "head", "tail"))
@pytest.mark.parametrize("path_entry", (".", "bin"))
def test_direct_vitest_rejects_shadowed_runtime_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    shadowed_command: str,
    path_entry: str,
) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    shadow_directory = workspace if path_entry == "." else workspace / path_entry
    shadow_directory.mkdir(exist_ok=True)
    shadow = shadow_directory / shadowed_command
    _ = shadow.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shadow.chmod(0o755)
    monkeypatch.setenv("PATH", f"{path_entry}{os.pathsep}{os.environ.get('PATH', '')}")
    suffix = "--no-coverage 2>&1 | head -40" if shadowed_command == "head" else "--no-coverage 2>&1 | tail -40"

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, runner, suffix=suffix)},
        cwd=caller,
        home_dir=home,
    )
