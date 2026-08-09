"""Regressions for verified TypeScript diagnostic filtering."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.runtime import direct_vitest
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


def _trusted_command(_command: str, *, cwd: Path, home_dir: Path) -> bool:
    del cwd, home_dir
    return True


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, str]:
    for key in tuple(os.environ):
        normalized_key = key.casefold()
        if (
            key.startswith(("BASH_FUNC_", "DYLD_", "LD_"))
            or normalized_key.startswith("npm_config_")
            or normalized_key in {"bash_env", "env", "node_options", "node_path", "zdotdir"}
        ):
            monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    caller = home / "caller"
    workspace = tmp_path / "subject"
    caller.mkdir(parents=True)
    package_dir = workspace / "node_modules" / "typescript"
    compiler = package_dir / "bin" / "tsc"
    compiler.parent.mkdir(parents=True)
    _ = compiler.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    _ = (package_dir / "package.json").write_text(
        json.dumps({"name": "typescript", "version": "5.9.3", "bin": {"tsc": "./bin/tsc"}}),
        encoding="utf-8",
    )
    bin_directory = workspace / "node_modules" / ".bin"
    bin_directory.mkdir()
    _ = (bin_directory / "tsc").symlink_to("../typescript/bin/tsc")
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
    identities = dict(direct_vitest._TRUSTED_TYPESCRIPT_PACKAGES)  # pyright: ignore[reportPrivateUsage]
    identity = next(iter(identities))
    identities[identity] = direct_vitest._package_tree_digest(package_dir)  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(direct_vitest, "_TRUSTED_TYPESCRIPT_PACKAGES", identities)
    monkeypatch.setattr(direct_vitest, "_trusted_path_command", _trusted_command)
    command = (
        f"cd {workspace} && npx tsc --noEmit 2>&1 "
        '| grep -E "harnesses/page|enterprises/page" || echo "NO_ERRORS_IN_TOUCHED_FILES"'
    )
    return home, caller, command


def test_verified_typescript_diagnostic_filter_is_benign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)

    request = extract_sensitive_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )

    assert request is None
    assert is_explicitly_benign_tool_action_request(
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
                "tool_name": "Bash",
                "tool_input": {"command": command},
            },
            action_envelope=None,
            home_dir=home,
            guard_home=home / ".guard",
            workspace=caller,
        )
        is None
    )


def test_typescript_diagnostic_filter_accepts_escaped_literal_dots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)

    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command.replace("harnesses/page|enterprises/page", r"src/page\.tsx|app/route\.tsx")},
        cwd=caller,
        home_dir=home,
    )


def test_verified_routine_typescript_pipeline_is_benign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)
    workspace = Path(command.split(" && ", 1)[0].removeprefix("cd "))
    source = workspace / "src" / "index.ts"
    source.parent.mkdir()
    _ = source.write_text("export const value = 1;\n", encoding="utf-8")
    command = (
        f"cd {workspace} && npx tsc --noEmit --types @cloudflare/workers-types "
        "--lib es2022 --target es2022 --module esnext --moduleResolution bundler "
        '--skipLibCheck src/index.ts 2>&1 | grep -v "npm warn" | head -8; echo "TSC_DONE"'
    )

    heap_command = command.replace("npx tsc", 'NODE_OPTIONS="--max-old-space-size=8192" npx tsc').replace(
        '| grep -v "npm warn" | head -8',
        "| head -40",
    )
    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": heap_command},
        cwd=caller,
        home_dir=home,
    )

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


def test_verified_direct_typescript_diagnostic_is_benign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)
    workspace = Path(command.split(" && ", 1)[0].removeprefix("cd "))
    source = workspace / "workers" / "services" / "risk.ts"
    source.parent.mkdir(parents=True)
    _ = source.write_text("export {};\n", encoding="utf-8")
    command = (
        f'cd {workspace} && NODE_OPTIONS="--max-old-space-size=8192" npx tsc --noEmit '
        + "--strict --skipLibCheck --esModuleInterop --moduleResolution bundler --module esnext --target es2022 "
        + str(source.relative_to(workspace))
    )
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
    ("original", "replacement"),
    (
        ("--noEmit", "--outDir build"),
        ("--noEmit", "--noEmit false"),
        ("--noEmit", "--noEmit @compiler.args"),
        ("@cloudflare/workers-types", '"$(touch marker)"'),
        ("@cloudflare/workers-types", "../../outside"),
        ("--skipLibCheck", "--generateTrace traces"),
        ("--skipLibCheck", "--watch"),
        ("--skipLibCheck", "--project=../outside/tsconfig.json"),
        ("src/index.ts", "src/index.ts > package.json"),
        ("src/index.ts", "src/index.ts > ~/.ssh/authorized_keys"),
        ("src/index.ts", "src/index.ts>package.json"),
        ("src/index.ts", "src/index.ts 2>package.json"),
        ("npx tsc", 'NODE_OPTIONS="--require=payload" npx tsc'),
        ("src/index.ts", "../outside.ts"),
        ('grep -v "npm warn"', "grep -f patterns.txt"),
        ('grep -v "npm warn"', "grep -v --file=patterns.txt"),
        ('grep -v "npm warn"', 'grep -v "$(touch marker)"'),
        ('grep -v "npm warn" | head -8', 'grep -v "npm warn"'),
        ("head -8", "head -10000"),
        ('echo "TSC_DONE"', "touch marker"),
    ),
)
def test_routine_typescript_pipeline_rejects_effect_widening(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    original: str,
    replacement: str,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)
    workspace = Path(command.split(" && ", 1)[0].removeprefix("cd "))
    source = workspace / "src" / "index.ts"
    source.parent.mkdir()
    _ = source.write_text("export const value = 1;\n", encoding="utf-8")
    command = (
        f"cd {workspace} && npx tsc --noEmit --types @cloudflare/workers-types "
        "--lib es2022 --target es2022 --module esnext --moduleResolution bundler "
        '--skipLibCheck src/index.ts 2>&1 | grep -v "npm warn" | head -8; echo "TSC_DONE"'
    )

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command.replace(original, replacement)},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize("shadowed_command", ("grep", "head"))
def test_routine_typescript_pipeline_requires_trusted_observers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    shadowed_command: str,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)
    workspace = Path(command.split(" && ", 1)[0].removeprefix("cd "))
    source = workspace / "src" / "index.ts"
    source.parent.mkdir()
    _ = source.write_text("export const value = 1;\n", encoding="utf-8")
    command = f'cd {workspace} && npx tsc --noEmit src/index.ts 2>&1 | grep -v "npm warn" | head -8; echo "TSC_DONE"'

    def selectively_trusted(candidate: str, *, cwd: Path, home_dir: Path) -> bool:
        del cwd, home_dir
        return candidate != shadowed_command

    monkeypatch.setattr(direct_vitest, "_trusted_path_command", selectively_trusted)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )


def test_routine_typescript_pipeline_rejects_bare_symlink_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)
    workspace = Path(command.split(" && ", 1)[0].removeprefix("cd "))
    outside = tmp_path / "outside.js"
    _ = outside.write_text("export const secret = 1;\n", encoding="utf-8")
    _ = (workspace / "linked.js").symlink_to(outside)
    command = f'cd {workspace} && npx tsc --noEmit linked.js 2>&1 | grep -v "npm warn" | head -8; echo "TSC_DONE"'

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize(
    ("original", "replacement"),
    (
        ("npx tsc --noEmit", "npx tsc --outDir build"),
        ("npx tsc --noEmit", "npx --package typescript tsc --noEmit"),
        ("2>&1", "> diagnostics.txt 2>&1"),
        ('grep -E "harnesses/page|enterprises/page"', 'grep -E ".*"'),
        (
            'grep -E "harnesses/page|enterprises/page"',
            'grep -E "harnesses/.|enterprises/page"',
        ),
        ('grep -E "harnesses/page|enterprises/page"', "grep harnesses/page"),
        ('echo "NO_ERRORS_IN_TOUCHED_FILES"', "touch marker"),
    ),
)
def test_typescript_diagnostic_filter_rejects_widened_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    original: str,
    replacement: str,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command.replace(original, replacement)},
        cwd=caller,
        home_dir=home,
    )


def test_typescript_diagnostic_filter_requires_bound_local_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)
    workspace = Path(command.split(" && ", 1)[0].removeprefix("cd "))
    (workspace / "node_modules" / ".bin" / "tsc").unlink()

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize(
    "key",
    ("NODE_OPTIONS", "NODE_PATH", "npm_config_node_options", "NPM_CONFIG_SCRIPT_SHELL"),
)
def test_typescript_diagnostic_filter_rejects_node_code_loading_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key: str,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)
    monkeypatch.setenv(key, "attacker-module")

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize(
    "key",
    ("BASH_ENV", "BASH_FUNC_injected%%", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"),
)
def test_typescript_diagnostic_filter_rejects_shell_code_loading_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key: str,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)
    monkeypatch.setenv(key, str(tmp_path / "payload"))

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize("location", ("workspace", "home"))
def test_typescript_diagnostic_filter_rejects_npm_configuration_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)
    workspace = Path(command.split(" && ", 1)[0].removeprefix("cd "))
    config_root = workspace if location == "workspace" else home
    _ = (config_root / ".npmrc").write_text("node-options=--require=payload.js\n", encoding="utf-8")

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize(
    "setting",
    (
        "call=payload.js",
        "foreground-scripts=true",
        "global=true",
        "ignore-scripts=false",
        "include-workspace-root=true",
        "location=global",
        "package=attacker-package",
        "prefix=/unverified",
        "scripts-prepend-node-path=true",
        "workspace=unverified",
        "workspaces=true",
    ),
)
def test_typescript_diagnostic_filter_rejects_npm_exec_controls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    setting: str,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)
    workspace = Path(command.split(" && ", 1)[0].removeprefix("cd "))
    _ = (workspace / ".npmrc").write_text(f"{setting}\n", encoding="utf-8")

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize(
    "content",
    (
        "registry=https://registry.npmjs.org/\n",
        "@example:registry=https://registry.example/\n",
        "//registry.example/:_authToken=${TOKEN}\n",
        "fund=false\n",
    ),
)
def test_typescript_diagnostic_filter_accepts_benign_npm_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: str,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)
    workspace = Path(command.split(" && ", 1)[0].removeprefix("cd "))
    _ = (workspace / ".npmrc").write_text(content, encoding="utf-8")

    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )


def test_typescript_diagnostic_filter_requires_trusted_node_interpreter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        direct_vitest,
        "_trusted_path_command",
        lambda candidate, *, cwd, home_dir: bool(cwd and home_dir) and candidate != "node",
    )

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )
