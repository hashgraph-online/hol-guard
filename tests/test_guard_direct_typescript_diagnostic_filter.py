"""Regressions for verified TypeScript diagnostic filtering."""

from __future__ import annotations

import json
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
