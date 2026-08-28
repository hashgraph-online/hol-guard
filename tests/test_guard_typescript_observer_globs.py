"""TypeScript observer glob characters must not be treated as a static grep."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.secret_file_requests import is_explicitly_benign_tool_action_request
from tests.test_guard_direct_typescript_diagnostic_filter import _fixture


def test_routine_typescript_error_grep_pipeline_stays_benign(
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
    observer_command = command.replace(
        '| grep -v "npm warn" | head -8',
        "| grep error | head -200",
    )

    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": observer_command},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize(
    "replacement",
    (
        "grep -a ^*",
        "grep error?",
        "grep [error]",
    ),
)
def test_routine_typescript_pipeline_rejects_observer_globs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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
        {"command": command.replace('grep -v "npm warn"', replacement)},
        cwd=caller,
        home_dir=home,
    )
