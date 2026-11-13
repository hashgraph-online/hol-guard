"""The OpenCode plugin forwards the agent's command description to Guard.

OpenCode's own ``bash`` tool carries the model's one-line ``description`` of a
command. The plugin sends it so the review card can quote the agent, and only
for ``bash``: Guard binds a ``bash`` approval to the command text alone, while
another intercepted tool's whole input binds its approval, so a reworded
description there would ask for approval again.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from tests.opencode_test_support import pretool_plugin_source


def _bun_executable() -> str | None:
    path_without_guard_shims = os.pathsep.join(
        entry for entry in os.environ.get("PATH", "").split(os.pathsep) if "package-shims" not in entry
    )
    unwrapped = shutil.which("bun", path=path_without_guard_shims)
    if unwrapped is not None:
        return unwrapped
    user_install = Path.home() / ".bun" / "bin" / "bun"
    if user_install.is_file():
        return str(user_install)
    return shutil.which("bun")


RUNNER = """\
import { hookToolInput } from './guard-description-plugin';
const cases = [
  ['bash', { command: 'ls', description: 'List files' }, { command: 'ls', workdir: '/w', description: 'List files' }],
  ['bash', { command: 'ls' }, { command: 'ls', workdir: '/w' }],
  ['bash', { command: 'ls', description: 42 }, { command: 'ls', workdir: '/w' }],
  ['bash', undefined, { command: 'ls', workdir: '/w' }],
  ['ctx_shell', { command: 'ls', description: 'List files' }, { command: 'ls', workdir: '/w' }],
  ['oc_bash', { command: 'ls', description: 'List files' }, { command: 'ls', workdir: '/w' }],
] as const;
for (const [tool, args, expected] of cases) {
  const got = hookToolInput(tool, args as Record<string, unknown> | undefined, 'ls', '/w');
  if (JSON.stringify(got) !== JSON.stringify(expected)) {
    throw new Error(`${tool} ${JSON.stringify(args)} => ${JSON.stringify(got)}`);
  }
}
console.log('ok');
"""


def test_only_the_bash_tool_forwards_a_string_description(tmp_path: Path) -> None:
    bun = _bun_executable()
    if bun is None:
        pytest.skip("bun not installed")
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    (tmp_path / "guard-description-plugin.ts").write_text(pretool_plugin_source(context), encoding="utf-8")
    runner = tmp_path / "guard-description-runner.ts"
    runner.write_text(RUNNER, encoding="utf-8")
    completed = subprocess.run(
        [bun, str(runner)],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "ok"
