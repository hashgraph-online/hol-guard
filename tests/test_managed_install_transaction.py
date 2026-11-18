from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import native_managed_install
from codex_plugin_scanner.guard.cli.install_commands import apply_managed_install
from codex_plugin_scanner.guard.harness.base import HarnessContext

PROBE = r"""
import sys, time
from pathlib import Path
from codex_plugin_scanner.guard.native_owned import codex_install_transaction
home = Path(sys.argv[1])
try:
    with codex_install_transaction(home, home / "managed", actor="competing-installer",
                                   deadline=time.monotonic() + 0.2):
        print("entered")
except TimeoutError:
    print("excluded")
"""


def test_python_held_adapters_run_under_the_owner_the_native_install_reuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex/config.toml").write_text("[features]\nhooks = true\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    context = HarnessContext(home_dir=home, guard_home=home / ".hol-guard", workspace_dir=None)
    observations = []

    def native_install(op, _context, **fields):
        assert op == "managed_install"
        # Codex's own state lives in this process, so its adapter ran first under this process's owner and
        # the runtime is told which owner to journal under, with the manifest the adapter produced.
        assert isinstance(fields["owner"], str)
        [target] = fields["targets"]
        assert target["harness"] == "codex"
        assert isinstance(json.loads(target["manifest"]), dict)
        result = subprocess.run(
            [sys.executable, "-c", PROBE, str(context.guard_home)],
            env={**os.environ, "HOME": str(home), "USERPROFILE": str(home)},
            capture_output=True,
            timeout=5,
        )
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        observations.append(result.stdout.strip())
        return {"ok": True, "rows": [], "guidance": None}

    class StoreProbe:
        guard_home = context.guard_home
        path = context.guard_home / "guard.db"
        guard_source = "default"

    monkeypatch.setattr(native_managed_install, "ask", native_install)
    apply_managed_install("install", "codex", False, context, StoreProbe(), None, "2026-09-30T00:00:00Z")
    assert observations == [b"excluded"]
