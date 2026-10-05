from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.install_commands import _apply_managed_install_owned, apply_managed_install

PROBE = r"""
import sys, time
from pathlib import Path
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
home = Path(sys.argv[1])
try:
    with codex_install_transaction(home, home / "managed", actor="competing-installer",
                                   deadline=time.monotonic() + 0.2):
        print("entered")
except TimeoutError:
    print("excluded")
"""


@pytest.mark.parametrize("whole_operation", [False, True])
def test_installer_ownership_extends_through_store_proof_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, whole_operation: bool
):
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex/config.toml").write_text("[features]\nhooks = true\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    context = HarnessContext(home_dir=home, guard_home=home / ".hol-guard", workspace_dir=None)
    observations = []

    class StoreProbe:
        def set_managed_install(self, harness, active, workspace, manifest, now):
            assert harness == "codex" and active
            assert manifest["protection_artifact_proof"]["artifacts"]
            result = subprocess.run(
                [sys.executable, "-c", PROBE, str(context.guard_home)],
                env={**os.environ, "HOME": str(home), "USERPROFILE": str(home)},
                capture_output=True,
                timeout=5,
            )
            assert result.returncode == 0, result.stderr.decode(errors="replace")
            observations.append(result.stdout.strip())

        def get_managed_install(self, _harness):
            return None

    # Calling the old body without the new outer owner reproduces the window:
    # the adapter is committed, but a competitor can enter during store.set.
    install = apply_managed_install if whole_operation else _apply_managed_install_owned
    install("install", "codex", False, context, StoreProbe(), None, "2026-09-30T00:00:00Z")
    assert observations == [b"excluded" if whole_operation else b"entered"]
