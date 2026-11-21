from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import native_managed_install
from codex_plugin_scanner.guard.cli.install_commands import apply_managed_install
from codex_plugin_scanner.guard.harness_context import HarnessContext


def test_install_hands_the_native_runtime_every_target_and_holds_no_owner_of_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex/config.toml").write_text("[features]\nhooks = true\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    context = HarnessContext(home_dir=home, guard_home=home / ".hol-guard", workspace_dir=None)
    requests = []

    def native_install(op, _context, **fields):
        assert op == "managed_install"
        # Codex installs inside the runtime too: this process names the target and the facts only it knows,
        # and the runtime takes the installation locks itself.
        assert "owner" not in fields
        assert fields["actor"] == "managed.install"
        assert fields["targets"] == [{"harness": "codex"}]
        assert isinstance(fields["facts"]["codex"], dict)
        requests.append(fields)
        return {"ok": True, "rows": [], "guidance": None}

    class StoreProbe:
        guard_home = context.guard_home
        path = context.guard_home / "guard.db"
        guard_source = "default"

    monkeypatch.setattr(native_managed_install, "ask", native_install)
    apply_managed_install("install", "codex", False, context, StoreProbe(), None, "2026-09-30T00:00:00Z")
    assert len(requests) == 1
