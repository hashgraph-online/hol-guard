from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.store import GuardStore


def test_recognize_reads_help_and_lists_commands(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    script = home / "ship.py"
    script.write_text(
        """
print(\"\"\"Commands:
  deploy  Ship the build
  status  Show status
\"\"\")
""",
        encoding="utf-8",
    )
    store = GuardStore(home)
    service = LocalCliApiService(store=store)
    result = service.recognize({"command": f"python3 {script} deploy"})
    item = result["item"]
    assert isinstance(item, dict)
    ids = [entry["command_id"] for entry in item["commands"]]
    assert "root" in ids
    assert "deploy" in ids
    assert "status" in ids
    assert "other" in ids
    assert result["help_status"] == "ok"
    assert "commands" in str(result["summary"]).lower()
