"""The dashboard's Codex repair route explains a refusal it cannot fix itself."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from ci.guard_daemon_harness import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


def _post_codex_repair(store: GuardStore) -> tuple[int, dict[str, object]]:
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/harnesses/codex/repair",
            data=json.dumps({"dry_run": False}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8"))
    finally:
        daemon.stop()


def test_daemon_repair_endpoint_explains_a_dead_codex_handler_it_cannot_remove(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The app shows the refusal the CLI prints, not a bare reason code.

    A handler left by a deleted checkout names a Guard bridge that no longer
    exists. Guard will not remove a handler it cannot prove it wrote, so the
    person has to delete it; the reply must say where it is and what to do.
    """

    home = tmp_path / "home"
    codex_home = home / ".codex"
    codex_home.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)
    dead_bridge = tmp_path / "deleted-checkout" / "src/codex_plugin_scanner/guard/adapters/codex_daemon_hook_bridge.py"
    command = f"{sys.executable} -I {dead_bridge} '{{}}'"
    config_path = codex_home / "config.toml"
    original = (
        "[features]\nhooks = true\n\n[hooks]\n"
        f'PreToolUse = [{{ matcher = "Bash", hooks = [{{ type = "command", command = {json.dumps(command)} }}] }}]\n'
    )
    config_path.write_text(original, encoding="utf-8")

    status, payload = _post_codex_repair(GuardStore(tmp_path / "guard-home"))

    assert status == 409
    assert payload["error"] == "codex_hook_owner_conflict"
    assert payload["harness"] == "codex"
    message = payload["message"]
    assert isinstance(message, str)
    assert str(dead_bridge) in message
    assert str(config_path) in message
    assert "hol-guard install codex" in message
    assert config_path.read_text(encoding="utf-8") == original


def test_daemon_repair_endpoint_keeps_unexplained_failures_generic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.cli import install_commands

    def fail(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("internal state at /private/guard-home/secret-path went missing")

    monkeypatch.setattr(install_commands, "apply_managed_install", fail)

    status, payload = _post_codex_repair(GuardStore(tmp_path / "guard-home"))

    assert status == 409
    assert payload["error"] == "harness_repair_failed"
    assert "secret-path" not in json.dumps(payload)
