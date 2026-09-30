"""Inspection uses the running daemon and never initializes local authority."""

from argparse import Namespace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_local as dispatch
from codex_plugin_scanner.guard.cli import extension_controls_commands as controls
from codex_plugin_scanner.guard.daemon.client import GuardDaemonRequestError


@pytest.mark.parametrize("mode", ["test", "explain"])
def test_inspection_uses_daemon_without_initializing_store(monkeypatch, tmp_path, mode):
    emitted = []
    requests = []

    class Client:
        def inspect_command(self, payload):
            requests.append(payload)
            return {"status": "matched", "minimum_action": "review"}

    def client(guard_home):
        assert guard_home == tmp_path
        return Client()

    def forbidden_store(*args, **kwargs):
        pytest.fail("inspection must not initialize a store")

    monkeypatch.setattr(controls, "_client", client)
    monkeypatch.setattr(controls, "GuardStore", forbidden_store)
    monkeypatch.setattr(dispatch, "GuardStore", forbidden_store)
    monkeypatch.setattr(dispatch, "_emit", lambda *args: emitted.append(args), raising=False)
    args = Namespace(command_command=mode, command_text="  git status  ", guard_home=str(tmp_path), json=True)

    assert dispatch._run_guard_command_inspection_command(args) == 0
    assert requests == [{"command": "git status", "cwd": str(Path.cwd()), "home_dir": str(Path.home())}]
    assert emitted[0][1]["mode"] == mode


@pytest.mark.parametrize("transport_failure", [False, True])
def test_unavailable_inspection_has_nonzero_exit(monkeypatch, tmp_path, transport_failure):
    emitted = []

    class Client:
        def inspect_command(self, payload):
            if transport_failure:
                raise GuardDaemonRequestError("not running")
            return {"status": "native_unavailable", "minimum_action": "review"}

    monkeypatch.setattr(controls, "_client", lambda _: Client())
    monkeypatch.setattr(dispatch, "_emit", lambda *args: emitted.append(args), raising=False)
    args = Namespace(command_command="test", command_text="git status", guard_home=str(tmp_path), json=True)

    assert dispatch._run_guard_command_inspection_command(args) == 2
    assert emitted[0][1]["status"] == "native_unavailable"
    assert emitted[0][1]["minimum_action"] == "review"
    if transport_failure:
        assert emitted[0][1]["classification"]["explicitly_benign"] is False
