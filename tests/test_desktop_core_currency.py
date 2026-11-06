"""A CLI that Desktop has replaced stops contained runs with an actionable message.

Desktop moves ``current.json`` to each new Core release and its resident follows. A
``hol-guard`` that still runs from an older release publishes policy the resident
does not accept, so a contained run used to wait out every acknowledgement window
(about 84 seconds) before failing with a message that blamed the host.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import desktop_core_currency
from codex_plugin_scanner.guard.cli import commands_dispatch_local as cli
from codex_plugin_scanner.guard.desktop_core_currency import (
    OUT_OF_SYNC_REASON,
    SupersededCore,
    superseded_desktop_core,
)
from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError

_OLD = "3.50.0a3-5a0c7c2e1d9b4f68a3c0e2f7b19d46c85e03a7f1d2b6c94e8a05f3d7b1c2e960"
_NEW = "3.50.0a5-97b143fb3d2adf30a07b97d621d5d4eb0031db45822b3869c2e87442c94e2150"


def _core(tmp_path: Path, *, current: str | None = _NEW) -> tuple[Path, Path]:
    root = tmp_path / "<appdata>" / "core"
    launchers = {}
    for release in (_OLD, _NEW):
        launcher = root / "versions" / release / "bundle" / "hol-guard"
        launcher.parent.mkdir(parents=True)
        launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        launchers[release] = launcher
    if current is not None:
        pointer = {"schema": "guard-core-install.v1", "relativePath": f"versions/{current}/bundle/hol-guard"}
        (root / "current.json").write_text(json.dumps(pointer), encoding="utf-8")
    return root, launchers[_OLD]


def test_a_release_that_current_json_no_longer_selects_is_superseded(tmp_path: Path) -> None:
    _root, old_launcher = _core(tmp_path)

    superseded = superseded_desktop_core(old_launcher)

    assert superseded == SupersededCore(running=_OLD, current=_NEW)
    message = superseded.message()
    assert "Guard versions out of sync" in message
    assert _OLD in message
    assert _NEW in message
    assert "hol-guard repair" in message


def test_the_selected_release_is_current(tmp_path: Path) -> None:
    root, _old = _core(tmp_path)

    assert superseded_desktop_core(root / "versions" / _NEW / "bundle" / "hol-guard") is None


def test_the_release_layout_without_a_bundle_directory_is_judged_too(tmp_path: Path) -> None:
    root = tmp_path / "core"
    old = root / "versions" / _OLD / "hol-guard"
    old.parent.mkdir(parents=True)
    old.write_text("", encoding="utf-8")
    (root / "current.json").write_text(json.dumps({"relativePath": f"versions/{_NEW}/hol-guard"}), encoding="utf-8")

    assert superseded_desktop_core(old) == SupersededCore(running=_OLD, current=_NEW)


@pytest.mark.parametrize(
    "pointer",
    [
        None,
        "not json",
        "[]",
        json.dumps({}),
        json.dumps({"relativePath": ""}),
        json.dumps({"relativePath": 7}),
        json.dumps({"relativePath": f"/versions/{_NEW}/bundle/hol-guard"}),
        json.dumps({"relativePath": f"versions/../{_NEW}/hol-guard"}),
        json.dumps({"relativePath": f"versions\\{_NEW}\\hol-guard"}),
        json.dumps({"relativePath": "versions"}),
        json.dumps({"relativePath": f"bundled/{_NEW}/bin/hol-guard"}),
        json.dumps({"relativePath": f"versions/{_NEW}/README"}),
        json.dumps({"relativePath": f"versions/{_NEW}/bundle/_internal/hol-guard"}),
        json.dumps({"relativePath": f"versions/{_NEW}/bin/hol-guard"}),
        json.dumps({"relativePath": f"versions/{_NEW}"}),
        json.dumps({"relativePath": f"versions/{_NEW}/"}),
    ],
)
def test_a_pointer_that_cannot_be_judged_never_blocks_a_run(tmp_path: Path, pointer: str | None) -> None:
    root, old_launcher = _core(tmp_path, current=None)
    if pointer is not None:
        (root / "current.json").write_text(pointer, encoding="utf-8")

    assert superseded_desktop_core(old_launcher) is None


def test_the_windows_launcher_name_is_judged_too(tmp_path: Path) -> None:
    root = tmp_path / "core"
    old = root / "versions" / _OLD / "bundle" / "hol-guard.exe"
    old.parent.mkdir(parents=True)
    old.write_text("", encoding="utf-8")
    pointer = {"relativePath": f"versions/{_NEW}/bundle/hol-guard.exe"}
    (root / "current.json").write_text(json.dumps(pointer), encoding="utf-8")

    assert superseded_desktop_core(old) == SupersededCore(running=_OLD, current=_NEW)


def test_a_selected_release_whose_launcher_is_absent_locally_is_still_judged(tmp_path: Path) -> None:
    root, old_launcher = _core(tmp_path, current=None)
    pointer = {"relativePath": "versions/3.99.0-not-installed/bundle/hol-guard"}
    (root / "current.json").write_text(json.dumps(pointer), encoding="utf-8")

    assert superseded_desktop_core(old_launcher) == SupersededCore(running=_OLD, current="3.99.0-not-installed")


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
def test_a_symlinked_pointer_is_not_trusted(tmp_path: Path) -> None:
    root, old_launcher = _core(tmp_path, current=None)
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text(json.dumps({"relativePath": f"versions/{_NEW}/bundle/hol-guard"}), encoding="utf-8")
    (root / "current.json").symlink_to(elsewhere)

    assert superseded_desktop_core(old_launcher) is None


def test_installs_that_desktop_does_not_replace_are_never_superseded(tmp_path: Path) -> None:
    root, _old = _core(tmp_path)
    pipx = tmp_path / ".local" / "bin" / "hol-guard"
    bundled = root / "bundled" / _OLD / "bin" / "hol-guard"
    nested = root / "versions" / _OLD / "bundle" / "_internal" / "hol-guard"

    assert superseded_desktop_core(pipx) is None
    assert superseded_desktop_core(bundled) is None
    assert superseded_desktop_core(nested) is None


def test_a_process_that_is_not_frozen_is_never_superseded() -> None:
    assert superseded_desktop_core() is None


def test_the_running_frozen_executable_is_judged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _root, old_launcher = _core(tmp_path)
    monkeypatch.setattr(desktop_core_currency.sys, "frozen", True, raising=False)
    monkeypatch.setattr(desktop_core_currency.sys, "executable", str(old_launcher))

    assert superseded_desktop_core() == SupersededCore(running=_OLD, current=_NEW)


def _stale(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        desktop_core_currency, "superseded_desktop_core", lambda *a, **k: SupersededCore(running=_OLD, current=_NEW)
    )
    monkeypatch.setattr(sink, "superseded_desktop_core", desktop_core_currency.superseded_desktop_core)


def test_a_contained_run_from_a_superseded_cli_stops_before_asking_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stale(monkeypatch)
    request = {"tool_name": "bash", "tool_input": {"command": "git -C ../app status"}}
    monkeypatch.setattr(sink, "read_contained_test_request", lambda *args, **kwargs: request)

    def never(*_args: object, **_kwargs: object) -> int:
        pytest.fail("a superseded CLI must not wait on the resident")

    monkeypatch.setattr(sink, "run_authorized_contained_test", never)
    args = argparse.Namespace(request_file="unused", request_sha256="unused", timeout_seconds=20, harness="omp")

    code = cli._run_guard_execute_contained_test_command(
        args, guard_home=tmp_path, workspace=tmp_path, context=SimpleNamespace(home_dir=tmp_path), store=object()
    )

    assert code == 126
    err = capsys.readouterr().err
    assert err.startswith(f"{OUT_OF_SYNC_REASON}: Guard versions out of sync")
    assert "hol-guard repair" in err


def test_an_unanswered_authority_ask_names_the_skew_instead_of_the_host(monkeypatch: pytest.MonkeyPatch) -> None:
    unavailable = {"reason_code": "native_pre_tool_unavailable"}

    monkeypatch.setattr(sink, "superseded_desktop_core", lambda *a, **k: None)
    plain = sink._reject(unavailable)
    assert isinstance(plain, RestrictedPytestError)
    assert plain.reason_code == "contained_run_authorization_failed"
    assert "Try it again" in str(plain)

    _stale(monkeypatch)
    skewed = sink._reject(unavailable)
    assert skewed.reason_code == OUT_OF_SYNC_REASON
    assert skewed.exit_code == 126
    assert "Guard versions out of sync" in str(skewed)
    assert "Try it again" not in str(skewed)
