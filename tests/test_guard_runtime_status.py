"""``hol-guard guard runtime status`` and ``guard doctor --native``.

Both surfaces are read only: they report what the native runtime looks like
from here without starting it, repairing it, or producing a verdict of their
own. The counters they print belong to the printing process, and the report
says so rather than passing them off as the hook's.
"""

from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.cli import commands_dispatch_admin, doctor_native_runtime
from codex_plugin_scanner.guard.cli.runtime_posture_command import render_runtime_status
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity, NativeRuntimeStatus


def _guard_args(tmp_path: Path) -> list[str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return ["--home", str(home), "--guard-home", str(home / "guard"), "--workspace", str(tmp_path)]


def _pin_runtime(monkeypatch: pytest.MonkeyPatch, *, available: bool, reason: str) -> None:
    """Pin what the installed files say, which is all these surfaces may read.

    ``runtime status`` never runs the binary, so its answer comes from the
    passive identity check rather than from ``native_runtime_status``; that one
    is pinned too because the native guard config still consults it.
    """

    identity = NativeRuntimeIdentity(path=Path("hol-guard-runtime"), size=1, mtime_ns=1, sha256="a" * 64)
    status = NativeRuntimeStatus(
        mode="auto", available=available, compatible=available, reason=reason, identity=identity
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: "a" * 64 if available else None)


def test_status_json_reports_availability_and_resident_presence(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _pin_runtime(monkeypatch, available=True, reason="native_ready")

    code = main(["guard", "runtime", "status", "--json", *_guard_args(tmp_path)])

    payload = json.loads(capsys.readouterr().out)
    section = payload["native_runtime"]
    assert code == 0
    assert section["availability"]["reason_code"] == "native_status_probe_skipped"
    assert section["availability"]["evaluation_verified"] is False
    assert section["resident"]["live"] is False
    assert isinstance(section["daemon_http"], dict)
    assert "generated_at" in payload


def test_status_exits_nonzero_when_the_probe_says_unavailable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _pin_runtime(monkeypatch, available=False, reason="native_binary_missing")

    code = main(["guard", "runtime", "status", "--json", *_guard_args(tmp_path)])

    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["native_runtime"]["availability"]["available"] is False


def test_status_sees_a_resident_this_process_never_started(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _pin_runtime(monkeypatch, available=True, reason="native_ready")
    args = _guard_args(tmp_path)
    guard_home = Path(args[args.index("--guard-home") + 1])
    resident = guard_home / "native-runtime" / "resident-v3-aaaaaaaaaaaaaaaa"
    resident.mkdir(parents=True)
    state = {"runtime_sha256": "a" * 64, "process_id": os.getpid()}
    (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")

    code = main(["guard", "runtime", "status", "--json", *args])

    resident_payload = json.loads(capsys.readouterr().out)["native_runtime"]["resident"]
    assert code == 0
    assert resident_payload["live"] is True
    assert resident_payload["generations"] == 1
    # A live resident is read from its state files alone. Asking it how it is
    # doing means reading the runtime's feature list, which runs the binary;
    # this command says it starts nothing, so it does not ask.
    assert "serving" not in resident_payload


def test_status_text_scopes_the_counters_to_this_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _pin_runtime(monkeypatch, available=True, reason="native_ready")

    code = main(["guard", "runtime", "status", *_guard_args(tmp_path)])

    out = capsys.readouterr().out
    assert code == 0
    assert "Native runtime status (read only)" in out
    assert "available: yes" in out
    assert "Resident on this account: not running" in out
    assert "The hook and the daemon keep their own." in out


def test_status_output_does_not_disclose_the_binary_path_or_hash(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    identity = NativeRuntimeIdentity(path=Path("/private/user/native-secret"), size=1, mtime_ns=1, sha256="d" * 64)
    status = NativeRuntimeStatus(mode="auto", available=True, compatible=True, reason="native_ready", identity=identity)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: "d" * 64)

    main(["guard", "runtime", "status", "--json", *_guard_args(tmp_path)])

    out = capsys.readouterr().out
    assert "native-secret" not in out
    assert "d" * 64 not in out


def test_render_names_an_unknown_resident_without_inventing_one() -> None:
    section = {
        "availability": {"mode": "unknown", "available": None, "compatible": None, "reason_code": "probe_skipped"},
        "resident": {"live": None, "owner_lock_held": None, "generations": 0},
        "daemon_http": {},
    }

    rendered = render_runtime_status(section)

    assert "available: unknown" in rendered
    assert "Resident on this account: unknown" in rendered
    assert "no counters recorded" in rendered


def test_render_reports_a_held_owner_lock() -> None:
    section = {
        "availability": {"mode": "auto", "available": True, "compatible": True, "reason_code": "native_ready"},
        "resident": {"live": True, "owner_lock_held": True, "generations": 2},
        "daemon_http": {"accepted": 3, "rejected": 0},
    }

    rendered = render_runtime_status(section)

    assert "Resident on this account: running (owner lock held, 2 recorded generations)" in rendered
    assert "accepted 3, rejected 0" in rendered


def _pin_availability(monkeypatch: pytest.MonkeyPatch, reason: str) -> None:
    """Pin the probe doctor reads, not the runtime the config loader needs.

    ``native_runtime_status`` also answers for the native guard config, so
    replacing it would stop ``doctor`` booting at all. These two tests only care
    which report the ``--native`` branch produces.
    """

    monkeypatch.setattr(
        doctor_native_runtime,
        "doctor_native_availability",
        lambda _guard_home=None: {
            "mode": "auto",
            "available": True,
            "compatible": True,
            "reason_code": reason,
            "evaluation_verified": False,
        },
    )
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: None)


def _doctor_native(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, reason: str, as_json: bool) -> tuple[int, str]:
    """Run doctor's ``--native`` branch with the probe pinned.

    The branch is called directly rather than through ``main``: doctor loads the
    native guard config before it dispatches, so a machine without the native
    runtime never reaches this code. ``runtime status`` is the surface that
    still answers there, and its own tests cover that path.
    """

    monkeypatch.setattr(
        doctor_native_runtime,
        "doctor_native_availability",
        lambda _guard_home=None: {
            "mode": "auto",
            "available": True,
            "compatible": True,
            "reason_code": reason,
            "evaluation_verified": False,
        },
    )
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: None)
    args = argparse.Namespace(native=True, json=as_json, harness=None, harnesses=False, notifications=False)
    stream = io.StringIO()
    code = commands_dispatch_admin._run_guard_doctor_command(
        args,
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        context=object(),
        store=object(),
        config=object(),
        output_stream=stream,
    )
    return code, stream.getvalue()


def test_doctor_native_reports_the_section_without_the_rest_of_the_scan(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    code, out = _doctor_native(monkeypatch, tmp_path, reason="native_ready", as_json=True)

    payload = json.loads(out)
    assert code == 0
    assert payload["native_runtime"]["availability"]["reason_code"] == "native_ready"
    assert "approval_gate" not in payload
    assert "harnesses" not in payload
    # The caller asked for the report on its own stream, so none of it leaks to stdout.
    assert capsys.readouterr().out == ""


def test_doctor_native_text_uses_the_runtime_report_not_the_harness_panel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, out = _doctor_native(monkeypatch, tmp_path, reason="native_ready", as_json=False)

    assert code == 0
    assert "Native runtime status (read only)" in out
    assert "Guard doctor" not in out


def test_status_neither_runs_the_runtime_nor_restores_its_execute_bit(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """``runtime status`` documents itself as read only, so it must hold that line.

    The probe it used to take runs ``capabilities --json`` and, on the way,
    chmods the bundled binary back to executable. Both are side effects a
    support command must not have.
    """

    def _must_not_chmod(path: Path) -> None:
        raise AssertionError("runtime status must not change the native binary's permissions")

    monkeypatch.setattr(native_runtime, "_restore_bundled_runtime_execute_bit", _must_not_chmod)
    monkeypatch.setattr(native_runtime, "_capabilities_for_identity", _must_not_chmod)
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: "a" * 64)

    code = main(["guard", "runtime", "status", "--json", *_guard_args(tmp_path)])

    availability = json.loads(capsys.readouterr().out)["native_runtime"]["availability"]
    assert code == 0
    assert availability["reason_code"] == "native_status_probe_skipped"
    # Installation is still answered; only compatibility needs the binary to run.
    assert availability["available"] is True
    assert availability["compatible"] is None


def test_status_text_says_why_compatibility_is_not_reported(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: "a" * 64)

    code = main(["guard", "runtime", "status", *_guard_args(tmp_path)])

    out = capsys.readouterr().out
    assert code == 0
    assert "Compatibility is not reported" in out


def test_doctor_rejects_native_together_with_repair(tmp_path: Path) -> None:
    """``--repair`` runs the lifecycle gate, which can revive a resident.

    ``--native`` promises a read-only report, so the pair is refused before
    anything runs rather than silently doing one of the two.
    """

    guard_home = tmp_path / "home" / "guard"

    with pytest.raises(SystemExit) as caught:
        main(["guard", "doctor", "--native", "--repair", *_guard_args(tmp_path)])

    assert caught.value.code == 2
    # Nothing was started on the way to the refusal.
    assert not (guard_home / "native-runtime").exists()
