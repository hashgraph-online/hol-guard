"""Strict original/candidate WTEXT parity and diagnostic forwarding controls."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ci.native_runtime import windows_wtext_acceptance_probe as probe

_ROOT = Path(__file__).resolve().parents[1]
_CHILD = _ROOT / "ci/native_runtime/windows_wtext_acceptance_probe.py"
_CONTROL_SECONDS = 5
_WINDOWS = pytest.mark.skipif(os.name != "nt", reason="actual Windows CRT acceptance boundary")
_CASES = [
    ("ascii-no-bom", "wtext", "unchanged"),
    ("utf8-bom", "wtext", "unchanged"),
    ("utf16le-bom", "wtext", "unchanged"),
    ("empty", "wtext", "unchanged"),
    ("utf8-bom-only", "wtext", "unchanged"),
    ("utf16le-bom-only", "wtext", "unchanged"),
    ("utf8-bom", "text", "wtext"),
    ("utf8-bom", "wtext", "text"),
]
_CASE_IDS = [
    "wtext-ascii",
    "wtext-utf8-bom",
    "wtext-utf16le-bom",
    "wtext-empty",
    "wtext-utf8-bom-only",
    "wtext-utf16le-bom-only",
    "audit-enters-wtext",
    "audit-leaves-wtext",
]
_SAFE_STRINGS = {
    "windows-wtext-acceptance-observation.v1",
    "single original or candidate reader boundary; not installed qualification",
    "bounded",
    "text",
    "bytes",
    "open",
    "r",
    "PermissionError",
    "FileNotFoundError",
    "UnicodeDecodeError",
    "OSError",
    "ValueError",
    "RuntimeError",
    "other",
    "utf-8",
    "utf-16-le",
    *probe.PAYLOADS,
}
_SAFE_KEYS = {
    "schema",
    "scope",
    "candidate",
    "route",
    "payload",
    "input_bytes",
    "input_sha256",
    "read_bound_bytes",
    "reader_import_binding_verified",
    "initial_mode",
    "mode_before_call",
    "mode_after_call",
    "audit_mode",
    "audit_refuse",
    "events",
    "operation_calls",
    "result",
    "error",
    "refusal_same_object",
    "default_mode_restored",
    "cleanup_error",
    "observation_complete",
    "qualification",
    "setup_or_observer_error",
    "event",
    "mode",
    "flags",
    "crt_before",
    "crt_after",
    "kind",
    "bytes",
    "sha256",
    "errno",
    "winerror",
    "encoding",
    "start",
    "end",
}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate report key")
        result[key] = value
    return result


def _safe(value, depth=0):
    if depth > 5:
        return False
    if value is None or type(value) is bool:
        return True
    if type(value) is int:
        return -(1 << 63) <= value < (1 << 64)
    if isinstance(value, str):
        return value in _SAFE_STRINGS or (len(value) == 64 and all(c in "0123456789abcdef" for c in value))
    if isinstance(value, list):
        return len(value) <= 2 and all(_safe(item, depth + 1) for item in value)
    return (
        isinstance(value, dict) and set(value) <= _SAFE_KEYS and all(_safe(item, depth + 1) for item in value.values())
    )


def _child(target, payload, initial, audit_mode, route, candidate, refuse, record_property) -> dict[str, Any]:
    command = [
        sys.executable,
        "-I",
        str(_CHILD),
        "--source-root",
        str(_ROOT),
        "--target",
        str(target),
        "--payload",
        payload,
        "--route",
        route,
        "--initial-mode",
        initial,
        "--audit-mode",
        audit_mode,
    ]
    if candidate:
        command.append("--candidate")
    if refuse:
        command.append("--refuse")
    label = "candidate" if candidate else "original"
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
    except BaseException as error:
        record_property(
            f"wtext_child_{label}",
            json.dumps(
                {
                    "spawned": False,
                    "retired": True,
                    "error": probe._error(error),
                    "qualification": False,
                },
                sort_keys=True,
            ),
        )
        raise
    stdout = stderr = b""
    failure = cleanup_error = None
    killed = False
    partial = None
    try:
        stdout, stderr = process.communicate(timeout=_CONTROL_SECONDS)
    except BaseException as error:
        failure = error
        if isinstance(error, subprocess.TimeoutExpired):
            stdout, stderr = error.output or b"", error.stderr or b""
            partial = {
                "stdout_bytes": len(stdout),
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stderr_bytes": len(stderr),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            }
    finally:
        if process.poll() is None:
            try:
                killed = True
                process.kill()
                stdout, stderr = process.communicate(timeout=_CONTROL_SECONDS)
            except BaseException as error:
                cleanup_error = probe._error(error)
                if failure is None:
                    failure = error
        report = None
        parse_error = False
        try:
            if len(stdout) > 16384:
                raise ValueError("report limit")
            report = json.loads(stdout, object_pairs_hook=_unique)
            if not isinstance(report, dict) or not _safe(report):
                raise ValueError("report shape")
        except (ValueError, UnicodeDecodeError):
            parse_error = True
        record_property(
            f"wtext_child_{label}",
            json.dumps(
                {
                    "return_code": process.returncode,
                    "retired": process.poll() is not None,
                    "kill_requested": killed,
                    "timed_out": isinstance(failure, subprocess.TimeoutExpired),
                    "cleanup_error": cleanup_error,
                    "stdout_bytes": len(stdout),
                    "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                    "stderr_bytes": len(stderr),
                    "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                    "stderr_content_retained": False,
                    "stdout_content": stdout.decode("utf-8") if not parse_error else None,
                    "report": report if not parse_error else None,
                    "partial": partial,
                },
                sort_keys=True,
            ),
        )
    if failure is not None:
        raise failure
    assert not parse_error and isinstance(report, dict)
    assert process.returncode == 0 and not stderr and process.poll() is not None
    assert report["observation_complete"] is True
    assert report["operation_calls"] == 1
    assert report["default_mode_restored"] is True and report["cleanup_error"] is None
    assert report["reader_import_binding_verified"] is True
    assert report["qualification"] is False
    assert len(report["events"]) == 1
    return report


def _pair(tmp_path, record_property, payload, initial, audit_mode, route, refuse):
    target = tmp_path / "synthetic-authority"
    target.write_bytes(probe.PAYLOADS[payload])
    original = _child(target, payload, initial, audit_mode, route, False, refuse, record_property)
    candidate = _child(target, payload, initial, audit_mode, route, True, refuse, record_property)
    original_values = {key: value for key, value in original.items() if key != "candidate"}
    candidate_values = {key: value for key, value in candidate.items() if key != "candidate"}
    parity = original_values == candidate_values
    record_property("wtext_original_candidate_parity", parity)
    record_property("wtext_probe_is_qualification", False)
    assert original["candidate"] is False and candidate["candidate"] is True
    assert original["refusal_same_object"] is candidate["refusal_same_object"] is refuse
    assert target.read_bytes() == probe.PAYLOADS[payload]
    # This must remain a strict failure for the frozen reader's supported-mode
    # narrowing. Collecting the diagnostic is not acceptance of that behavior.
    assert parity


@_WINDOWS
@pytest.mark.parametrize("route", ["bounded", "text"], ids=["bounded", "textio"])
@pytest.mark.parametrize("payload,initial,audit_mode", _CASES, ids=_CASE_IDS)
def test_supported_wtext_default_preserves_original_read(
    tmp_path, record_property, payload, initial, audit_mode, route
):
    _pair(tmp_path, record_property, payload, initial, audit_mode, route, False)


@_WINDOWS
@pytest.mark.parametrize("route", ["bounded", "text"], ids=["bounded", "textio"])
def test_original_audit_can_enter_wtext_and_refuse_before_open(tmp_path, record_property, route):
    _pair(tmp_path, record_property, "utf8-bom", "text", "wtext", route, True)


@pytest.mark.parametrize("candidate", [False, True], ids=["original", "candidate"])
def test_bounded_forwarding_retains_return_and_exact_failure(monkeypatch, candidate):
    calls = []
    target = Path("synthetic-authority")
    returned = b"synthetic"
    failure = OSError(13, "synthetic read error")

    def opened(path, flags):
        calls.append(("open", path is target, flags))
        return 17

    def read(descriptor, maximum):
        calls.append(("read", descriptor, maximum))
        if len(calls) > 4:
            raise failure
        return returned

    fake_os = SimpleNamespace(O_RDONLY=0, O_CLOEXEC=8, O_NOFOLLOW=16, open=opened, read=read)
    fake_os.close = lambda descriptor: calls.append(("close", descriptor))
    monkeypatch.setattr(probe, "os", fake_os)
    reader = SimpleNamespace(open_replaceable_read_descriptor=opened)
    assert probe._read(target, candidate=candidate, route="bounded", reader=reader) is returned
    with pytest.raises(OSError) as observed:
        probe._read(target, candidate=candidate, route="bounded", reader=reader)
    assert observed.value is failure
    assert calls == [("open", True, 24), ("read", 17, 4096), ("close", 17)] * 2


def test_cleanup_fault_retains_already_observed_result(tmp_path, monkeypatch):
    target = tmp_path / "synthetic-authority"
    target.write_bytes(probe.PAYLOADS["ascii-no-bom"])
    source = tmp_path / "source"
    source.mkdir()
    state: dict[str, Any] = {"mode": 0x4000, "after_read": False, "audit": None}
    cleanup_failure = RuntimeError("synthetic mode-query failure")

    def set_mode(value):
        state["mode"] = value
        return 0

    api = SimpleNamespace(_set_fmode=set_mode)

    def mode(_api):
        if state["after_read"]:
            raise cleanup_failure
        return state["mode"]

    reader = SimpleNamespace(
        __file__=str(source / "src/codex_plugin_scanner/guard/windows_replaceable_file.py"),
        _crt_api=lambda: api,
    )
    fake_sys = SimpleNamespace(
        flags=SimpleNamespace(isolated=1),
        implementation=SimpleNamespace(name="cpython"),
        path=[],
        addaudithook=lambda hook: state.update(audit=hook),
    )

    def read(path, **_kwargs):
        audit = state["audit"]
        assert callable(audit)
        audit("open", (str(path), None, 0x80))
        state["after_read"] = True
        return b"retained-result"

    monkeypatch.setattr(probe, "sys", fake_sys)
    monkeypatch.setattr(probe, "os", SimpleNamespace(name="nt", O_TEXT=0x4000, O_BINARY=0x8000))
    monkeypatch.setattr(probe, "importlib", SimpleNamespace(import_module=lambda _name: reader))
    monkeypatch.setattr(probe, "_mode", mode)
    monkeypatch.setattr(probe, "_read", read)
    args = argparse.Namespace(
        source_root=source,
        target=target,
        payload="ascii-no-bom",
        initial_mode="wtext",
        audit_mode="unchanged",
        refuse=False,
        candidate=True,
        route="bounded",
    )
    result = probe.observe(args)
    returned = result["result"]
    cleanup = result["cleanup_error"]
    assert isinstance(returned, dict) and isinstance(cleanup, dict)
    assert returned["sha256"] == hashlib.sha256(b"retained-result").hexdigest()
    assert result["error"] is None
    assert cleanup["kind"] == "RuntimeError"
    assert result["observation_complete"] is False
    assert result["default_mode_restored"] is False
    assert state["mode"] == 0x4000


def test_child_spawn_failure_retains_original_exception_and_bounded_evidence(monkeypatch):
    failure = PermissionError(13, "synthetic private path must not be retained")
    records = []

    def spawn(*_arguments, **_keywords):
        raise failure

    monkeypatch.setattr(subprocess, "Popen", spawn)
    with pytest.raises(PermissionError) as observed:
        _child(
            Path("synthetic"),
            "empty",
            "wtext",
            "unchanged",
            "bounded",
            False,
            False,
            lambda name, value: records.append((name, json.loads(value))),
        )
    assert observed.value is failure
    assert records == [
        (
            "wtext_child_original",
            {
                "spawned": False,
                "retired": True,
                "error": {"kind": "PermissionError", "errno": 13, "winerror": None},
                "qualification": False,
            },
        )
    ]
