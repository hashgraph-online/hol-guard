from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery import active_security, lifecycle

transport = lifecycle.transport


@pytest.fixture
def native(monkeypatch, tmp_path):
    calls = {"verify": 0, "copies": 0, "runs": 0}

    def verify_compiler(path, manifest):
        calls["verify"] += 1
        return b"runtime"

    @contextmanager
    def verified_executable(raw):
        calls["copies"] += 1
        yield Path(tmp_path / "runtime")

    def run_bounded(argv, request, timeout):
        calls["runs"] += 1
        return 0, b"{}", b""

    monkeypatch.setattr(transport, "_verify_manifest", lambda path: {})
    monkeypatch.setattr(transport, "_verify_compiler", verify_compiler)
    monkeypatch.setattr(transport, "_verified_executable", verified_executable)
    monkeypatch.setattr(transport, "_run_bounded", run_bounded)
    monkeypatch.setattr(transport, "_decode_output", lambda stdout, returncode, stderr: {})
    return calls


def test_session_verifies_once_and_only_when_native_is_used(native):
    with lifecycle.session():
        pass
    assert native["verify"] == 0

    with lifecycle.session():
        lifecycle.invoke("offline", operation="one")
        with lifecycle.session():
            lifecycle.invoke("offline", operation="two")
    assert native == {"verify": 1, "copies": 1, "runs": 2}

    lifecycle.invoke("offline", operation="three")
    lifecycle.invoke("offline", operation="four")
    assert native == {"verify": 3, "copies": 3, "runs": 4}


@pytest.fixture
def answers(monkeypatch):
    requests = []
    monkeypatch.setattr(active_security, "_key", lambda store: b"k" * 32)
    monkeypatch.setattr(lifecycle, "runtime_fingerprint", lambda: ((1, 2),))
    monkeypatch.setattr(active_security, "_ANSWERS", type(active_security._ANSWERS)())

    def invoke(kind, **fields):
        requests.append(fields)
        if fields.get("record") == "bad":
            raise ValueError("active_security_invalid")
        return {"active_matches": True, "publication": {"epoch": len(requests)}}

    monkeypatch.setattr(lifecycle, "invoke", invoke)
    return requests


def test_pure_answers_are_reused_for_identical_requests(answers):
    first = active_security.invoke("resume", object(), record="r", activation_digest="a")
    first["publication"]["epoch"] = 99
    second = active_security.invoke("resume", object(), record="r", activation_digest="a")
    assert second == {"active_matches": True, "publication": {"epoch": 1}}
    assert len(answers) == 1

    active_security.invoke("resume", object(), record="r", activation_digest="b")
    active_security.invoke("binding", object(), record="r", binding={})
    assert len(answers) == 3


def test_stateful_operations_and_failures_are_never_reused(answers):
    for _ in range(2):
        active_security.invoke("begin", object(), record="r", publication="p")
    assert len(answers) == 2

    for _ in range(2):
        with pytest.raises(ValueError, match="active_security_invalid"):
            active_security.invoke("read", object(), record="bad")
    assert len(answers) == 4


def test_answers_stay_bounded(answers):
    for index in range(active_security._ANSWERS_LIMIT + 5):
        active_security.invoke("read", object(), record=str(index))
    assert len(active_security._ANSWERS) == active_security._ANSWERS_LIMIT
    active_security.invoke("read", object(), record="0")
    assert len(answers) == active_security._ANSWERS_LIMIT + 6


def test_a_replaced_or_missing_runtime_is_asked_again(answers, monkeypatch):
    active_security.invoke("read", object(), record="r")
    monkeypatch.setattr(lifecycle, "runtime_fingerprint", lambda: ((3, 4),))
    active_security.invoke("read", object(), record="r")
    assert len(answers) == 2

    def missing():
        raise FileNotFoundError

    monkeypatch.setattr(lifecycle, "runtime_fingerprint", missing)
    active_security.invoke("read", object(), record="r")
    active_security.invoke("read", object(), record="r")
    assert len(answers) == 4


def test_runtime_fingerprint_tracks_the_installed_files(monkeypatch, tmp_path):
    monkeypatch.setattr(transport, "_NATIVE_PACKAGE", tmp_path)
    with pytest.raises(OSError):
        lifecycle.runtime_fingerprint()
    (tmp_path / transport._MANIFEST_NAME).write_text("{}")
    (tmp_path / transport._COMPILER_NAME).write_bytes(b"one")
    first = lifecycle.runtime_fingerprint()
    (tmp_path / transport._COMPILER_NAME).write_bytes(b"three")
    assert lifecycle.runtime_fingerprint() != first


def test_installed_answers_are_reused_until_an_installed_file_changes(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard.catalog_delivery import installed_bundle

    native = tmp_path / "_native"
    native.mkdir()
    (native / "runtime-manifest.json").write_text("{}")
    monkeypatch.setattr(installed_bundle, "_package", lambda: tmp_path)
    monkeypatch.setattr(transport, "_NATIVE_PACKAGE", native)
    answers = []

    def presence():
        answers.append("presence")
        if len(answers) == 3:
            raise ValueError("installed bundle metadata unavailable")
        return True

    monkeypatch.setattr(installed_bundle, "_advertised", presence)
    assert installed_bundle.advertised() and installed_bundle.advertised()
    assert answers == ["presence"]

    (native / "runtime-manifest.json").write_text('{"changed": true}')
    assert installed_bundle.advertised()
    (native / "hol-guard-runtime").write_bytes(b"new")
    with pytest.raises(ValueError, match="metadata unavailable"):
        installed_bundle.advertised()
    assert installed_bundle.advertised()
    assert len(answers) == 4
