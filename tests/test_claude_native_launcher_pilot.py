from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import claude_native_pilot_fallback as fallback
from codex_plugin_scanner.guard.adapters import claude_native_pilot_record as records
from codex_plugin_scanner.guard.codex_hook_integrity import load_or_create_hook_secret
from codex_plugin_scanner.guard.local_authority_integrity import sign_local_authority_payload


def _record(tmp_path: Path):
    guard = tmp_path / "guard"
    guard.mkdir(mode=0o700)
    secret = load_or_create_hook_secret(guard)
    folder = guard / "managed" / "claude-pilot"
    folder.mkdir(mode=0o700)
    path = folder / "launcher.json"
    config = tmp_path / "settings.json"
    argv = {event: ["/synthetic/runtime", "claude-hook-pilot", str(path), event] for event in records.EVENTS}
    config.write_text(
        json.dumps(
            {"hooks": {event: [{"hooks": [{"command": args[0], "args": args[1:]}]}] for event, args in argv.items()}}
        )
    )
    package = tmp_path / "synthetic-package.py"
    package.write_text("# synthetic immutable package file\n")
    unsigned = {
        "schema": records.SCHEMA,
        "guard_home": str(guard),
        "installation_id": secret.installation_id,
        "configuration": str(config),
        "registration_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        "argv": argv,
        "files": {"fixture": records.file_binding(package)},
    }

    def write(value):
        signed = {
            **value,
            "authentication": sign_local_authority_payload(
                value,
                key=secret.key,
                key_id=secret.key_id,
                purpose=records.PURPOSE,
                signed_at="synthetic-generation",
            ),
        }
        path.write_text(json.dumps(signed))
        path.chmod(0o600)

    write(unsigned)
    return path, unsigned, write


def test_record_authenticates_registration_and_package_before_use(tmp_path):
    path, expected, _write = _record(tmp_path)
    for event in records.EVENTS:
        loaded = records.load_record(path, event)
        assert {key: value for key, value in loaded.items() if key != "authentication"} == expected
    with pytest.raises(ValueError, match="record_invalid"):
        records.load_record(path, "PermissionRequest")


@pytest.mark.parametrize("field", ["guard_home", "installation_id", "argv", "files", "configuration"])
def test_record_tampering_cannot_choose_a_command_or_context(tmp_path, field):
    path, _expected, _write = _record(tmp_path)
    tampered = json.loads(path.read_text())
    tampered[field] = "changed"
    path.write_text(json.dumps(tampered))
    with pytest.raises(ValueError, match="authentication_failed"):
        records.load_record(path, "PreToolUse")


def test_configuration_mutation_and_file_replacement_invalidate_record(tmp_path):
    path, expected, _write = _record(tmp_path)
    configuration = Path(expected["configuration"])
    old = configuration.read_text()
    configuration.write_text(old + " ")
    with pytest.raises(ValueError, match="registration_changed"):
        records.load_record(path, "PreToolUse")
    configuration.write_text(old)
    package = Path(expected["files"]["fixture"]["path"])
    package.write_text("# changed fixture\n")
    with pytest.raises(ValueError, match="file_identity_changed"):
        records.load_record(path, "PreToolUse")


def test_interpreter_invocation_path_is_bound_separately_from_target(tmp_path):
    if os.name == "nt":
        pytest.skip("Linux pilot invocation contract")
    target = tmp_path / "python-target"
    target.write_bytes(b"synthetic executable")
    target.chmod(0o700)
    invocation = tmp_path / "venv-python"
    invocation.symlink_to(target)
    binding = records.file_binding(invocation, invocation=True)
    assert binding["path"] == str(invocation)
    assert binding["resolved"] == str(target)
    records.verify_file(binding)
    invocation.unlink()
    invocation.symlink_to(target)
    with pytest.raises(ValueError, match="file_identity_changed"):
        records.verify_file(binding)


def _handoff(data: str, **values):
    return {
        "body_base64": base64.urlsafe_b64encode(data.encode()).decode().rstrip("="),
        "deadline_monotonic_ns": time.monotonic_ns() + 2_000_000_000,
        **values,
    }


@pytest.fixture
def completion(monkeypatch, tmp_path):
    config = {
        "state_path": str(tmp_path / "guard" / "daemon-state.json"),
        "fallback_daemon_url": "http://127.0.0.1:32123",
        "fallback_command": [sys.executable, "synthetic-fallback"],
        "query": "guard-home=synthetic",
    }
    record = {"bridge": config, "recovery_command": [sys.executable, "synthetic-recovery"]}
    monkeypatch.setattr(fallback, "load_record", lambda *_args: record)
    return tmp_path / "record", config


@pytest.mark.parametrize("event", records.EVENTS)
def test_authenticated_failure_matches_existing_bridge_without_new_request(completion, monkeypatch, event):
    path, _config = completion
    data = json.dumps({"hook_event_name": event})
    monkeypatch.setattr(bridge, "_post_to_loopback_daemon", lambda *_a, **_k: pytest.fail("must not restart hook"))
    result = fallback.complete(path, event, _handoff(data, kind="identity", detail="daemon identity challenge expired"))
    assert result == bridge._authenticated_control_plane_failure("daemon identity challenge expired", data)


@pytest.mark.parametrize("event", records.EVENTS)
def test_malformed_received_response_does_not_retry_or_fallback(completion, monkeypatch, event):
    path, _config = completion
    data = json.dumps({"hook_event_name": event})
    monkeypatch.setattr(
        bridge, "_post_to_loopback_daemon", lambda *_a, **_k: pytest.fail("already received a response")
    )
    monkeypatch.setattr(bridge, "_run_local_fallback", lambda *_a, **_k: pytest.fail("no baseline fallback here"))
    assert fallback.complete(path, event, _handoff(data, kind="response", response="not-json")) == bridge._degraded(
        "daemon returned malformed hook JSON",
        data,
    )


def test_overload_keeps_existing_local_fallback_without_recovery(completion, monkeypatch):
    path, config = completion
    data = '{"hook_event_name":"PreToolUse"}'
    observed = []
    monkeypatch.setattr(
        bridge, "_recover_retry_or_fallback", lambda *_a, **_k: pytest.fail("overload must not recover")
    )
    monkeypatch.setattr(bridge, "_run_local_fallback", lambda *a, **k: observed.append((a, k)) or "{}")
    handoff = _handoff(data, kind="http", status=429, detail="capacity")
    assert fallback.complete(path, "PreToolUse", handoff) == "{}"
    assert observed[0][0] == ("daemon returned HTTP 429: capacity", data, tuple(config["fallback_command"]))
    assert observed[0][1]["deadline"] == handoff["deadline_monotonic_ns"] / 1_000_000_000


def test_transport_completion_retains_original_remaining_deadline(completion, monkeypatch):
    path, config = completion
    observed = []
    monkeypatch.setattr(bridge, "_recover_retry_or_fallback", lambda *a, **k: observed.append((a, k)) or "{}")
    handoff = _handoff('{"hook_event_name":"PreToolUse"}', kind="timeout", detail="timed out")
    assert fallback.complete(path, "PreToolUse", handoff) == "{}"
    assert observed[0][1]["deadline"] == handoff["deadline_monotonic_ns"] / 1_000_000_000
    assert observed[0][1]["fallback_command"] == tuple(config["fallback_command"])


def test_unknown_or_extended_deadline_handoff_is_rejected(completion):
    path, _config = completion
    with pytest.raises(ValueError, match="kind_invalid"):
        fallback.complete(path, "PreToolUse", _handoff("{}", kind="unknown"))
    value = _handoff("{}", kind="response", response="{}")
    value["deadline_monotonic_ns"] = time.monotonic_ns() + 20_000_000_000
    with pytest.raises(ValueError, match="deadline_invalid"):
        fallback.complete(path, "PreToolUse", value)


@pytest.mark.parametrize("kind, field", [("http", "status"), ("io", "errno")])
@pytest.mark.parametrize("invalid", [None, True, "429", 429.0, [], {}])
def test_handoff_numeric_fields_reject_coercion_before_any_bridge_action(completion, monkeypatch, kind, field, invalid):
    path, _config = completion
    monkeypatch.setattr(
        bridge, "_daemon_failure_reason", lambda *_a, **_k: pytest.fail("invalid handoff reached bridge")
    )
    handoff = _handoff("{}", kind=kind, detail="synthetic", **{field: invalid})
    with pytest.raises(ValueError, match="handoff_integer_invalid"):
        fallback.complete(path, "PreToolUse", handoff)


def test_registration_reader_rejects_growth_before_unbounded_allocation(tmp_path, monkeypatch):
    path, expected, _write = _record(tmp_path)
    configuration = Path(expected["configuration"])
    with configuration.open("r+b") as stream:
        stream.truncate(8 * 1024 * 1024)
    original = Path.read_bytes

    def no_unbounded_configuration_read(current):
        if current == configuration:
            pytest.fail("registration must use the bounded descriptor reader")
        return original(current)

    monkeypatch.setattr(Path, "read_bytes", no_unbounded_configuration_read)
    with pytest.raises(ValueError, match="private_file_changed"):
        records.load_record(path, "PreToolUse")


def test_handoff_preserves_linux_stdin_newlines(completion, monkeypatch):
    path, _config = completion
    data = "a\r\nb\rc\n"
    observed = []

    def original_reader(**_kwargs):
        observed.append(sys.stdin.read())
        sys.stdout.write("{}")

    monkeypatch.setattr(bridge, "main", original_reader)
    assert fallback.complete(path, "PreToolUse", _handoff(data, kind="before_send")) == "{}"
    assert observed == [data]


@pytest.mark.skipif(os.name == "nt", reason="Linux-only pilot file contract")
@pytest.mark.parametrize("reader", [records.bounded_read, records.file_binding])
def test_regular_file_to_fifo_replacement_does_not_block_open(tmp_path, monkeypatch, reader):
    import queue
    import threading

    path = tmp_path / "bound-file"
    path.write_bytes(b"immutable original")
    original_open = os.open
    replaced = False
    results = queue.Queue()

    def replace_before_open(current, flags, *args, **kwargs):
        nonlocal replaced
        if Path(current) == path and not replaced:
            replaced = True
            path.unlink()
            os.mkfifo(path, 0o600)
        return original_open(current, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", replace_before_open)

    def read_replaced_file():
        try:
            results.put(reader(path))
        except Exception as error:
            results.put(error)

    worker = threading.Thread(target=read_replaced_file, daemon=True)
    worker.start()
    worker.join(timeout=1)
    blocked = worker.is_alive()
    if blocked:
        # Fail safely even if a regression again blocks waiting for a FIFO writer.
        keeper = original_open(path, os.O_RDWR | os.O_NONBLOCK)
        worker.join(timeout=1)
        os.close(keeper)
    assert not blocked, "a replaced FIFO must not block the package/record descriptor open"
    assert replaced
    outcome = results.get_nowait()
    assert isinstance(outcome, ValueError) and "file_changed" in str(outcome)
