from __future__ import annotations

import hashlib
import threading
import time

import pytest

from codex_plugin_scanner.guard import codex_hook_bridge_runtime as bridge_runtime
from codex_plugin_scanner.guard import codex_hook_file_integrity as files
from codex_plugin_scanner.guard import codex_hook_integrity as manifests
from codex_plugin_scanner.guard import codex_hook_launch_runtime as launches
from codex_plugin_scanner.guard import codex_hook_runtime_trust as trust


def test_expired_validation_reads_no_authority_or_executable(monkeypatch):
    def forbidden(**kwargs):
        raise AssertionError("expired operation started identity validation")

    monkeypatch.setattr(trust, "validate_codex_hook_launch", forbidden)
    with pytest.raises(files.CodexHookIntegrityError, match="exhausted"):
        bridge_runtime.trusted_hook_launch(
            manifest_path="/isolated/manifest.json",
            state_path="/isolated/guard/daemon.json",
            fallback_command=("fixture",),
            start_command=("fixture",),
            config_json="{}",
            deadline_monotonic=time.monotonic() - 1,
        )


def test_hashing_stops_after_the_chunk_that_exhausts_original_budget(tmp_path, monkeypatch):
    path = tmp_path / "module.py"
    path.write_bytes(b"fixture")
    clock, reads = [5.0], []
    monkeypatch.setattr(files.time, "monotonic", lambda: clock[0])

    class SlowFile:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            reads.append(size)
            clock[0] = 11.0
            return b"fixture"

    with monkeypatch.context() as patch:
        patch.setattr(type(path), "open", lambda *args, **kwargs: SlowFile())
        with pytest.raises(files.CodexHookIntegrityError, match="exhausted"), files.hook_validation_deadline(10):
            files._sha256_file(path)
    assert reads == [1024 * 1024]
    # A failed validator cannot leave a deadline attached to later operations.
    assert files._sha256_file(path) == hashlib.sha256(b"fixture").hexdigest()


def test_nested_and_legacy_validation_scopes_cannot_renew_original_budget(tmp_path, monkeypatch):
    path = tmp_path / "module.py"
    path.write_bytes(b"fixture")
    clock = [5.0]
    monkeypatch.setattr(files.time, "monotonic", lambda: clock[0])
    with files.hook_validation_deadline(10):
        for nested in (None, 20.0):
            with (
                pytest.raises(files.CodexHookIntegrityError, match="exhausted"),
                files.hook_validation_deadline(nested),
            ):
                clock[0] = 11.0
                files._sha256_file(path)
            clock[0] = 5.0
    clock[0] = 11.0
    assert files._sha256_file(path) == hashlib.sha256(b"fixture").hexdigest()


def test_expiry_after_manifest_read_does_not_read_authority_key(tmp_path, monkeypatch):
    path = tmp_path / "manifest.json"
    path.write_text("{}")
    path.chmod(0o600)
    clock = [5.0]
    monkeypatch.setattr(files.time, "monotonic", lambda: clock[0])

    def slow_read(*args, **kwargs):
        clock[0] = 11.0
        return "{}"

    def forbidden(*args, **kwargs):
        raise AssertionError("expired manifest validation read authority key")

    monkeypatch.setattr(manifests, "read_private_regular_text", slow_read)
    monkeypatch.setattr(manifests, "load_hook_secret", forbidden)
    with pytest.raises(files.CodexHookIntegrityError, match="exhausted"), files.hook_validation_deadline(10):
        manifests.load_authenticated_hook_manifest_path(tmp_path, path)


def test_validation_deadline_does_not_leak_into_another_thread(tmp_path, monkeypatch):
    path = tmp_path / "module.py"
    path.write_bytes(b"fixture")
    monkeypatch.setattr(
        files.time, "monotonic", lambda: 11.0 if threading.current_thread().name == "other-validator" else 5.0
    )
    results = []

    def other_validator():
        try:
            results.append(files._sha256_file(path))
        except Exception as error:
            results.append(error)

    with files.hook_validation_deadline(10):
        thread = threading.Thread(target=other_validator, name="other-validator")
        thread.start()
        thread.join(timeout=1)
        assert not thread.is_alive()
    assert results == [hashlib.sha256(b"fixture").hexdigest()]


@pytest.mark.parametrize("deadline", [float("nan"), float("inf"), True])
def test_invalid_deadline_does_not_enter_validation_scope(deadline):
    with pytest.raises(files.CodexHookIntegrityError, match="invalid"), files.hook_validation_deadline(deadline):
        raise AssertionError("invalid deadline admitted validation")


@pytest.mark.parametrize("contained", [True, False])
def test_authenticated_children_keep_original_deadline_and_require_containment(tmp_path, monkeypatch, contained):
    calls = []
    monkeypatch.setattr(trust.time, "monotonic", lambda: 5.0)

    def runner(*args, **kwargs):
        calls.append(kwargs["deadline_monotonic"])
        return launches.BoundedHookProcessResult(0, "{}", False, False, containment_failed=not contained)

    monkeypatch.setattr(trust, "run_isolated_hook_process", runner)
    context = trust.TrustedCodexHookLaunch(tmp_path, {}, deadline_monotonic=10)
    assert context.run_start(("fixture",), timeout_seconds=99) is contained
    assert context.run_fallback(("fixture",), data="{}", timeout_seconds=99) == ("{}" if contained else None)
    assert calls == [10, 10]


def test_expired_authenticated_context_cannot_start_a_child_with_fresh_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(trust.time, "monotonic", lambda: 5.0)

    def forbidden(*args, **kwargs):
        raise AssertionError("expired authenticated context launched a child")

    monkeypatch.setattr(launches, "_spawn_hook_process", forbidden)
    context = trust.TrustedCodexHookLaunch(tmp_path, {}, deadline_monotonic=4)
    assert not context.run_start(("fixture",), timeout_seconds=99)
    assert context.run_fallback(("fixture",), data="{}", timeout_seconds=99) is None


def test_successful_validator_returned_after_deadline_cannot_publish_a_launch_context(tmp_path, monkeypatch):
    clock, observed = [5.0], []
    monkeypatch.setattr(files.time, "monotonic", lambda: clock[0])

    def slow_validator(**kwargs):
        observed.append(files.active_hook_validation_deadline())
        clock[0] = 11.0
        return trust.TrustedCodexHookLaunch(tmp_path, {}, deadline_monotonic=observed[0])

    monkeypatch.setattr(trust, "validate_codex_hook_launch", slow_validator)
    with pytest.raises(files.CodexHookIntegrityError, match="exhausted"):
        bridge_runtime.trusted_hook_launch(
            manifest_path="/isolated/manifest.json",
            state_path="/isolated/guard/daemon.json",
            fallback_command=("fixture",),
            start_command=("fixture",),
            config_json="{}",
            deadline_monotonic=10,
        )
    assert observed == [10]


def test_phase_cap_remains_shorter_than_original_deadline(tmp_path, monkeypatch):
    captured = []
    monkeypatch.setattr(trust.time, "monotonic", lambda: 5.0)

    def runner(*args, **kwargs):
        captured.append(kwargs["deadline_monotonic"])
        return launches.BoundedHookProcessResult(0, "{}", False, False)

    monkeypatch.setattr(trust, "run_isolated_hook_process", runner)
    context = trust.TrustedCodexHookLaunch(tmp_path, {}, deadline_monotonic=10)
    assert context.run_start(("fixture",), timeout_seconds=2)
    assert captured == [7]
