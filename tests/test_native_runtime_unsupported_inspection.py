"""Restricted Linux /proc keeps full admission without creating cache trust."""

from __future__ import annotations

import errno
import json
import os
import subprocess
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runtime as runtime
from codex_plugin_scanner.guard import native_runtime_identity as identities
from codex_plugin_scanner.guard.native_resident_stream import _PersistentNativeClient

from .test_native_runtime_live_identity import _attest
from .test_native_runtime_live_identity import running_image as _running_image

running_image = _running_image


def _deny_proc(monkeypatch, *, error: int, surface: str, pid: int | None = None):
    original_read = Path.read_text
    original_stat = Path.stat

    def affected(path):
        return path.parent.parent == Path("/proc") and (pid is None or path.parent.name == str(pid))

    def read(path, *args, **kwargs):
        if surface == "stat" and path.name == "stat" and affected(path):
            raise OSError(error, "synthetic unavailable process inspection")
        return original_read(path, *args, **kwargs)

    def metadata(path, *args, **kwargs):
        if surface == "exe" and path.name == "exe" and affected(path):
            raise OSError(error, "synthetic unavailable image inspection")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(Path, "stat", metadata)


def _runtime_for_fixture(monkeypatch, fixture):
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setattr(runtime, "_bundled_runtime_candidate", lambda: fixture.executable)
    monkeypatch.setattr(runtime, "_python_package_version", lambda: "3.0.1")
    monkeypatch.setattr(runtime, "_capabilities_for_identity", lambda *_args: fixture.status.capabilities)


@pytest.mark.parametrize("error", (errno.EACCES, errno.EPERM, errno.ENOENT, errno.ENOSYS, errno.ENOTSUP))
@pytest.mark.parametrize("surface", ("stat", "exe"))
def test_unavailable_proc_is_typed_and_full_verified_without_a_reusable_proof(
    running_image, monkeypatch, error, surface
):
    _deny_proc(monkeypatch, error=error, surface=surface, pid=running_image.process.pid)
    inspected = identities._inspect_process_image(running_image.process, running_image.executable)
    assert inspected.status == "unsupported"
    result = identities.attest_native_process(
        running_image.process,
        running_image.status,
        verify=running_image.verify,
        package_version=lambda: "3.0.1",
    )
    assert result.status == "unsupported" and result.attestation is None
    assert running_image.verifications == [True]
    assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") is None
    assert id(running_image.process) not in identities._ATTESTATIONS


@pytest.mark.parametrize("fallback", ("restricted_proc", "registry_capacity"))
def test_fallback_stream_hashes_before_and_after_launch_and_every_warm_status(running_image, monkeypatch, fallback):
    _runtime_for_fixture(monkeypatch, running_image)
    prior = None
    if fallback == "restricted_proc":
        _deny_proc(monkeypatch, error=errno.EACCES, surface="stat")
    else:
        monkeypatch.setattr(identities, "_MAX_ATTESTATIONS", 1)
        monkeypatch.setattr(identities, "_digest_reuse_suspended", False)
        prior = _attest(running_image)
    original_validate = runtime._validate_binary
    original_spawn = subprocess.Popen
    events = []

    def validate(path):
        events.append("full-validation")
        return original_validate(path)

    def spawn(_args, **kwargs):
        events.append("spawn")
        # The real inert executable waits on stdin; no synthetic process or
        # fabricated executable identity substitutes for kernel behavior.
        return original_spawn([str(running_image.executable)], **kwargs)

    monkeypatch.setattr(runtime, "_validate_binary", validate)
    monkeypatch.setattr(subprocess, "Popen", spawn)
    client = _PersistentNativeClient(executable=running_image.executable, state_dir=Path("/unused"), environment={})
    try:
        assert client._start()
        assert events == ["full-validation", "spawn", "full-validation"]
        assert client._attestation is None and client._process is not None
        assert client._process.poll() is None
        if prior is not None:
            assert identities._digest_reuse_suspended
            assert len(identities._ATTESTATIONS) + len(identities._FULL_VALIDATION_CLIENTS) == 1
            assert identities.attestation_is_current(prior, package_version="3.0.1")
        events.clear()
        for _ in range(3):
            assert runtime.native_runtime_status().compatible
        assert events == ["full-validation"] * 3
        client.close()
        events.clear()
        assert client._start()
        assert events == ["full-validation", "spawn", "full-validation"]
    finally:
        client.close()


@pytest.mark.parametrize("same_process", (False, True))
def test_unsupported_client_registered_during_probes_cannot_return_indirect_reuse(
    running_image, monkeypatch, same_process
):
    _attest(running_image)
    process = (
        running_image.process
        if same_process
        else subprocess.Popen([str(running_image.executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    )
    entered = threading.Event()
    finished = threading.Event()
    results = []
    original = identities._manifest_binding
    caller = threading.current_thread()

    def register():
        assert entered.wait(2)
        try:
            _deny_proc(monkeypatch, error=errno.EACCES, surface="exe", pid=process.pid)
            results.append(
                identities.attest_native_process(
                    process, running_image.status, verify=running_image.verify, package_version=lambda: "3.0.1"
                )
            )
        finally:
            finished.set()

    def inspect_manifest(path):
        binding = original(path)
        if threading.current_thread() is caller:
            entered.set()
            assert finished.wait(2)
        return binding

    worker = threading.Thread(target=register)
    try:
        monkeypatch.setattr(identities, "_manifest_binding", inspect_manifest)
        worker.start()
        assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") is None
        worker.join(timeout=2)
        assert not worker.is_alive()
        assert len(results) == 1 and results[0].status == "unsupported"
        assert id(process) in identities._FULL_VALIDATION_CLIENTS
    finally:
        entered.set()
        worker.join(timeout=2)
        identities.retire_native_process(process)
        process.terminate()
        process.wait(timeout=2)
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                stream.close()


def test_uninspectable_client_prevents_indirect_reuse_from_another_verified_child(running_image, monkeypatch):
    _attest(running_image)
    process = subprocess.Popen([str(running_image.executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        _deny_proc(monkeypatch, error=errno.ENOENT, surface="exe", pid=process.pid)
        result = identities.attest_native_process(
            process, running_image.status, verify=running_image.verify, package_version=lambda: "3.0.1"
        )
        assert result.status == "unsupported"
        assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") is None
        process.terminate()
        process.wait(timeout=2)
        assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") == (
            running_image.status.identity
        )
    finally:
        identities.retire_native_process(process)
        process.terminate()
        process.wait(timeout=2)
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                stream.close()


@pytest.mark.parametrize("change", ("pid", "parent", "start", "inode", "unsafe_mode", "unsafe_owner"))
def test_affirmative_identity_mismatches_are_never_unsupported(running_image, monkeypatch, change):
    original_read = Path.read_text
    original_stat = Path.stat
    original_lstat = Path.lstat
    target = Path("/proc") / str(running_image.process.pid)
    start_reads = 0

    def read(path, *args, **kwargs):
        nonlocal start_reads
        content = original_read(path, *args, **kwargs)
        if path != target / "stat":
            return content
        prefix, suffix = content.rsplit(")", 1)
        fields = suffix.split()
        if change == "pid":
            prefix = str(running_image.process.pid + 1) + " (synthetic"
        elif change == "parent":
            fields[1] = str(os.getpid() + 1)
        elif change == "start":
            fields[19] = str(int(fields[19]) + start_reads)
            start_reads += 1
        return prefix + ") " + " ".join(fields)

    def stat(path, *args, **kwargs):
        metadata = original_stat(path, *args, **kwargs)
        if change == "inode" and path == target / "exe":
            values = list(metadata)
            values[1] += 1
            return os.stat_result(values)
        return metadata

    def lstat(path, *args, **kwargs):
        metadata = original_lstat(path, *args, **kwargs)
        if change == "unsafe_owner" and path == running_image.executable:
            values = list(metadata)
            values[4] = os.getuid() + 65534
            return os.stat_result(values)
        return metadata

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(Path, "stat", stat)
    monkeypatch.setattr(Path, "lstat", lstat)
    if change == "unsafe_mode":
        running_image.executable.chmod(0o777)
    result = identities.attest_native_process(
        running_image.process,
        running_image.status,
        verify=running_image.verify,
        package_version=lambda: "3.0.1",
    )
    assert result.status == "invalid" and result.attestation is None
    assert id(running_image.process) not in identities._FULL_VALIDATION_CLIENTS


@pytest.mark.parametrize("change", ("manifest", "package", "full_validation", "exit"))
def test_unsupported_proc_cannot_hide_failed_full_admission(running_image, monkeypatch, change):
    _deny_proc(monkeypatch, error=errno.EACCES, surface="stat", pid=running_image.process.pid)

    def verify():
        verified = running_image.verify()
        if change == "manifest":
            content = json.loads(running_image.manifest.read_text())
            content["source_sha"] = "d" * 40
            running_image.manifest.write_text(json.dumps(content))
        elif change == "exit":
            running_image.process.terminate()
            running_image.process.wait(timeout=2)
        return replace(verified, compatible=False) if change == "full_validation" else verified

    result = identities.attest_native_process(
        running_image.process,
        running_image.status,
        verify=verify,
        package_version=lambda: "changed-version" if change == "package" else "3.0.1",
    )
    assert result.status == "invalid"
    assert id(running_image.process) not in identities._FULL_VALIDATION_CLIENTS


def test_unexpected_proc_io_failure_is_not_classified_as_supported_fallback(running_image, monkeypatch):
    _deny_proc(monkeypatch, error=errno.EIO, surface="stat", pid=running_image.process.pid)
    inspected = identities._inspect_process_image(running_image.process, running_image.executable)
    assert inspected.status == "invalid"


def test_affirmative_pid_mismatch_quarantines_the_actual_child_before_any_frame(running_image, monkeypatch):
    _runtime_for_fixture(monkeypatch, running_image)
    original_spawn = subprocess.Popen
    original_read = Path.read_text
    children = []

    def spawn(_args, **kwargs):
        process = original_spawn([str(running_image.executable)], **kwargs)
        children.append(process)
        return process

    def read(path, *args, **kwargs):
        content = original_read(path, *args, **kwargs)
        if children and path == Path("/proc") / str(children[0].pid) / "stat":
            return str(children[0].pid + 1) + " " + content.split(" ", 1)[1]
        return content

    def no_frame(*_args, **_kwargs):
        pytest.fail("An observed PID mismatch must quarantine before any hook frame")

    monkeypatch.setattr(subprocess, "Popen", spawn)
    monkeypatch.setattr(Path, "read_text", read)
    client = _PersistentNativeClient(executable=running_image.executable, state_dir=Path("/unused"), environment={})
    monkeypatch.setattr(client, "_write_frame", no_frame)
    try:
        assert client.request(b"synthetic hook", deadline_monotonic=time.monotonic() + 1) is None
        assert len(children) == 1 and children[0].poll() is not None
        assert client._process is None
        assert id(children[0]) not in identities._FULL_VALIDATION_CLIENTS
    finally:
        client.close()
