"""Executable trust is bound to a running local image, never a stat cache."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_resident_client as clients
from codex_plugin_scanner.guard import native_runtime as runtime
from codex_plugin_scanner.guard import native_runtime_identity as identities
from codex_plugin_scanner.guard.native_resident_stream import _PersistentNativeClient


@pytest.fixture
def running_image(tmp_path: Path):
    if sys.platform != "linux":
        pytest.skip("Live inode pinning is Linux-only; other platforms retain full validation")
    source = Path("/bin/cat")
    if not source.is_file():
        pytest.skip("The inert stdin fixture requires the system cat executable")
    roots = [tmp_path]
    if Path("/dev/shm").is_dir():
        roots.append(Path("/dev/shm"))
    for root in roots:
        with tempfile.TemporaryDirectory(prefix="guard-live-image-", dir=root) as directory:
            executable = Path(directory) / "runtime"
            shutil.copyfile(source, executable)
            executable.chmod(0o755)
            identity = runtime._validate_binary(executable)
            assert identity is not None
            capabilities = runtime.NativeRuntimeCapabilities(1, "3.0.1", "a" * 64, "b" * 40, "x86_64-linux", ())
            status = runtime.NativeRuntimeStatus("auto", True, True, "native_ready", identity, capabilities)
            manifest = executable.with_name("runtime-manifest.json")
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "hol-guard-native-runtime.v1",
                        "protocol_version": 1,
                        "package_version": "3.0.1",
                        "target": "x86_64-linux",
                        "platform_tag": "linux_x86_64",
                        "source_sha": "b" * 40,
                        "rule_digest": "a" * 64,
                        "runtime_sha256": identity.sha256,
                        "runtime_size": identity.size,
                    }
                )
            )
            process = subprocess.Popen([str(executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            try:
                if not identities._local_executable_filesystem(process):
                    continue
                verifications = []

                def verify(verifications=verifications, status=status, executable=executable):
                    verifications.append(True)
                    return replace(status, identity=runtime._validate_binary(executable))

                yield SimpleNamespace(
                    executable=executable,
                    process=process,
                    status=status,
                    manifest=manifest,
                    verify=verify,
                    verifications=verifications,
                )
                return
            finally:
                identities.retire_native_process(process)
                process.terminate()
                process.wait(timeout=2)
                for stream in (process.stdin, process.stdout):
                    if stream is not None:
                        stream.close()
    pytest.skip("No eligible executable local filesystem was available")


def _attest(fixture):
    result = identities.attest_native_process(
        fixture.process,
        fixture.status,
        verify=fixture.verify,
        package_version=lambda: "3.0.1",
    )
    assert result.status == "verified"
    assert result.attestation is not None
    return result.attestation


def test_live_image_reuses_only_a_verified_running_inode(running_image):
    attestation = _attest(running_image)
    for _ in range(5):
        assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") == (
            running_image.status.identity
        )
    assert running_image.verifications == [True]
    assert identities.attestation_is_current(attestation, package_version="3.0.1")
    with pytest.raises(OSError) as caught:
        os.open(running_image.executable, os.O_WRONLY | os.O_NONBLOCK)
    assert caught.value.errno == errno.ETXTBSY


@pytest.mark.parametrize(
    "change", ("same_size_replacement", "symlink", "permissions", "manifest", "manifest_permissions", "restored_mtime")
)
def test_live_identity_retires_file_and_manifest_changes(running_image, change):
    attestation = _attest(running_image)
    path = running_image.executable
    before = path.stat()
    if change in {"same_size_replacement", "symlink"}:
        replacement = path.with_name("replacement")
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(stat_mode := (before.st_mode & 0o777))
        assert stat_mode == 0o755
        os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
        if change == "symlink":
            path.unlink()
            path.symlink_to(replacement)
        else:
            replacement.replace(path)
            assert path.stat().st_size == before.st_size
            assert path.stat().st_mtime_ns == before.st_mtime_ns
    elif change == "permissions":
        path.chmod(0o777)
    elif change == "manifest":
        payload = json.loads(running_image.manifest.read_text())
        payload["source_sha"] = "c" * 40
        running_image.manifest.write_text(json.dumps(payload))
    elif change == "manifest_permissions":
        running_image.manifest.chmod(0o666)
    else:
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert path.stat().st_mtime_ns == before.st_mtime_ns
    assert not identities.attestation_is_current(attestation, package_version="3.0.1")
    assert identities.live_native_identity(path, package_version=lambda: "3.0.1") is None


def test_package_version_and_process_exit_revoke_the_proof(running_image):
    attestation = _attest(running_image)
    assert not identities.attestation_is_current(attestation, package_version="3.0.2")
    assert not identities.attestation_is_current(attestation, package_version=None)
    running_image.process.terminate()
    running_image.process.wait(timeout=2)
    assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") is None
    content = bytearray(running_image.executable.read_bytes())
    content[-1] ^= 1
    before = running_image.executable.stat()
    running_image.executable.write_bytes(content)
    os.utime(running_image.executable, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert len(content) == running_image.status.identity.size
    assert hashlib.sha256(content).hexdigest() != running_image.status.identity.sha256
    assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") is None


def test_mismatched_verification_never_registers_a_child(running_image):
    mismatched = replace(running_image.status, compatible=False)
    result = identities.attest_native_process(
        running_image.process,
        running_image.status,
        verify=lambda: mismatched,
        package_version=lambda: "3.0.1",
    )
    assert result.status == "invalid"
    assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") is None


def test_unsupported_filesystem_never_registers_digest_reuse(running_image, monkeypatch):
    monkeypatch.setattr(identities, "_local_executable_filesystem", lambda _process: False)
    result = identities.attest_native_process(
        running_image.process,
        running_image.status,
        verify=running_image.verify,
        package_version=lambda: "3.0.1",
    )
    assert result.status == "unsupported"
    assert running_image.verifications == [True]
    assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") is None


def test_unsupported_filesystem_still_checks_the_new_child_against_full_admission(running_image, monkeypatch):
    monkeypatch.setattr(identities, "_local_executable_filesystem", lambda _process: False)
    result = identities.attest_native_process(
        running_image.process,
        replace(running_image.status, capabilities=replace(running_image.status.capabilities, build_sha="c" * 40)),
        verify=running_image.verify,
        package_version=lambda: "3.0.1",
    )
    assert result.status == "invalid"
    assert running_image.verifications == [True]
    assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") is None


def test_new_process_admission_hashes_even_while_another_child_is_attested(running_image, monkeypatch):
    _attest(running_image)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setattr(runtime, "_bundled_runtime_candidate", lambda: running_image.executable)
    monkeypatch.setattr(runtime, "_python_package_version", lambda: "3.0.1")
    monkeypatch.setattr(runtime, "_capabilities_for_identity", lambda *_args: running_image.status.capabilities)
    original = runtime._validate_binary
    validations = []

    def counted(path):
        validations.append(path)
        return original(path)

    monkeypatch.setattr(runtime, "_validate_binary", counted)
    assert runtime.native_runtime_status().compatible
    assert not validations
    required, admitted = runtime.native_process_spawn_admission(running_image.executable)
    assert required and admitted is not None and admitted.compatible
    assert validations == [running_image.executable]


def test_child_death_between_status_and_dispatch_never_authorizes_a_changed_respawn(running_image, monkeypatch):
    attestation = _attest(running_image)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setattr(runtime, "_bundled_runtime_candidate", lambda: running_image.executable)
    monkeypatch.setattr(runtime, "_python_package_version", lambda: "3.0.1")
    monkeypatch.setattr(runtime, "_capabilities_for_identity", lambda *_args: running_image.status.capabilities)
    original = runtime._validate_binary
    validations = []

    def counted(path):
        validations.append(path)
        return original(path)

    monkeypatch.setattr(runtime, "_validate_binary", counted)
    assert runtime.native_runtime_status().compatible
    assert not validations
    client = _PersistentNativeClient(executable=running_image.executable, state_dir=Path("/unused"), environment={})
    client._process = running_image.process
    client._attestation = attestation
    running_image.process.terminate()
    running_image.process.wait(timeout=2)
    before = running_image.executable.stat()
    replacement = bytearray(running_image.executable.read_bytes())
    replacement[-1] ^= 1
    running_image.executable.write_bytes(replacement)
    os.utime(running_image.executable, ns=(before.st_atime_ns, before.st_mtime_ns))

    def no_spawn(*_args, **_kwargs):
        pytest.fail("A mismatched new image must fail full admission before Popen")

    monkeypatch.setattr(subprocess, "Popen", no_spawn)
    assert client._request_snapshot() is None
    assert validations == [running_image.executable]
    assert client._process is None and client._attestation is None
    assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") is None


def test_registration_detects_image_change_during_verification(running_image):
    def replace_after_hash():
        verified = running_image.verify()
        replacement = running_image.executable.with_name("replacement")
        replacement.write_bytes(running_image.executable.read_bytes())
        replacement.chmod(0o755)
        replacement.replace(running_image.executable)
        return verified

    result = identities.attest_native_process(
        running_image.process,
        running_image.status,
        verify=replace_after_hash,
        package_version=lambda: "3.0.1",
    )
    assert result.status == "invalid"
    assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") is None


def test_a_different_process_start_marker_cannot_reuse_identity(running_image, monkeypatch):
    attestation = _attest(running_image)
    monkeypatch.setattr(
        identities,
        "_process_image",
        lambda *_args: (attestation.image_metadata, str(int(attestation.process_start_marker) + 1)),
    )
    assert not identities.attestation_is_current(attestation, package_version="3.0.1")
    assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") is None


@pytest.mark.parametrize("retirement", ("process", "path"))
def test_retirement_during_file_probes_cannot_return_a_current_attestation(running_image, monkeypatch, retirement):
    attestation = _attest(running_image)
    original = identities._manifest_binding

    def retire_after_probe(executable):
        binding = original(executable)
        if retirement == "process":
            identities.retire_native_process(running_image.process)
        else:
            identities.retire_native_path(executable)
        return binding

    monkeypatch.setattr(identities, "_manifest_binding", retire_after_probe)
    assert not identities.attestation_is_current(attestation, package_version="3.0.1")
    assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") is None


@pytest.mark.parametrize("platform_name", ("darwin", "win32"))
def test_unimplemented_platforms_keep_full_validation(running_image, monkeypatch, platform_name):
    _attest(running_image)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setattr(runtime, "_bundled_runtime_candidate", lambda: running_image.executable)
    monkeypatch.setattr(runtime, "_python_package_version", lambda: "3.0.1")
    monkeypatch.setattr(runtime, "_capabilities_for_identity", lambda *_args: running_image.status.capabilities)
    monkeypatch.setattr(runtime, "sys", SimpleNamespace(platform=platform_name))
    monkeypatch.setattr(identities, "sys", SimpleNamespace(platform=platform_name))
    original = runtime._validate_binary
    validations = []

    def counted(path):
        validations.append(path)
        return original(path)

    monkeypatch.setattr(runtime, "_validate_binary", counted)
    assert runtime.native_runtime_status().compatible
    assert runtime.native_runtime_status().compatible
    assert validations == [running_image.executable, running_image.executable]
    assert runtime.native_process_spawn_admission(running_image.executable) == (False, None)


def test_executable_ownership_change_retires_the_live_proof(running_image):
    if os.geteuid() != 0:
        pytest.skip("An actual ownership transition requires root for this fixture")
    attestation = _attest(running_image)
    before = running_image.executable.stat()
    try:
        try:
            os.chown(running_image.executable, 65534, before.st_gid)
        except OSError as exc:
            if exc.errno in {errno.EINVAL, errno.EPERM, errno.ENOSYS}:
                pytest.skip("The host UID map or filesystem does not permit this ownership transition")
            raise
        assert not identities.attestation_is_current(attestation, package_version="3.0.1")
        assert runtime._validate_binary(running_image.executable) is None
    finally:
        os.chown(running_image.executable, before.st_uid, before.st_gid)


@pytest.mark.parametrize("failure", ("invalid", "exception"))
def test_failed_post_spawn_verification_closes_child_before_any_frame(running_image, monkeypatch, failure):
    monkeypatch.setattr(runtime, "native_process_spawn_admission", lambda _: (True, running_image.status))
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: running_image.process)

    def rejected(*_args, **_kwargs):
        if failure == "exception":
            raise OSError("synthetic verification failure")
        return identities.NativeProcessAttestationResult("invalid")

    monkeypatch.setattr(runtime, "register_native_process_attestation", rejected)
    client = _PersistentNativeClient(executable=running_image.executable, state_dir=Path("/unused"), environment={})

    def no_frame(*_args, **_kwargs):
        pytest.fail("An unverified child must never receive a hook frame")

    monkeypatch.setattr(client, "_write_frame", no_frame)
    assert client.request(b"synthetic hook frame", deadline_monotonic=time.monotonic() + 1) is None
    assert client._process is None and running_image.process.poll() is not None
    assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") is None


@pytest.mark.parametrize("failure", ("capabilities_missing", "protocol_mismatch", "manifest_build_mismatch"))
def test_failed_capability_validation_retires_the_existing_proof(running_image, monkeypatch, failure):
    attestation = _attest(running_image)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setattr(runtime, "_bundled_runtime_candidate", lambda: running_image.executable)
    monkeypatch.setattr(runtime, "_python_package_version", lambda: "3.0.1")
    capabilities = (
        None
        if failure == "capabilities_missing"
        else replace(
            running_image.status.capabilities,
            **({"protocol_version": 2} if failure == "protocol_mismatch" else {"build_sha": "c" * 40}),
        )
    )
    monkeypatch.setattr(runtime, "_capabilities_for_identity", lambda *_args: capabilities)
    assert not runtime.native_runtime_status().compatible
    assert not identities.attestation_is_current(attestation, package_version="3.0.1")
    assert identities.live_native_identity(running_image.executable, package_version=lambda: "3.0.1") is None


def test_pool_file_replacement_retires_the_old_streams(tmp_path, monkeypatch):
    path = tmp_path / "runtime"
    path.write_bytes(b"one")
    state_dir = tmp_path / "home" / "native-runtime"
    first = clients._client_pool_for(path, state_dir, {})
    closed = []
    monkeypatch.setattr(first, "close", lambda: closed.append(first))
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"two")
    replacement.replace(path)
    second = clients._client_pool_for(path, state_dir, {})
    try:
        assert second is not first
        assert closed == [first]
    finally:
        clients.close_native_resident_clients(state_dir.parent)
