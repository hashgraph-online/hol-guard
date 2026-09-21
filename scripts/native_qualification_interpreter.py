"""Own an exact interpreter copy inside a disposable Linux or macOS venv.

The shared uv/toolcache interpreter and installed wheel bytes are never chmodded
or rewritten. The ordinary installed managed-file validator remains the gate.
"""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from scripts.native_qualification_process import observe_probe_exit

_MAX_INTERPRETER_BYTES = 128 * 1024 * 1024
_MAX_CONFIG_BYTES = 16 * 1024
_MAX_PROBE_BYTES = 16 * 1024
_PROBE_SECONDS = 15.0
_PROBE = """
import hashlib, json, platform, sqlite3, ssl, sys, sysconfig
from pathlib import Path
result = {
    "version": platform.python_version(),
    "implementation": platform.python_implementation(),
    "cache_tag": sys.implementation.cache_tag,
    "soabi": sysconfig.get_config_var("SOABI"),
    "sqlite_version": sqlite3.sqlite_version,
    "openssl_version": ssl.OPENSSL_VERSION,
    "_prefix": str(Path(sys.prefix).resolve()),
    "_base_prefix": str(Path(sys.base_prefix).resolve()),
    "_executable": str(Path(sys.executable).absolute()),
}
if sys.argv[1] == "managed":
    from codex_plugin_scanner.guard import codex_hook_file_integrity as integrity
    integrity.validate_regular_file(Path(sys.executable), role="interpreter", executable_required=True)
    validator = Path(integrity.__file__).resolve()
    if not validator.is_relative_to(Path(sys.prefix).resolve()):
        raise RuntimeError("qualification_interpreter_validator_not_installed")
    result["managed_integrity_validated"] = True
    with validator.open("rb") as handle:
        encoded = handle.read(512 * 1024 + 1)
    if len(encoded) > 512 * 1024:
        raise RuntimeError("qualification_interpreter_validator_unbounded")
    result["managed_validator_sha256"] = hashlib.sha256(encoded).hexdigest()
    result["managed_validator_inside_venv"] = True
print(json.dumps(result, sort_keys=True))
"""


class InterpreterProvisioningError(RuntimeError):
    def __init__(self, evidence: dict[str, Any]) -> None:
        super().__init__("qualification_interpreter_provisioning_failed")
        self.evidence = evidence


def _stamp(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _metadata(value: os.stat_result) -> dict[str, Any]:
    return {
        "bytes": value.st_size,
        "mode": stat.S_IMODE(value.st_mode),
        "regular": stat.S_ISREG(value.st_mode),
        "owner_current": value.st_uid == os.getuid(),
        "owner_root": value.st_uid == 0,
        "group_current": value.st_gid == os.getgid(),
        "group_root": value.st_gid == 0,
        "group_writable": bool(value.st_mode & stat.S_IWGRP),
        "world_writable": bool(value.st_mode & stat.S_IWOTH),
    }


def _private_directory(path: Path) -> None:
    value = path.lstat()
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.getuid() or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError("qualification_interpreter_venv_directory_unsafe")


def _configuration(path: Path) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not 0 < before.st_size <= _MAX_CONFIG_BYTES
    ):
        raise RuntimeError("qualification_interpreter_venv_config_invalid")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        if _stamp(os.fstat(handle.fileno())) != _stamp(before):
            raise RuntimeError("qualification_interpreter_venv_config_changed")
        encoded = handle.read(_MAX_CONFIG_BYTES + 1)
        if (
            len(encoded) != before.st_size
            or _stamp(os.fstat(handle.fileno())) != _stamp(before)
            or _stamp(path.lstat()) != _stamp(before)
        ):
            raise RuntimeError("qualification_interpreter_venv_config_changed")
    return encoded


def _probe_output(python: Path, environment: dict[str, str], *, managed: bool) -> bytes:
    deadline = time.monotonic() + _PROBE_SECONDS
    process = subprocess.Popen(
        [str(python), "-I", "-c", _PROBE, "managed" if managed else "stdlib"],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    failed = True
    try:
        assert process.stdout is not None and process.stderr is not None
        captured = {"stdout": bytearray(), "stderr": bytearray()}
        with selectors.DefaultSelector() as selector:
            for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("qualification_interpreter_probe_deadline")
                for key, _mask in selector.select(remaining):
                    chunk = os.read(key.fd, _MAX_PROBE_BYTES + 1 - len(captured[key.data]))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    captured[key.data].extend(chunk)
                    if len(captured[key.data]) > _MAX_PROBE_BYTES:
                        raise RuntimeError("qualification_interpreter_probe_output_limit")
        # Observe termination without reaping: every failed path must retain
        # the leader PID until its owned process group has been retired.
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("qualification_interpreter_probe_deadline")
            status = observe_probe_exit(process.pid)
            if status is not None:
                if status.si_code != os.CLD_EXITED or status.si_status != 0:
                    raise RuntimeError("qualification_interpreter_isolated_probe_failed")
                break
            time.sleep(min(0.01, remaining))
        process.wait(timeout=remaining)
        failed = False
        return bytes(captured["stdout"])
    finally:
        # The leader may already have exited while a descendant retains a
        # pipe. Do not poll/reap it before retiring the owned session on that
        # failure path: its unreaped PID keeps the group identity reserved.
        try:
            if failed:
                try:
                    with suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                finally:
                    process.wait(timeout=2)
        finally:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


def _probe(python: Path, *, managed: bool) -> dict[str, Any]:
    environment = dict(os.environ)
    for key in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
        environment.pop(key, None)
    value = json.loads(_probe_output(python, environment, managed=managed))
    if not isinstance(value, dict) or value.get("implementation") != "CPython":
        raise RuntimeError("qualification_interpreter_runtime_unsupported")
    if value.get("_prefix") != str(python.parent.parent.resolve()) or value.get("_executable") != str(python):
        raise RuntimeError("qualification_interpreter_venv_binding_changed")
    if value.get("_prefix") == value.get("_base_prefix"):
        raise RuntimeError("qualification_interpreter_not_a_venv")
    return value


def _copy(source: Path, invocation: Path, *, evidence: dict[str, Any]) -> None:
    before = source.lstat()
    evidence["source"] = _metadata(before)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid not in {0, os.getuid()}
        or not 0 < before.st_size <= _MAX_INTERPRETER_BYTES
        or not before.st_mode & stat.S_IXUSR
    ):
        raise RuntimeError("qualification_interpreter_source_unsupported")
    invocation_before = invocation.lstat()
    evidence["source_invocation_symlink"] = stat.S_ISLNK(invocation_before.st_mode)
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    temporary: Path | None = None
    try:
        with os.fdopen(descriptor, "rb") as original:
            if _stamp(os.fstat(original.fileno())) != _stamp(before):
                raise RuntimeError("qualification_interpreter_source_changed")
            file_descriptor, name = tempfile.mkstemp(prefix=".qualification-python-", dir=invocation.parent)
            temporary = Path(name)
            source_hash = hashlib.sha256()
            total = 0
            with os.fdopen(file_descriptor, "wb") as copied:
                while chunk := original.read(min(1024 * 1024, _MAX_INTERPRETER_BYTES + 1 - total)):
                    total += len(chunk)
                    if total > _MAX_INTERPRETER_BYTES:
                        raise RuntimeError("qualification_interpreter_source_grew")
                    source_hash.update(chunk)
                    copied.write(chunk)
                copied.flush()
                os.fchmod(copied.fileno(), 0o755)
                os.fsync(copied.fileno())
            if (
                total != before.st_size
                or _stamp(os.fstat(original.fileno())) != _stamp(before)
                or _stamp(source.lstat()) != _stamp(before)
                or _stamp(invocation.lstat()) != _stamp(invocation_before)
                or invocation.resolve(strict=True) != source
            ):
                raise RuntimeError("qualification_interpreter_source_changed")
            with temporary.open("rb") as copied:
                copied_digest = hashlib.sha256()
                for chunk in iter(lambda: copied.read(1024 * 1024), b""):
                    copied_digest.update(chunk)
                copied_hash = copied_digest.hexdigest()
            if copied_hash != source_hash.hexdigest():
                raise RuntimeError("qualification_interpreter_copy_digest_mismatch")
            evidence.update(
                source_sha256=source_hash.hexdigest(),
                copied_sha256=copied_hash,
                identical_bytes=True,
                original_target_is_invocation=source == invocation,
                original_target_preserved=None,
            )
            os.replace(temporary, invocation)
            temporary = None
            if source != invocation and _stamp(source.lstat()) != _stamp(before):
                raise RuntimeError("qualification_interpreter_original_target_changed")
            evidence["original_target_preserved"] = source != invocation
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    result = invocation.lstat()
    evidence["owned"] = _metadata(result)
    if not stat.S_ISREG(result.st_mode) or result.st_uid != os.getuid() or stat.S_IMODE(result.st_mode) != 0o755:
        raise RuntimeError("qualification_interpreter_owned_copy_unsafe")


def provision_venv_interpreter(python: Path) -> dict[str, Any]:
    """Preserve the uv-selected runtime and validate the private installed copy."""
    proof: dict[str, Any] = {
        "schema": "hol-guard.qualification-interpreter-copy.v1",
        "scope": {
            "linux": "disposable_linux_venv_interpreter_only",
            "darwin": "disposable_macos_venv_interpreter_only",
        }.get(sys.platform, "unsupported_platform"),
        "passed": False,
        "maximum_copy_bytes": _MAX_INTERPRETER_BYTES,
        "shared_interpreter_chmodded": False,
        "wheel_bytes_modified": False,
        "production_integrity_checks_relaxed": False,
    }
    try:
        if sys.platform not in {"linux", "darwin"}:
            raise RuntimeError("qualification_interpreter_platform_unsupported")
        python = python.absolute()
        if python.name != "python" or python.parent.name != "bin":
            raise RuntimeError("qualification_interpreter_invocation_unsupported")
        _private_directory(python.parent.parent)
        _private_directory(python.parent)
        configuration = python.parent.parent / "pyvenv.cfg"
        config_before = _configuration(configuration)
        original_runtime = _probe(python, managed=False)
        source = python.resolve(strict=True)
        _copy(source, python, evidence=proof)
        copied_runtime = _probe(python, managed=True)
        if any(copied_runtime.get(key) != value for key, value in original_runtime.items()):
            raise RuntimeError("qualification_interpreter_runtime_changed")
        if _configuration(configuration) != config_before:
            raise RuntimeError("qualification_interpreter_venv_config_changed")
        proof.update(
            passed=True,
            pyvenv_cfg_sha256=hashlib.sha256(config_before).hexdigest(),
            pyvenv_cfg_unchanged=True,
            base_prefix_unchanged=True,
            runtime_compatible=True,
            isolated_stdlib_extensions_loaded=True,
            managed_integrity_validated=copied_runtime["managed_integrity_validated"],
            managed_validator_sha256=copied_runtime["managed_validator_sha256"],
            managed_validator_inside_venv=copied_runtime["managed_validator_inside_venv"],
            runtime={key: value for key, value in original_runtime.items() if not key.startswith("_")},
        )
        return proof
    except Exception as error:
        proof["failure"] = {
            "category": type(error).__name__,
            "code": str(error) if str(error).startswith("qualification_interpreter_") else "unclassified_failure",
            "digest": hashlib.sha256(str(error).encode()).hexdigest(),
        }
        raise InterpreterProvisioningError(proof) from error
