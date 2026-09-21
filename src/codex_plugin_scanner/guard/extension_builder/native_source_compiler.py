"""Bounded access to the packaged declarative source compiler.

The compiler is a native release resource.  This module only locates a
manifest-bound executable and exchanges one bounded JSON document over stdin;
it never discovers Cargo, reads a checkout, imports contributor code, or
provides a Python compilation fallback.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import subprocess
import tempfile
import threading
from collections.abc import Mapping
from contextlib import contextmanager, suppress
from importlib import metadata
from pathlib import Path
from typing import BinaryIO

_MAX_INPUT_BYTES = 4 * 1024 * 1024
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_COMPILER_BYTES = 128 * 1024 * 1024
_MAX_STDERR_BYTES = 64 * 1024
_DEFAULT_TIMEOUT_SECONDS = 30.0
_SHA40 = 40
_SHA64 = 64
_MANIFEST_NAME = "source-compiler-manifest.json"
_COMPILER_NAME = "guard-command-source.exe" if os.name == "nt" else "guard-command-source"
_NATIVE_PACKAGE = Path(__file__).resolve().parents[2] / "_native"
_DEVELOPMENT_COMPILER_ENV = "HOL_GUARD_NATIVE_SOURCE_COMPILER"
# Both environment overrides are restricted to source checkouts without a
# packaged compiler. The development override takes precedence in that case.
_TEST_COMPILER_ENV = "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER"
_PACKAGED_PROGRAM = (
    Path(__file__).resolve().parents[1] / "contracts" / "data" / "extensions" / "native-command-program.v1.json"
)


class NativeSourceCompilerError(RuntimeError):
    """Raised when the packaged compiler cannot be verified or completed."""

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        pointer: str | None = None,
        returncode: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.pointer = pointer
        self.returncode = returncode


def _read_regular(path: Path, *, limit: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise NativeSourceCompilerError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise NativeSourceCompilerError(f"{label} must be a regular non-symlink file")
    if before.st_size <= 0 or before.st_size > limit:
        raise NativeSourceCompilerError(f"{label} size is outside the accepted bound")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise NativeSourceCompilerError(f"{label} could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size != before.st_size:
            raise NativeSourceCompilerError(f"{label} changed while being opened")
        content = bytearray()
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            while True:
                chunk = handle.read(min(64 * 1024, limit + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > limit:
                    raise NativeSourceCompilerError(f"{label} exceeds the accepted bound")
        if len(content) != before.st_size:
            raise NativeSourceCompilerError(f"{label} could not be read completely")
        return bytes(content)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _manifest(path: Path) -> dict[str, object]:
    raw = _read_regular(path, limit=_MAX_MANIFEST_BYTES, label="source compiler manifest")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise NativeSourceCompilerError("source compiler manifest contains duplicate keys")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeSourceCompilerError("source compiler manifest is invalid") from exc
    if not isinstance(value, dict):
        raise NativeSourceCompilerError("source compiler manifest must be an object")
    return value


def _hex(value: object, *, length: int, field: str) -> str:
    if not isinstance(value, str) or len(value) != length or any(char not in "0123456789abcdef" for char in value):
        raise NativeSourceCompilerError(f"source compiler manifest has an invalid {field}")
    return value


def _verify_compiler(path: Path, manifest: Mapping[str, object]) -> bytes:
    raw = _read_regular(path, limit=_MAX_COMPILER_BYTES, label="source compiler")
    if os.name != "nt":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o022:
            raise NativeSourceCompilerError("source compiler is group/world writable")
        if not mode & stat.S_IXUSR:
            raise NativeSourceCompilerError("source compiler is not owner-executable")
    size = manifest.get("compiler_size")
    if not isinstance(size, int) or size <= 0 or size != len(raw):
        raise NativeSourceCompilerError("source compiler manifest size does not match the executable")
    digest = _hex(manifest.get("compiler_sha256"), length=_SHA64, field="compiler hash")
    if hashlib.sha256(raw).hexdigest() != digest:
        raise NativeSourceCompilerError("source compiler hash does not match its manifest")
    return raw


def _packaged_program_digest() -> str:
    raw = _read_regular(_PACKAGED_PROGRAM, limit=_MAX_INPUT_BYTES, label="packaged native command program")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeSourceCompilerError("packaged native command program is invalid") from exc
    if not isinstance(value, dict):
        raise NativeSourceCompilerError("packaged native command program is invalid")
    return _hex(value.get("program_digest"), length=_SHA64, field="base program digest")


def _verify_manifest(path: Path) -> dict[str, object]:
    manifest = _manifest(path)
    if manifest.get("schema") != "hol-guard-native-source-compiler.v1":
        raise NativeSourceCompilerError("source compiler manifest schema is unsupported")
    if manifest.get("protocol_version") != 1:
        raise NativeSourceCompilerError("source compiler manifest protocol is unsupported")
    package_version = manifest.get("package_version")
    if not isinstance(package_version, str) or not package_version.strip():
        raise NativeSourceCompilerError("source compiler manifest package version is invalid")
    try:
        installed_version = metadata.version("hol-guard")
    except metadata.PackageNotFoundError:
        installed_version = None
    if installed_version is not None and installed_version != package_version:
        raise NativeSourceCompilerError("source compiler package version does not match the installed package")
    target = manifest.get("target")
    platform_tag = manifest.get("platform_tag")
    if (
        not isinstance(target, str)
        or not target
        or any(char in target for char in "\\/\x00")
        or not isinstance(platform_tag, str)
        or not platform_tag
        or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_." for char in platform_tag)
    ):
        raise NativeSourceCompilerError("source compiler manifest target is invalid")
    _hex(manifest.get("source_sha"), length=_SHA40, field="source SHA")
    _hex(manifest.get("implementation_digest"), length=_SHA64, field="implementation digest")
    base_program_digest = _hex(manifest.get("base_program_digest"), length=_SHA64, field="base program digest")
    if base_program_digest != _packaged_program_digest():
        raise NativeSourceCompilerError("source compiler base program does not match the packaged program")
    _verify_compiler(_NATIVE_PACKAGE / _COMPILER_NAME, manifest)
    runtime_manifest_path = _NATIVE_PACKAGE / "runtime-manifest.json"
    if not runtime_manifest_path.is_file() or runtime_manifest_path.is_symlink():
        raise NativeSourceCompilerError("packaged source compiler is missing its runtime manifest")
    runtime_manifest = _manifest(runtime_manifest_path)
    if runtime_manifest.get("schema") != "hol-guard-native-runtime.v1":
        raise NativeSourceCompilerError("packaged runtime manifest schema is unsupported")
    for field in ("package_version", "source_sha", "target", "platform_tag"):
        if runtime_manifest.get(field) != manifest.get(field):
            raise NativeSourceCompilerError(f"source compiler and runtime {field} differ")
    return manifest


def find_packaged_source_compiler() -> Path:
    """Return the verified compiler from the installed package resources."""
    if not _NATIVE_PACKAGE.is_dir() or _NATIVE_PACKAGE.is_symlink():
        raise NativeSourceCompilerError("packaged native resources are unavailable")
    _verify_manifest(_NATIVE_PACKAGE / _MANIFEST_NAME)
    return _NATIVE_PACKAGE / _COMPILER_NAME


def _canonical_request(request: Mapping[str, object]) -> bytes:
    if not isinstance(request, Mapping):
        raise NativeSourceCompilerError("compiler request must be an object")
    try:
        encoded = (
            json.dumps(
                dict(request), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise NativeSourceCompilerError("compiler request is not canonical JSON") from exc
    if len(encoded) > _MAX_INPUT_BYTES:
        raise NativeSourceCompilerError("compiler request exceeds the native input bound")
    return encoded


def _decode_output(
    stdout: bytes,
    *,
    returncode: int,
    stderr: bytes,
) -> dict[str, object]:
    if len(stdout) > _MAX_OUTPUT_BYTES:
        raise NativeSourceCompilerError("source compiler output exceeds the accepted bound", returncode=returncode)
    try:
        value = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        detail = stderr[:512].decode("utf-8", errors="replace")
        raise NativeSourceCompilerError(
            f"source compiler returned invalid JSON{(': ' + detail) if detail else ''}", returncode=returncode
        ) from exc
    if not isinstance(value, dict):
        raise NativeSourceCompilerError("source compiler response must be an object", returncode=returncode)
    if returncode != 0:
        code = value.get("code")
        pointer = value.get("pointer")
        raise NativeSourceCompilerError(
            f"source compiler rejected the request: {code or 'unknown'}",
            code=code if isinstance(code, str) else None,
            pointer=pointer if isinstance(pointer, str) else None,
            returncode=returncode,
        )
    return value


@contextmanager
def _verified_executable(raw: bytes):  # type: ignore[no-untyped-def]
    """Materialize exactly the verified bytes in a private execution directory."""
    with tempfile.TemporaryDirectory(prefix="hol-guard-source-compiler-") as directory:
        name = "guard-command-source.exe" if os.name == "nt" else "guard-command-source"
        path = Path(directory) / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags, 0o700)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if os.name != "nt":
            path.chmod(0o700)
        yield path


def _run_bounded(
    arguments: list[str],
    payload: bytes,
    *,
    timeout: float,
) -> tuple[int, bytes, bytes]:
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
        raise NativeSourceCompilerError("source compiler timeout must be positive and finite")
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except OSError as exc:
        raise NativeSourceCompilerError("source compiler could not be started") from exc
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    overflow = threading.Event()

    def drain(stream: BinaryIO | None, buffer: bytearray, limit: int) -> None:
        if stream is None:
            return
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            if len(buffer) + len(chunk) > limit:
                overflow.set()
                with suppress(OSError):
                    process.kill()
                return
            buffer.extend(chunk)

    stdout_thread = threading.Thread(target=drain, args=(process.stdout, stdout_buffer, _MAX_OUTPUT_BYTES), daemon=True)
    stderr_thread = threading.Thread(target=drain, args=(process.stderr, stderr_buffer, _MAX_STDERR_BYTES), daemon=True)

    def write_stdin() -> None:
        if process.stdin is None:
            return
        try:
            process.stdin.write(payload)
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    stdin_thread = threading.Thread(target=write_stdin, daemon=True)
    threads = (stdin_thread, stdout_thread, stderr_thread)
    for thread in threads:
        thread.start()
    try:
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            raise NativeSourceCompilerError("source compiler timed out") from exc
    finally:
        for thread in threads:
            thread.join(timeout=1.0)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        for thread in threads:
            thread.join()
    if overflow.is_set():
        raise NativeSourceCompilerError("source compiler output exceeds the accepted bound", returncode=returncode)
    return returncode, bytes(stdout_buffer), bytes(stderr_buffer)


def run_source_compiler(
    subcommand: str,
    request: Mapping[str, object] | None = None,
    *,
    digest: str | None = None,
    compiler: Path | None = None,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Run one native source-compiler operation using bounded JSON stdin."""
    if subcommand not in {"compile", "validate", "check", "test", "compare", "schema", "descriptor-schema"}:
        raise NativeSourceCompilerError("unsupported source compiler subcommand")
    if subcommand == "check":
        _hex(digest, length=_SHA64, field="program digest")
    elif digest is not None:
        raise NativeSourceCompilerError("digest is only valid for the check subcommand")
    if compiler is None and (
        configured_compiler := os.environ.get(_DEVELOPMENT_COMPILER_ENV) or os.environ.get(_TEST_COMPILER_ENV)
    ):
        # Installed authoring must not bypass its packaged identity checks through
        # either development or test environment configuration.
        if (_NATIVE_PACKAGE / _MANIFEST_NAME).is_file():
            raise NativeSourceCompilerError("compiler override is not permitted alongside a packaged compiler")
        compiler = Path(configured_compiler)
    manifest: Mapping[str, object] | None = None
    if compiler is None:
        manifest = _verify_manifest(_NATIVE_PACKAGE / _MANIFEST_NAME)
        compiler_bytes = _verify_compiler(_NATIVE_PACKAGE / _COMPILER_NAME, manifest)
    else:
        compiler_path = Path(compiler)
        compiler_bytes = _read_regular(compiler_path, limit=_MAX_COMPILER_BYTES, label="source compiler")
        compiler_bytes = _verify_compiler(
            compiler_path,
            {
                "compiler_size": len(compiler_bytes),
                "compiler_sha256": hashlib.sha256(compiler_bytes).hexdigest(),
            },
        )
    if subcommand in {"schema", "descriptor-schema"} and request is None:
        payload = b""
    else:
        payload = _canonical_request(request or {})
    with _verified_executable(compiler_bytes) as executable:
        arguments = [str(executable), subcommand]
        if subcommand == "check" and digest is not None:
            arguments.append(digest)
        returncode, stdout, stderr = _run_bounded(arguments, payload, timeout=timeout)
        result = _decode_output(stdout, returncode=returncode, stderr=stderr)
        binding_result = result
        build_request = request.get("build") if request is not None and subcommand in {"test", "compare"} else request
        if (
            manifest is not None
            and subcommand in {"validate", "check", "test", "compare"}
            and isinstance(build_request, Mapping)
            and build_request.get("base") == "packaged"
        ):
            # Compact validation/fixture responses omit the base digest. Obtain that
            # binding from the same verified executable and exact input, and
            # require both native operations to identify the same program.
            returncode, stdout, stderr = _run_bounded(
                [str(executable), "compile"], _canonical_request(build_request), timeout=timeout
            )
            binding_result = _decode_output(stdout, returncode=returncode, stderr=stderr)
            program = binding_result.get("program")
            result_digest = result.get("candidate_program_digest" if subcommand == "compare" else "program_digest")
            _hex(result_digest, length=_SHA64, field="program digest")
            if not isinstance(program, dict) or program.get("program_digest") != result_digest:
                raise NativeSourceCompilerError("source compiler validation and compilation identities differ")
    if manifest is not None and subcommand in {"compile", "validate", "check", "compare"}:
        if any(
            output.get("implementation_digest") != manifest.get("implementation_digest")
            for output in (result, binding_result)
        ):
            raise NativeSourceCompilerError("source compiler implementation identity does not match its manifest")
        if (
            isinstance(build_request, Mapping)
            and build_request.get("base") == "packaged"
            and binding_result.get("base_program_digest") != manifest.get("base_program_digest")
        ):
            raise NativeSourceCompilerError("source compiler base program identity does not match its manifest")
    if manifest is not None and subcommand == "test" and binding_result is not result:
        if binding_result.get("implementation_digest") != manifest.get("implementation_digest"):
            raise NativeSourceCompilerError("source compiler implementation identity does not match its manifest")
        if binding_result.get("base_program_digest") != manifest.get("base_program_digest"):
            raise NativeSourceCompilerError("source compiler base program identity does not match its manifest")
    return result


def compile_source(request: Mapping[str, object], *, compiler: Path | None = None) -> dict[str, object]:
    """Compile a complete ``guard.command-extension-build.v1`` request."""
    return run_source_compiler("compile", request, compiler=compiler)


def validate_source(request: Mapping[str, object], *, compiler: Path | None = None) -> dict[str, object]:
    """Validate a complete ``guard.command-extension-build.v1`` request."""
    return run_source_compiler("validate", request, compiler=compiler)


__all__ = [
    "NativeSourceCompilerError",
    "compile_source",
    "find_packaged_source_compiler",
    "run_source_compiler",
    "validate_source",
]
