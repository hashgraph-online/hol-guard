"""Trusted bridge from the Python control plane to the native Guard runtime.

The public package remains Python. This is the only PATH-free local entry
to ``hol-guard-runtime``; it never downloads a binary or sends hook material.
"""

from __future__ import annotations

import importlib.metadata
import json
import math
import os
import stat
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path

from .codex_hook_launch_runtime import run_isolated_hook_process
from .native_binary_identity import validate_native_binary as _validate_binary
from .native_resident_client import native_resident_client_request
from .native_response_decoder import native_error as _native_error
from .native_response_decoder import response_from_payload as _response_from_payload
from .native_route_receipt import record_native_hook_result
from .native_runtime_resilience import (
    NativeRuntimeHealthSnapshot,
    native_record_integrity_failure,
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
    native_runtime_health_snapshot,
)
from .native_runtime_values import (
    _INTEGRITY_FAILURE_REASONS,
    NativeMode,
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeManifest,
    NativeRuntimeStatus,
    _decode_capabilities,
    _identity_key,
    _is_lower_hex,
    _python_package_version,
    _resolve_native_mode,
    decode_runtime_manifest,
    native_output_sha256,  # noqa: F401
    parity_signature,  # noqa: F401
)
from .native_runtime_values import _NATIVE_RUNTIME_EXPORTS as __all__  # noqa: F401, N811
from .runtime.hook_review_types import HookReviewRequest, HookReviewResponse

_NATIVE_PROTOCOL_VERSION = 1
_NATIVE_BINARY_ENV = "HOL_GUARD_NATIVE_BINARY"
_NATIVE_MODE_ENV = "HOL_GUARD_NATIVE"
_DEFAULT_NATIVE_MODE: NativeMode = "auto"
_NATIVE_MANIFEST_NAME = "runtime-manifest.json"
_NATIVE_MANIFEST_SCHEMA = "hol-guard-native-runtime.v1"
_MAX_MANIFEST_BYTES = 16 * 1024
_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"


def native_mode() -> NativeMode:
    return _resolve_native_mode(os.environ.get(_NATIVE_MODE_ENV), _DEFAULT_NATIVE_MODE)


def _bundled_runtime_candidate() -> Path:
    executable = "hol-guard-runtime.exe" if os.name == "nt" else "hol-guard-runtime"
    package_root = Path(__file__).resolve().parents[1]
    return package_root / "_native" / executable


def _runtime_candidates() -> tuple[Path, ...]:
    mode = native_mode()
    candidates: list[Path] = []
    override = os.environ.get(_NATIVE_BINARY_ENV)
    if override and mode in {"shadow", "force"}:
        candidate = Path(override).expanduser()
        if candidate.is_absolute():
            candidates.append(candidate)

    candidates.append(_bundled_runtime_candidate())

    # Developer compatibility: a separately installed runtime distribution is
    # validation-only. Automatic production selection must use the runtime
    # bundled inside the version-matched hol-guard wheel and its manifest.
    if mode in {"shadow", "force"}:
        try:
            distribution = importlib.metadata.distribution("hol-guard-runtime")
        except importlib.metadata.PackageNotFoundError:
            distribution = None
        if distribution is not None:
            executable_names = {"hol-guard-runtime", "hol-guard-runtime.exe"}
            for entry in distribution.files or ():
                if Path(str(entry)).name not in executable_names:
                    continue
                candidates.append(Path(str(distribution.locate_file(entry))))

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key not in seen:
            unique.append(candidate)
            seen.add(key)
    return tuple(unique)


def _decode_runtime_manifest(payload: object) -> NativeRuntimeManifest | None:
    return decode_runtime_manifest(
        payload,
        schema=_NATIVE_MANIFEST_SCHEMA,
        protocol_version=_NATIVE_PROTOCOL_VERSION,
        hex_validator=_is_lower_hex,
    )


def _manifest_for_bundled_identity(
    identity: NativeRuntimeIdentity,
) -> tuple[NativeRuntimeManifest | None, str | None]:
    manifest_path = identity.path.with_name(_NATIVE_MANIFEST_NAME)
    try:
        metadata = manifest_path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return None, "native_manifest_invalid"
        if metadata.st_size <= 0 or metadata.st_size > _MAX_MANIFEST_BYTES:
            return None, "native_manifest_invalid"
        if os.name != "nt":
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                return None, "native_manifest_invalid"
            current_uid = os.getuid() if hasattr(os, "getuid") else None
            owner = getattr(metadata, "st_uid", current_uid)
            if current_uid is not None and owner not in {0, current_uid}:
                return None, "native_manifest_invalid"
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, "native_manifest_missing"
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, "native_manifest_invalid"
    manifest = _decode_runtime_manifest(payload)
    if manifest is None:
        return None, "native_manifest_invalid"
    if manifest.runtime_size != identity.size or manifest.runtime_sha256 != identity.sha256:
        return None, "native_manifest_runtime_mismatch"
    expected_version = _python_package_version()
    if expected_version is not None and manifest.package_version != expected_version:
        return None, "native_manifest_version_mismatch"
    return manifest, None


def _is_bundled_candidate(candidate: Path) -> bool:
    try:
        return candidate.expanduser().absolute() == _bundled_runtime_candidate().absolute()
    except (OSError, RuntimeError, ValueError):
        return False


def _restore_bundled_runtime_execute_bit(path: Path) -> None:
    """PyInstaller DATA extracts without owner execute; spawn still needs it."""
    if os.name == "nt" or not _is_bundled_candidate(path):
        return
    try:
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or mode & 0o022 or mode & stat.S_IXUSR:
            return
        current_uid = os.getuid() if hasattr(os, "getuid") else None
        owner = getattr(metadata, "st_uid", current_uid)
        if current_uid is not None and owner not in {0, current_uid}:
            return
        path.chmod(mode | 0o111)
    except (OSError, RuntimeError, ValueError):
        return


def _windows_native_dll_directories() -> list[str]:
    """Trusted directories for the Windows native runtime's CRT search.

    The published runtime links the Visual C++ CRT dynamically. Windows finds
    those DLLs in System32 when the redistributable is installed machine-wide.
    An x64 wheel on ARM, or a per-user Python install, often has the CRT only
    beside the base interpreter. The isolated environment cannot inherit the
    user PATH, so the loader otherwise fails with STATUS_DLL_NOT_FOUND.
    """

    roots: list[str] = []
    system_root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR")
    if system_root:
        roots.append(os.path.join(system_root, "System32"))
    base_prefix = getattr(sys, "base_prefix", "")
    if (
        isinstance(base_prefix, str)
        and base_prefix
        and any(os.path.isfile(os.path.join(base_prefix, name)) for name in ("vcruntime140.dll", "vcruntime140_1.dll"))
    ):
        roots.append(base_prefix)
    runtime_dir = _bundled_runtime_candidate().parent
    if runtime_dir.is_dir():
        roots.append(str(runtime_dir))
    unique: list[str] = []
    seen: set[str] = set()
    for root in roots:
        key = root.casefold()
        if key in seen:
            continue
        seen.add(key)
        unique.append(root)
    return unique


def _isolated_environment() -> dict[str, str]:
    allowed = {
        "COMSPEC",
        "HOME",
        "HOL_GUARD_NATIVE_DIAGNOSTIC",
        "LANG",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
    environment = {
        key: value for key, value in os.environ.items() if key.upper() in allowed or key.upper().startswith("LC_")
    }
    if os.name == "nt":
        dll_path = os.pathsep.join(_windows_native_dll_directories())
        if dll_path:
            environment["PATH"] = dll_path
    return environment


def _run_native_process(
    path: Path,
    args: tuple[str, ...],
    *,
    input_text: str,
    timeout_seconds: float,
) -> str | None:
    result = run_isolated_hook_process(
        (str(path), *args),
        input_text=input_text,
        cwd=path.parent,
        environment=_isolated_environment(),
        timeout_seconds=timeout_seconds,
        output_limit=_MAX_RESPONSE_BYTES,
    )
    if result.returncode != 0 or result.timed_out or result.output_limit_exceeded or result.containment_failed:
        return None
    return result.stdout


# Successful probes are cached per binary identity. Failures are not cached:
# they carry a short retry window so a transient cold-start miss cannot poison
# every later native check in the process, and a caller-supplied deadline caps
# how long the probe may run so a one-shot request never overspends its budget.
_capabilities_probe_lock = threading.Lock()
_capabilities_cache: dict[tuple[str, int, int, str], NativeRuntimeCapabilities] = {}
_capabilities_retry_after: dict[tuple[str, int, int, str], float] = {}
_CAPABILITIES_PROBE_TIMEOUT_SECONDS = 5.0
_CAPABILITIES_RETRY_BACKOFF_SECONDS = 0.25
_CAPABILITIES_CACHE_MAX = 16


def _clear_capabilities_probe_state() -> None:
    """Reset the probe cache and retry windows; tests call this between
    distinct fake binaries so a prior probe cannot leak into the next case."""
    with _capabilities_probe_lock:
        _capabilities_cache.clear()
        _capabilities_retry_after.clear()


def _capabilities_for_identity(
    path: str,
    size: int,
    mtime_ns: int,
    sha256: str,
    *,
    deadline_monotonic: float | None = None,
) -> NativeRuntimeCapabilities | None:
    key = (path, size, mtime_ns, sha256)
    now = time.monotonic()
    with _capabilities_probe_lock:
        cached = _capabilities_cache.get(key)
        retry_after = _capabilities_retry_after.get(key)
    if cached is not None:
        return cached
    if retry_after is not None and now < retry_after:
        return None
    timeout_seconds = _CAPABILITIES_PROBE_TIMEOUT_SECONDS
    if deadline_monotonic is not None:
        remaining = deadline_monotonic - now
        if remaining <= 0:
            # The caller's budget is already spent; starting a fresh probe
            # would overshoot the request deadline.
            return None
        timeout_seconds = min(timeout_seconds, remaining)
    output = _run_native_process(
        Path(path),
        ("capabilities", "--json"),
        input_text="",
        timeout_seconds=timeout_seconds,
    )
    capabilities = None
    if output is not None:
        try:
            capabilities = _decode_capabilities(json.loads(output))
        except json.JSONDecodeError:
            capabilities = None
    with _capabilities_probe_lock:
        if capabilities is not None:
            if len(_capabilities_cache) >= _CAPABILITIES_CACHE_MAX:
                _capabilities_cache.pop(next(iter(_capabilities_cache)))
            _capabilities_cache[key] = capabilities
            _capabilities_retry_after.pop(key, None)
        else:
            _capabilities_retry_after[key] = time.monotonic() + _CAPABILITIES_RETRY_BACKOFF_SECONDS
    return capabilities


def native_runtime_status(*, deadline_monotonic: float | None = None) -> NativeRuntimeStatus:
    mode = native_mode()
    if mode == "off":
        return NativeRuntimeStatus(
            mode=mode,
            available=False,
            compatible=False,
            reason="native_disabled",
        )
    for candidate in _runtime_candidates():
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            break
        _restore_bundled_runtime_execute_bit(candidate)
        identity = _validate_binary(candidate)
        if identity is None:
            continue
        manifest: NativeRuntimeManifest | None = None
        if _is_bundled_candidate(candidate):
            manifest, manifest_error = _manifest_for_bundled_identity(identity)
            if manifest_error is not None:
                return NativeRuntimeStatus(
                    mode=mode,
                    available=True,
                    compatible=False,
                    reason=manifest_error,
                    identity=identity,
                )
        capabilities = _capabilities_for_identity(
            str(identity.path),
            identity.size,
            identity.mtime_ns,
            identity.sha256,
            deadline_monotonic=deadline_monotonic,
        )
        if capabilities is None:
            continue
        if capabilities.protocol_version != _NATIVE_PROTOCOL_VERSION:
            return NativeRuntimeStatus(
                mode=mode,
                available=True,
                compatible=False,
                reason="native_protocol_mismatch",
                identity=identity,
                capabilities=capabilities,
                manifest=manifest,
            )
        if manifest is not None:
            if capabilities.protocol_version != manifest.protocol_version:
                reason = "native_manifest_protocol_mismatch"
            elif capabilities.runtime_version != manifest.package_version:
                reason = "native_manifest_version_mismatch"
            elif capabilities.rule_digest != manifest.rule_digest:
                reason = "native_manifest_rule_mismatch"
            elif capabilities.build_sha != manifest.source_sha:
                reason = "native_manifest_build_mismatch"
            else:
                reason = None
            if reason is not None:
                return NativeRuntimeStatus(
                    mode=mode,
                    available=True,
                    compatible=False,
                    reason=reason,
                    identity=identity,
                    capabilities=capabilities,
                    manifest=manifest,
                )
        expected_version = _python_package_version()
        version_compatible = expected_version is None or capabilities.runtime_version == expected_version
        compatible = version_compatible or mode in {"shadow", "force"}
        return NativeRuntimeStatus(
            mode=mode,
            available=True,
            compatible=compatible,
            reason="native_ready" if compatible else "native_version_mismatch",
            identity=identity,
            capabilities=capabilities,
            manifest=manifest,
        )
    return NativeRuntimeStatus(
        mode=mode,
        available=False,
        compatible=False,
        reason="native_unavailable",
    )


def _capture_native_deadline(request: HookReviewRequest) -> tuple[float, int]:
    """Capture one absolute native deadline and its bounded envelope budget."""
    now = time.monotonic()
    requested = request.deadline_monotonic
    deadline = requested if requested is not None and math.isfinite(requested) else now + 0.75
    budget_ms = max(1, min(9_000, int((deadline - now) * 1_000)))
    return deadline, budget_ms


def native_runtime_health(guard_home: Path) -> NativeRuntimeHealthSnapshot:
    status = native_runtime_status()
    return native_runtime_health_snapshot(_identity_key(status), guard_home)


def review_post_tool_native(
    request: HookReviewRequest,
    *,
    observe_mode: bool,
    policy_snapshot: Mapping[str, object] | None,
) -> HookReviewResponse | None:
    """Review PostToolUse through the native Rust client and resident.

    Native failure returns ``None`` so the caller fails closed without Python
    re-evaluation or a semantic one-shot fallback.
    """
    del observe_mode
    status = native_runtime_status()
    identity_key = _identity_key(status)
    if not status.available or not status.compatible or status.identity is None:
        if status.reason in _INTEGRITY_FAILURE_REASONS:
            native_record_integrity_failure(
                identity_key,
                request.guard_home,
                reason=status.reason,
            )
        return record_native_hook_result("native_fail_safe", None)

    deadline_monotonic, deadline_budget_ms = _capture_native_deadline(request)
    if policy_snapshot is None:
        return record_native_hook_result("native_fail_safe", None)
    generation = policy_snapshot.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
        return record_native_hook_result("native_fail_safe", None)
    envelope = {
        "schema": "guard-hook-envelope.v2",
        "request_id": request.request_id,
        "harness": request.harness,
        "event": request.event_name,
        "raw_payload": request.payload,
        "deadline_budget_ms": deadline_budget_ms,
        "policy_generation": generation,
        # The resident already authenticated and cached the full snapshot at
        # push/startup. Bind each request to that snapshot without copying
        # policy rules or re-running their integrity checks on the hot path.
        "policy_snapshot": {
            "generation": generation,
            "policy_digest": policy_snapshot.get("policy_digest"),
            "runtime_identity": policy_snapshot.get("runtime_identity"),
        },
        "source": {
            "cwd": str(request.cwd) if request.cwd is not None else None,
            "home_dir": str(request.home_dir),
            "guard_home": str(request.guard_home),
            "source_ref_external_allowed": request.source_ref_external_allowed,
        },
    }
    input_text = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)
    if len(encoded := input_text.encode("utf-8")) > _MAX_REQUEST_BYTES:
        return record_native_hook_result("native_fail_safe", None)
    resident_output = None
    if status.capabilities is not None and _RESIDENT_PROTOCOL_FEATURE in status.capabilities.features:
        resident_output = native_resident_client_request(
            executable=status.identity.path,
            guard_home=request.guard_home,
            environment=_isolated_environment(),
            payload=encoded,
            deadline_monotonic=deadline_monotonic,
        )
    if resident_output is not None:
        try:
            resident_payload = json.loads(resident_output)
        except (UnicodeDecodeError, json.JSONDecodeError):
            resident_payload = None
        resident_error = _native_error(resident_payload)
        if resident_error == "native_overloaded":
            native_record_overload(status.identity.sha256, request.guard_home)
            return record_native_hook_result("native_fail_safe", None)
        response = _response_from_payload(resident_payload)
        if response is not None:
            native_record_resident_success(status.identity.sha256, request.guard_home)
            return record_native_hook_result("native_resident", response)
        failure_reason = resident_error or "native_resident_invalid_response"
    else:
        failure_reason = (
            "native_resident_unavailable"
            if status.capabilities is not None and _RESIDENT_PROTOCOL_FEATURE in status.capabilities.features
            else "native_resident_protocol_unsupported"
        )

    native_record_resident_failure(
        status.identity.sha256,
        request.guard_home,
        reason=failure_reason,
    )
    return record_native_hook_result("native_fail_safe", None)
