"""Trusted bridge from the Python control plane to the native Guard runtime.

The public package remains Python. This module is the only Python entry point
for discovering and invoking ``hol-guard-runtime``. It never searches PATH,
never downloads a binary, and never sends hook material to a network service.
"""

from __future__ import annotations

import functools
import hashlib
import importlib.metadata
import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from .codex_hook_launch_runtime import run_isolated_hook_process
from .native_runtime_resident import resident_native_request
from .native_runtime_resilience import (
    NativeRuntimeHealthSnapshot,
    native_oneshot_lease,
    native_record_integrity_failure,
    native_record_oneshot_failure,
    native_record_oneshot_success,
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
    native_runtime_health_snapshot,
)
from .runtime.hook_review_types import HookReviewRequest, HookReviewResponse

NativeMode = Literal["off", "shadow", "auto", "force"]
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
_UNAVAILABLE_IDENTITY = "0" * 64
_INTEGRITY_FAILURE_REASONS = frozenset(
    {
        "native_manifest_invalid",
        "native_manifest_missing",
        "native_manifest_runtime_mismatch",
        "native_manifest_version_mismatch",
        "native_manifest_protocol_mismatch",
        "native_manifest_rule_mismatch",
        "native_manifest_build_mismatch",
    }
)
_NATIVE_ERROR_CODES = frozenset(
    {
        "native_overloaded",
        "native_frame_read_failed",
        "native_request_digest_mismatch",
        "native_request_invalid_json",
        "native_request_too_large",
        "native_response_encode_failed",
        "native_runtime_panicked",
    }
)


@dataclass(frozen=True, slots=True)
class NativeRuntimeIdentity:
    path: Path
    size: int
    mtime_ns: int
    sha256: str


@dataclass(frozen=True, slots=True)
class NativeRuntimeCapabilities:
    protocol_version: int
    runtime_version: str
    rule_digest: str
    build_sha: str
    target: str
    features: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NativeRuntimeManifest:
    schema: str
    protocol_version: int
    package_version: str
    target: str
    platform_tag: str
    source_sha: str
    rule_digest: str
    runtime_sha256: str
    runtime_size: int


@dataclass(frozen=True, slots=True)
class NativeRuntimeStatus:
    mode: NativeMode
    available: bool
    compatible: bool
    reason: str
    identity: NativeRuntimeIdentity | None = None
    capabilities: NativeRuntimeCapabilities | None = None


def native_mode() -> NativeMode:
    """Return the configured native mode, defaulting to bundled auto selection.

    Explicit ``off`` remains the emergency rollback. Invalid or empty values do
    not silently disable the native safety path; they resolve to the product
    default and still retain Python fallback when native is unavailable.
    """

    raw_value = os.environ.get(_NATIVE_MODE_ENV)
    if raw_value is None:
        return _DEFAULT_NATIVE_MODE
    value = raw_value.strip().lower()
    if value not in {"off", "shadow", "auto", "force"}:
        return _DEFAULT_NATIVE_MODE
    return cast(NativeMode, value)


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


def _validate_binary(path: Path) -> NativeRuntimeIdentity | None:
    try:
        lexical = path.expanduser()
        metadata = lexical.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return None
        if os.name != "nt":
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                return None
            current_uid = os.getuid() if hasattr(os, "getuid") else None
            owner = getattr(metadata, "st_uid", current_uid)
            if current_uid is not None and owner not in {0, current_uid}:
                return None
        resolved = lexical.resolve(strict=True)
        resolved_metadata = resolved.stat()
        if metadata.st_size != resolved_metadata.st_size:
            return None
        digest = hashlib.sha256()
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return NativeRuntimeIdentity(
            path=resolved,
            size=resolved_metadata.st_size,
            mtime_ns=resolved_metadata.st_mtime_ns,
            sha256=digest.hexdigest(),
        )
    except (OSError, RuntimeError, ValueError):
        return None


def _is_lower_hex(value: str, length: int) -> bool:
    return len(value) == length and all(character in "0123456789abcdef" for character in value)


def _decode_runtime_manifest(payload: object) -> NativeRuntimeManifest | None:
    if not isinstance(payload, dict):
        return None
    schema = payload.get("schema")
    protocol_version = payload.get("protocol_version")
    package_version = payload.get("package_version")
    target = payload.get("target")
    platform_tag = payload.get("platform_tag")
    source_sha = payload.get("source_sha")
    rule_digest = payload.get("rule_digest")
    runtime_sha256 = payload.get("runtime_sha256")
    runtime_size = payload.get("runtime_size")
    if (
        schema != _NATIVE_MANIFEST_SCHEMA
        or protocol_version != _NATIVE_PROTOCOL_VERSION
        or not isinstance(package_version, str)
        or not package_version.strip()
        or not isinstance(target, str)
        or not target.strip()
        or not isinstance(platform_tag, str)
        or not platform_tag.strip()
        or not isinstance(source_sha, str)
        or not _is_lower_hex(source_sha, 40)
        or not isinstance(rule_digest, str)
        or not _is_lower_hex(rule_digest, 64)
        or not isinstance(runtime_sha256, str)
        or not _is_lower_hex(runtime_sha256, 64)
        or not isinstance(runtime_size, int)
        or isinstance(runtime_size, bool)
        or runtime_size <= 0
    ):
        return None
    return NativeRuntimeManifest(
        schema=schema,
        protocol_version=protocol_version,
        package_version=package_version,
        target=target,
        platform_tag=platform_tag,
        source_sha=source_sha,
        rule_digest=rule_digest,
        runtime_sha256=runtime_sha256,
        runtime_size=runtime_size,
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


def _isolated_environment() -> dict[str, str]:
    allowed = {
        "COMSPEC",
        "HOME",
        "LANG",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
    return {key: value for key, value in os.environ.items() if key.upper() in allowed or key.upper().startswith("LC_")}


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


def _decode_capabilities(payload: object) -> NativeRuntimeCapabilities | None:
    if not isinstance(payload, dict):
        return None
    protocol_version = payload.get("protocol_version")
    runtime_version = payload.get("runtime_version")
    rule_digest = payload.get("rule_digest")
    build_sha = payload.get("build_sha")
    target = payload.get("target")
    features = payload.get("features")
    if (
        not isinstance(protocol_version, int)
        or not isinstance(runtime_version, str)
        or not isinstance(rule_digest, str)
        or not isinstance(build_sha, str)
        or not isinstance(target, str)
        or not isinstance(features, list)
        or not all(isinstance(feature, str) for feature in features)
    ):
        return None
    return NativeRuntimeCapabilities(
        protocol_version=protocol_version,
        runtime_version=runtime_version,
        rule_digest=rule_digest,
        build_sha=build_sha,
        target=target,
        features=tuple(features),
    )


@functools.lru_cache(maxsize=16)
def _capabilities_for_identity(
    path: str,
    size: int,
    mtime_ns: int,
    sha256: str,
) -> NativeRuntimeCapabilities | None:
    del size, mtime_ns, sha256
    output = _run_native_process(
        Path(path),
        ("capabilities", "--json"),
        input_text="",
        timeout_seconds=1.0,
    )
    if output is None:
        return None
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return None
    return _decode_capabilities(payload)


def _python_package_version() -> str | None:
    try:
        return importlib.metadata.version("hol-guard")
    except importlib.metadata.PackageNotFoundError:
        return None


def native_runtime_status() -> NativeRuntimeStatus:
    mode = native_mode()
    if mode == "off":
        return NativeRuntimeStatus(
            mode=mode,
            available=False,
            compatible=False,
            reason="native_disabled",
        )
    for candidate in _runtime_candidates():
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
        )
    return NativeRuntimeStatus(
        mode=mode,
        available=False,
        compatible=False,
        reason="native_unavailable",
    )


def _response_from_payload(payload: object) -> HookReviewResponse | None:
    if not isinstance(payload, dict):
        return None
    decision = payload.get("decision")
    model_output_action = payload.get("model_output_action")
    notice = payload.get("notice")
    reason_code = payload.get("reason_code")
    if decision not in {"allow", "deny"}:
        return None
    if model_output_action not in {
        "allow_original",
        "replace_with_reviewed_excerpt",
        "block",
        "not_applicable",
    }:
        return None
    if notice not in {"none", "excerpt", "warning"} or not isinstance(reason_code, str):
        return None
    reason = payload.get("reason")
    reviewed_output_sha256 = payload.get("reviewed_output_sha256")
    reviewed_excerpt = payload.get("reviewed_excerpt")
    policy_action = payload.get("policy_action")
    observed_policy_action = payload.get("observed_policy_action")
    return HookReviewResponse(
        decision=decision,
        reason=reason if isinstance(reason, str) else None,
        model_output_action=model_output_action,
        reviewed_output_sha256=(reviewed_output_sha256 if isinstance(reviewed_output_sha256, str) else None),
        reviewed_excerpt=(reviewed_excerpt if isinstance(reviewed_excerpt, str) else None),
        notice=notice,
        reason_code=reason_code,
        policy_action=policy_action if isinstance(policy_action, str) else None,
        observed_policy_action=(observed_policy_action if isinstance(observed_policy_action, str) else None),
        observe_mode=payload.get("observe_mode") is True,
    )


def _native_error(payload: object) -> str | None:
    if not isinstance(payload, dict) or set(payload) - {"error", "retryable"}:
        return None
    error = payload.get("error")
    if not isinstance(error, str) or error not in _NATIVE_ERROR_CODES:
        return None
    retryable = payload.get("retryable")
    if retryable is not None and not isinstance(retryable, bool):
        return None
    return error


def _deadline_budget_ms(request: HookReviewRequest) -> int:
    if request.deadline_monotonic is None:
        return 750
    return max(
        1,
        min(9_000, int((request.deadline_monotonic - time.monotonic()) * 1_000)),
    )


def _identity_key(status: NativeRuntimeStatus) -> str:
    return status.identity.sha256 if status.identity is not None else _UNAVAILABLE_IDENTITY


def native_resident_operation(
    *,
    operation: str,
    request: object,
    guard_home: Path,
    timeout_seconds: float = 1.0,
) -> dict[str, object] | None:
    """Send one bounded authenticated control-plane operation to Rust."""

    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
    ):
        return None
    envelope = {"operation": operation, "request": request}
    encoded = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > _MAX_REQUEST_BYTES:
        return None
    output = resident_native_request(
        executable=status.identity.path,
        identity_sha256=status.identity.sha256,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=encoded,
        timeout_seconds=max(0.05, min(9.0, timeout_seconds)),
    )
    if output is None:
        return None
    try:
        payload = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def native_runtime_health(guard_home: Path) -> NativeRuntimeHealthSnapshot:
    status = native_runtime_status()
    return native_runtime_health_snapshot(_identity_key(status), guard_home)


def review_post_tool_native(
    request: HookReviewRequest,
    *,
    observe_mode: bool,
    policy_snapshot_digest: str | None = None,
) -> HookReviewResponse | None:
    """Review PostToolUse with resident Rust, then one bounded Rust recovery.

    ``None`` means native authority could not complete. The caller must fail
    closed; it must never substitute a Python semantic evaluator. The one-shot
    path is globally bounded and is not used as overflow capacity after an
    explicit resident overload response.
    """

    status = native_runtime_status()
    identity_key = _identity_key(status)
    if not status.available or not status.compatible or status.identity is None:
        if status.reason in _INTEGRITY_FAILURE_REASONS:
            native_record_integrity_failure(
                identity_key,
                request.guard_home,
                reason=status.reason,
            )
        return None

    envelope = {
        "protocol_version": _NATIVE_PROTOCOL_VERSION,
        "request_id": request.request_id,
        "harness": request.harness,
        "event_name": request.event_name,
        "payload": request.payload,
        "cwd": str(request.cwd) if request.cwd is not None else None,
        "home_dir": str(request.home_dir),
        "guard_home": str(request.guard_home),
        "source_ref_external_allowed": request.source_ref_external_allowed,
        "observe_mode": observe_mode,
        "policy_snapshot_digest": policy_snapshot_digest,
        "deadline_budget_ms": _deadline_budget_ms(request),
    }
    input_text = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)
    encoded = input_text.encode("utf-8")
    if len(encoded) > _MAX_REQUEST_BYTES:
        return None
    timeout_seconds = max(
        0.05,
        min(9.0, _deadline_budget_ms(request) / 1_000.0),
    )

    resident_output = None
    if (
        policy_snapshot_digest is not None
        and status.capabilities is not None
        and _RESIDENT_PROTOCOL_FEATURE in status.capabilities.features
    ):
        resident_output = resident_native_request(
            executable=status.identity.path,
            identity_sha256=status.identity.sha256,
            guard_home=request.guard_home,
            environment=_isolated_environment(),
            payload=encoded,
            timeout_seconds=timeout_seconds,
        )
    if resident_output is not None:
        try:
            resident_payload = json.loads(resident_output)
        except (UnicodeDecodeError, json.JSONDecodeError):
            resident_payload = None
        resident_error = _native_error(resident_payload)
        if resident_error == "native_overloaded":
            native_record_overload(status.identity.sha256, request.guard_home)
            return None
        response = _response_from_payload(resident_payload)
        if response is not None:
            native_record_resident_success(status.identity.sha256, request.guard_home)
            return response
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
    with native_oneshot_lease(
        status.identity.sha256,
        request.guard_home,
    ) as acquired:
        if not acquired:
            return None
        output = _run_native_process(
            status.identity.path,
            ("hook", "--stdin"),
            input_text=input_text,
            timeout_seconds=timeout_seconds,
        )
        if output is None:
            native_record_oneshot_failure(
                status.identity.sha256,
                request.guard_home,
                reason="native_oneshot_failed",
            )
            return None
        try:
            oneshot_payload = json.loads(output)
        except json.JSONDecodeError:
            oneshot_payload = None
        response = _response_from_payload(oneshot_payload)
        if response is None:
            native_record_oneshot_failure(
                status.identity.sha256,
                request.guard_home,
                reason=_native_error(oneshot_payload) or "native_oneshot_invalid_response",
            )
            return None
        native_record_oneshot_success(status.identity.sha256, request.guard_home)
        return response


def parity_signature(response: HookReviewResponse) -> tuple[object, ...]:
    excerpt_hash = (
        hashlib.sha256(response.reviewed_excerpt.encode("utf-8")).hexdigest()
        if response.reviewed_excerpt is not None
        else None
    )
    return (
        response.decision,
        response.model_output_action,
        response.reason_code,
        response.notice,
        response.policy_action,
        response.observed_policy_action,
        response.reviewed_output_sha256,
        excerpt_hash,
    )


__all__ = [
    "NativeRuntimeCapabilities",
    "NativeRuntimeHealthSnapshot",
    "NativeRuntimeIdentity",
    "NativeRuntimeManifest",
    "NativeRuntimeStatus",
    "native_mode",
    "native_runtime_health",
    "native_runtime_status",
    "parity_signature",
    "review_post_tool_native",
]
