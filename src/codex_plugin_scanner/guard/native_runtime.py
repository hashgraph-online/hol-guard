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
from .runtime.hook_review_types import HookReviewRequest, HookReviewResponse

NativeMode = Literal["off", "shadow", "auto", "force"]
_NATIVE_PROTOCOL_VERSION = 1
_NATIVE_BINARY_ENV = "HOL_GUARD_NATIVE_BINARY"
_NATIVE_MODE_ENV = "HOL_GUARD_NATIVE"
_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


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
class NativeRuntimeStatus:
    mode: NativeMode
    available: bool
    compatible: bool
    reason: str
    identity: NativeRuntimeIdentity | None = None
    capabilities: NativeRuntimeCapabilities | None = None


def native_mode() -> NativeMode:
    value = os.environ.get(_NATIVE_MODE_ENV, "off").strip().lower()
    if value not in {"off", "shadow", "auto", "force"}:
        return "off"
    return cast(NativeMode, value)


def _bundled_runtime_candidate() -> Path:
    executable = "hol-guard-runtime.exe" if os.name == "nt" else "hol-guard-runtime"
    package_root = Path(__file__).resolve().parents[1]
    return package_root / "_native" / executable


def _runtime_candidates() -> tuple[Path, ...]:
    candidates: list[Path] = []
    override = os.environ.get(_NATIVE_BINARY_ENV)
    if override and native_mode() in {"shadow", "force"}:
        candidate = Path(override).expanduser()
        if candidate.is_absolute():
            candidates.append(candidate)

    candidates.append(_bundled_runtime_candidate())

    # Developer compatibility: a separately installed runtime distribution
    # may be used for shadow/force validation. Production packaging bundles
    # the binary inside the hol-guard wheel and does not require this project.
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
def _capabilities_for_identity(path: str, size: int, mtime_ns: int, sha256: str) -> NativeRuntimeCapabilities | None:
    del size, mtime_ns, sha256
    output = _run_native_process(Path(path), ("capabilities", "--json"), input_text="", timeout_seconds=1.0)
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
        return NativeRuntimeStatus(mode=mode, available=False, compatible=False, reason="native_disabled")
    for candidate in _runtime_candidates():
        identity = _validate_binary(candidate)
        if identity is None:
            continue
        capabilities = _capabilities_for_identity(str(identity.path), identity.size, identity.mtime_ns, identity.sha256)
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
    return NativeRuntimeStatus(mode=mode, available=False, compatible=False, reason="native_unavailable")


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
        reviewed_output_sha256=reviewed_output_sha256 if isinstance(reviewed_output_sha256, str) else None,
        reviewed_excerpt=reviewed_excerpt if isinstance(reviewed_excerpt, str) else None,
        notice=notice,
        reason_code=reason_code,
        policy_action=policy_action if isinstance(policy_action, str) else None,
        observed_policy_action=observed_policy_action if isinstance(observed_policy_action, str) else None,
        observe_mode=payload.get("observe_mode") is True,
    )


def _deadline_budget_ms(request: HookReviewRequest) -> int:
    if request.deadline_monotonic is None:
        return 750
    return max(1, min(9_000, int((request.deadline_monotonic - time.monotonic()) * 1000)))


def review_post_tool_native(request: HookReviewRequest, *, observe_mode: bool) -> HookReviewResponse | None:
    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
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
        "deadline_budget_ms": _deadline_budget_ms(request),
    }
    input_text = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)
    if len(input_text.encode("utf-8")) > _MAX_REQUEST_BYTES:
        return None
    timeout_seconds = max(0.05, min(9.0, _deadline_budget_ms(request) / 1000.0))
    output = _run_native_process(
        status.identity.path,
        ("hook", "--stdin"),
        input_text=input_text,
        timeout_seconds=timeout_seconds,
    )
    if output is None:
        return None
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return None
    return _response_from_payload(payload)


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


def choose_post_tool_response(
    request: HookReviewRequest,
    *,
    python_response: HookReviewResponse,
    observe_mode: bool,
) -> HookReviewResponse:
    mode = native_mode()
    if mode == "off":
        return python_response
    native_response = review_post_tool_native(request, observe_mode=observe_mode)
    if mode == "shadow" or native_response is None:
        return python_response
    return native_response


__all__ = [
    "NativeRuntimeCapabilities",
    "NativeRuntimeIdentity",
    "NativeRuntimeStatus",
    "choose_post_tool_response",
    "native_mode",
    "native_runtime_status",
    "parity_signature",
    "review_post_tool_native",
]
