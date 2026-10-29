"""Mechanical transport adapter for contained HTTP content decoding.

A managed fetch reads the raw body without letting any HTTP stack decompress
it (``native_archive_acquisition.fetch_managed_content_raw``). This module
hands that body and its ``Content-Encoding`` values to
``hol-guard-runtime content-decode --stdin``. The Rust worker owns every
decision: it refuses unsupported or over-deep codings before a decoder
exists, and decodes the rest only after its containment is applied and
proven. Python never decodes, never parses codings, and never returns the
raw body as decoded content. The worker gets a minimal environment, no
credentials and no destination; its decoded output is still untrusted.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
import secrets
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .codex_hook_launch_runtime import run_isolated_hook_process
from .native_archive_acquisition import MANAGED_CONTENT_MAX_RAW_BYTES, fetch_managed_content_raw
from .native_runtime import native_runtime_status
from .runtime.restricted_archive_contract import RestrictedArchiveFailure

ContentDecodeStatus = Literal["decoded", "rejected", "incomplete"]

_REQUEST_SCHEMA = "guard-content-decode.v1"
_RESULT_SCHEMA = "guard-content-decode-result.v1"
_NATIVE_FEATURE = "content-decode-v1"
_MAX_CODE_CHARS = 128
_MAX_MESSAGE_CHARS = 512
_MAX_COUNTER = 2**62
_MAX_HEADER_VALUES = 8
_RESULT_KEYS = frozenset(
    {"schema", "request_id", "request_sha256", "status", "code", "message", "runtime_sha256", "counters"}
)
_BODY_KEYS = frozenset({"body_base64", "body_sha256"})
_COUNTER_KEYS = frozenset({"decoder_calls", "input_bytes", "output_bytes", "layers", "elapsed_ms"})
_HEX_64_RE = re.compile(r"[0-9a-f]{64}")
_STATUSES: dict[str, ContentDecodeStatus] = {"decoded": "decoded", "rejected": "rejected", "incomplete": "incomplete"}
_RESULT_ENVELOPE_BYTES = 8 * 1024
# Fetch outcomes that are a verdict on the response, not a transport fault.
_FETCH_REFUSALS = frozenset(
    {
        "content_coding_unsupported",
        "content_coding_too_deep",
        "external_archive_download_size_limit",
        "external_archive_destination_rejected",
        "external_archive_redirect_rejected",
        "external_archive_redirect_limit",
        "external_archive_dns_rebinding",
    }
)

# Runtime ceilings: input 3 MiB, output 32 MiB, ratio 1000, 4 layers,
# 1 GiB memory, 30 s. Defaults stay well inside them.
_DEFAULT_TIMEOUT_SECONDS = 5.0
_DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_DEFAULT_MAX_RATIO = 200
_DEFAULT_MAX_LAYERS = 2
_DEFAULT_MAX_MEMORY_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ContentDecodeCounters:
    decoder_calls: int = 0
    input_bytes: int = 0
    output_bytes: int = 0
    layers: int = 0


@dataclass(frozen=True, slots=True)
class ManagedContentResult:
    """One typed outcome. ``body`` is set only when ``status`` is ``decoded``
    and is untrusted content, never instructions."""

    status: ContentDecodeStatus
    code: str
    message: str
    body: bytes | None = None
    counters: ContentDecodeCounters | None = None
    final_url: str | None = None


def _incomplete(code: str, message: str) -> ManagedContentResult:
    return ManagedContentResult("incomplete", code, message)


def _invalid_result() -> ManagedContentResult:
    return _incomplete("content_decode_incomplete", "The contained content decoder returned an invalid result.")


def _worker_environment() -> dict[str, str]:
    # Nothing from the caller's environment reaches the worker: no proxy
    # settings, tokens or home directories, only what the OS loader needs.
    environment = {"LC_ALL": "C"}
    for key in ("SYSTEMROOT", "WINDIR"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    return environment


def _counter(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAX_COUNTER


def decode_content_native(
    raw: bytes,
    content_encoding: Sequence[str],
    *,
    state_dir: Path,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    max_input_bytes: int = MANAGED_CONTENT_MAX_RAW_BYTES,
    max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
    max_ratio: int = _DEFAULT_MAX_RATIO,
    max_layers: int = _DEFAULT_MAX_LAYERS,
    max_memory_bytes: int = _DEFAULT_MAX_MEMORY_BYTES,
) -> ManagedContentResult:
    """Decode one raw response body in the contained native worker."""

    deadline_monotonic = time.monotonic() + timeout_seconds + 0.5
    if (
        not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or not 0 < max_input_bytes <= MANAGED_CONTENT_MAX_RAW_BYTES
        or max_output_bytes <= 0
        or max_ratio <= 0
        or max_layers <= 0
        or max_memory_bytes <= 0
        or len(content_encoding) > _MAX_HEADER_VALUES
        or not all(isinstance(value, str) for value in content_encoding)
    ):
        return _incomplete("content_decode_policy_invalid", "Content decode policy is invalid.")
    if len(raw) > max_input_bytes:
        # Refused before it is even handed to the worker.
        return ManagedContentResult(
            "rejected",
            "content_input_too_large",
            "The response body exceeds Guard's raw size limit.",
            counters=ContentDecodeCounters(input_bytes=len(raw)),
        )
    status = native_runtime_status(deadline_monotonic=deadline_monotonic)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _NATIVE_FEATURE not in status.capabilities.features
    ):
        return _incomplete("content_decode_native_unavailable", "Content decoding requires the Guard native runtime.")
    worker_budget = deadline_monotonic - time.monotonic() - 0.5
    if worker_budget <= 0:
        return _incomplete("content_decode_timeout", "Content decoding exceeded Guard's time limit.")
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        canonical_state_dir = state_dir.resolve(strict=True)
    except OSError:
        return _incomplete("content_decode_lease_failed", "The contained decode lease could not be established.")
    request = {
        "schema": _REQUEST_SCHEMA,
        "request_id": secrets.token_hex(16),
        "content_encoding": list(content_encoding),
        "body_base64": base64.b64encode(raw).decode("ascii"),
        "state_dir": str(canonical_state_dir),
        "timeout_ms": math.ceil(worker_budget * 1000),
        "caps": {
            "max_input_bytes": max_input_bytes,
            "max_output_bytes": max_output_bytes,
            "max_ratio": max_ratio,
            "max_layers": max_layers,
            "max_memory_bytes": max_memory_bytes,
        },
    }
    request_bytes = json.dumps(request, separators=(",", ":"), sort_keys=True).encode("ascii")
    request_digest = hashlib.sha256(request_bytes).hexdigest()
    result_limit = 4 * math.ceil(max_output_bytes / 3) + _RESULT_ENVELOPE_BYTES
    completed = run_isolated_hook_process(
        [str(status.identity.path), "content-decode", "--stdin"],
        input_text=request_bytes.decode("ascii"),
        cwd=canonical_state_dir,
        environment=_worker_environment(),
        deadline_monotonic=deadline_monotonic,
        output_limit=result_limit + 1024,
        parent_liveness=True,
    )
    if completed.timed_out:
        return _incomplete("content_decode_timeout", "Content decoding exceeded Guard's time limit.")
    if (
        completed.returncode != 0
        or completed.output_limit_exceeded
        or completed.containment_failed
        or len(completed.stdout) > result_limit
    ):
        return _incomplete("content_decode_incomplete", "The contained content decoder did not complete.")
    try:
        payload = json.loads(completed.stdout.strip())
    except (TypeError, ValueError):
        return _invalid_result()
    if not isinstance(payload, dict):
        return _invalid_result()
    status_value = payload.get("status")
    result_status = _STATUSES.get(status_value) if isinstance(status_value, str) else None
    keys = frozenset(payload)
    counters = payload.get("counters")
    code = payload.get("code")
    message = payload.get("message")
    runtime_sha256 = payload.get("runtime_sha256")
    if (
        result_status is None
        or keys != (_RESULT_KEYS | _BODY_KEYS if result_status == "decoded" else _RESULT_KEYS)
        or payload["schema"] != _RESULT_SCHEMA
        or payload["request_id"] != request["request_id"]
        or payload["request_sha256"] != request_digest
        or not isinstance(code, str)
        or not 0 < len(code) <= _MAX_CODE_CHARS
        or not isinstance(message, str)
        or not 0 < len(message) <= _MAX_MESSAGE_CHARS
        or not isinstance(runtime_sha256, str)
        or not _HEX_64_RE.fullmatch(runtime_sha256)
        or runtime_sha256 != status.identity.sha256
        or not isinstance(counters, dict)
        or frozenset(counters) != _COUNTER_KEYS
        or not all(_counter(value) for value in counters.values())
    ):
        return _invalid_result()
    decode_counters = ContentDecodeCounters(
        decoder_calls=counters["decoder_calls"],
        input_bytes=counters["input_bytes"],
        output_bytes=counters["output_bytes"],
        layers=counters["layers"],
    )
    if result_status != "decoded":
        return ManagedContentResult(result_status, code, message, counters=decode_counters)
    body_base64 = payload["body_base64"]
    body_sha256 = payload["body_sha256"]
    if not isinstance(body_base64, str) or not isinstance(body_sha256, str):
        return _invalid_result()
    try:
        body = base64.b64decode(body_base64.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error):
        return _invalid_result()
    if (
        len(body) > max_output_bytes
        or len(body) != decode_counters.output_bytes
        or hashlib.sha256(body).hexdigest() != body_sha256
    ):
        return _invalid_result()
    return ManagedContentResult("decoded", code, message, body=body, counters=decode_counters)


def fetch_managed_content(
    source_url: str,
    *,
    state_dir: Path,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    max_raw_bytes: int = MANAGED_CONTENT_MAX_RAW_BYTES,
    max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
    max_redirects: int = 4,
) -> ManagedContentResult:
    """Fetch one public HTTPS document and decode it in containment.

    For Guard's own managed fetches only, never arbitrary application HTTP.
    The fetch carries no credentials and the decoder never sees a destination.
    """

    started = time.monotonic()
    raw = fetch_managed_content_raw(
        source_url, max_bytes=max_raw_bytes, max_redirects=max_redirects, timeout_seconds=timeout_seconds
    )
    if isinstance(raw, RestrictedArchiveFailure):
        status: ContentDecodeStatus = "rejected" if raw.code in _FETCH_REFUSALS else "incomplete"
        return ManagedContentResult(status, raw.code, raw.message)
    remaining = timeout_seconds - (time.monotonic() - started)
    if remaining <= 0:
        return _incomplete("content_decode_timeout", "Content decoding exceeded Guard's time limit.")
    decoded = decode_content_native(
        raw.body,
        raw.content_encoding,
        state_dir=state_dir,
        timeout_seconds=remaining,
        max_input_bytes=max_raw_bytes,
        max_output_bytes=max_output_bytes,
    )
    return ManagedContentResult(
        decoded.status,
        decoded.code,
        decoded.message,
        body=decoded.body,
        counters=decoded.counters,
        final_url=raw.final_url,
    )


__all__ = [
    "ContentDecodeCounters",
    "ManagedContentResult",
    "decode_content_native",
    "fetch_managed_content",
]
