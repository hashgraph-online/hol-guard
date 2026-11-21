"""Package execution context build through the native resident.

The resident reads the repository, executable, dependency and configuration
inputs the context covers and returns every component digest. Python only sends
the request facts (workspace, artifact metadata, executable, environment) and
the process facts it used to read implicitly (working directory, home directory
and ambient ``PATH``). Nothing here recomputes a digest: when no answer bound to
the exact request comes back, the build fails closed with ``ValueError``.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, cast
from uuid import uuid4

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_resident_client import native_resident_client_failure_code
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

PACKAGE_CONTEXT_BUILD_FEATURE: Final = "package-context-build-v1"
_REQUEST_SCHEMA: Final = "guard-package-context-build-request.v1"
_RESULT_SCHEMA: Final = "guard-package-context-build-result.v1"
_TIMEOUT_SECONDS: Final = 30.0
# The resident accepts canonical requests up to 512 KiB; the envelope adds
# framing and ensure-ascii escaping on top, so leave generous headroom.
_MAX_REQUEST_BYTES: Final = 1024 * 1024
_STRING_KEYS: Final = ("package_manager", "package_executable")
_LIST_KEYS: Final = ("flags", "manifest_paths", "lockfile_paths")


def _metadata_facts(metadata: object) -> dict[str, object]:
    """Reduce artifact metadata to the typed keys the build reads.

    Every key is always present so the canonical request digest matches the one
    the resident computes over its typed request.
    """

    source = metadata if isinstance(metadata, dict) else {}
    facts: dict[str, object] = {}
    for key in _STRING_KEYS:
        value = source.get(key)
        facts[key] = value if isinstance(value, str) else None
    for key in _LIST_KEYS:
        value = source.get(key)
        facts[key] = [item for item in value if isinstance(item, str)] if isinstance(value, list | tuple) else []
    return facts


def _environment_facts(environment: Mapping[str, str] | None) -> dict[str, str]:
    values = dict(os.environ if environment is None else environment)
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in values.items()):
        raise ValueError("native_package_context_build_invalid_environment")
    return values


def _well_formed_context(context: object) -> bool:
    if not isinstance(context, dict):
        return False
    reason = context.get("non_portable_reason")
    components = context.get("components")
    return (
        isinstance(context.get("digest"), str)
        and isinstance(context.get("portable"), bool)
        and (reason is None or isinstance(reason, str))
        and isinstance(components, list)
        and all(
            isinstance(item, dict) and isinstance(item.get("name"), str) and isinstance(item.get("digest"), str)
            for item in components
        )
    )


def native_build_package_context(
    *,
    workspace_dir: Path,
    metadata: object,
    executable: str | None,
    executable_args: Sequence[str],
    environment: Mapping[str, str] | None,
) -> dict[str, object]:
    """Build the context in the resident; raise ``ValueError`` when it cannot."""

    guard_home = _resolve_digest_home(None)
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"package-context-build-{uuid4().hex}",
        "guard_home": str(guard_home),
        "workspace_dir": str(workspace_dir),
        "metadata": _metadata_facts(metadata),
        "executable": executable,
        "executable_args": [str(item) for item in executable_args],
        "environment": _environment_facts(environment),
        "process_cwd": os.getcwd(),
        "process_home": str(Path.home()),
        "process_home_env": os.environ.get("HOME"),
        "process_path": os.environ.get("PATH"),
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError) as error:
        raise ValueError("native_package_context_build_unrepresentable") from error
    try:
        # The resident parses strict UTF-8 JSON; an unpaired surrogate (POSIX
        # surrogateescape in an environment value or path) cannot be carried.
        json.dumps(request, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("native_package_context_build_non_utf8") from error
    if not ensure_resident_prerequisite(guard_home):
        raise ValueError("native_package_context_build_unavailable")
    status = native_runtime_status()
    response = _resident_request(
        operation="package_context_build",
        request=request,
        guard_home=guard_home,
        timeout_seconds=_TIMEOUT_SECONDS,
        required_feature=PACKAGE_CONTEXT_BUILD_FEATURE,
        response_schema=_RESULT_SCHEMA,
        max_request_bytes=_MAX_REQUEST_BYTES,
        record_success=False,
        status=status,
    )
    if response is None:
        raise ValueError(native_resident_client_failure_code() or "native_package_context_build_unavailable")
    identity = status.identity
    if identity is None:
        raise ValueError("native_package_context_build_unavailable")

    def reject(code: str) -> ValueError:
        native_record_resident_failure(identity.sha256, guard_home, reason=code)
        return ValueError(code)

    if (
        response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        raise reject("native_package_context_build_unbound")
    if response.get("status") != "ok" or response.get("code") != "ok":
        code = response.get("code")
        native_record_resident_success(identity.sha256, guard_home)
        raise ValueError(code if isinstance(code, str) else "native_package_context_build_failed")
    context = response.get("context")
    if not _well_formed_context(context):
        raise reject("native_package_context_build_malformed")
    native_record_resident_success(identity.sha256, guard_home)
    return cast(dict[str, object], context)
