"""Refresh root-signed workspace-review enrollment outside hook execution."""

from __future__ import annotations

import json
import logging
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.error import HTTPError

from ..native_resident_client import native_resident_client_request
from ..native_runtime import _isolated_environment, _run_native_process, native_runtime_status
from .command_queue_protocol import command_api_url
from .exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION, exact_cloud_review_operations

if TYPE_CHECKING:
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)
_STATE_KEY = "guard_cloud_review_workspace_enrollment"
# The connection fields the native store builds the enrollment binding from.
_BINDING_FIELDS = ("workspace_id", "machine_installation_id", "sync_url", "oauth_subject_hash")
_MAX_RECORD_BYTES = 16 * 1024
_RESIDENT_ENROLLMENT_FEATURE = "native-workspace-review-enrollment-resident-v1"


def _fetch_authority(auth_context: dict[str, object]) -> bytes:
    url = command_api_url(
        auth_context["sync_url"],
        "/current",
        base_path="/api/guard/review/v2/authority",
    )
    from . import cloud_bundle_sync

    response = cloud_bundle_sync.cloud_json_request(
        auth_context,
        url=url,
        body=b'{"protocolVersion":2}',
        timeout_seconds=5,
        retry_timeout_seconds=5,
    )
    if set(response) != {"authority", "protocolVersion"} or response["protocolVersion"] != 2:
        raise ValueError("native_workspace_review_authority_response_invalid")
    record = response["authority"]
    if not isinstance(record, dict):
        raise ValueError("native_workspace_review_authority_response_invalid")
    encoded = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(encoded) > _MAX_RECORD_BYTES:
        raise ValueError("native_workspace_review_authority_response_invalid")
    return encoded


def _install_authority(state_base: Path, encoded: bytes) -> None:
    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
        raise ValueError("native_workspace_review_runtime_unavailable")
    if state_base.is_symlink() or not state_base.is_dir():
        raise ValueError("native_workspace_review_state_unavailable")
    candidate_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=".workspace-review-authority-",
            suffix=".json",
            dir=state_base,
            delete=False,
        ) as candidate:
            candidate.write(encoded)
            candidate_path = Path(candidate.name)
        result = _run_native_process(
            status.identity.path,
            (
                "enroll-workspace-review-authority",
                "--state-dir",
                str(state_base),
                "--record",
                str(candidate_path),
            ),
            input_text="",
            timeout_seconds=5,
        )
        if result is None:
            capabilities = status.capabilities
            if capabilities is None or _RESIDENT_ENROLLMENT_FEATURE not in capabilities.features:
                raise ValueError("native_workspace_review_authority_install_failed")
            payload = json.dumps(
                {
                    "operation": "workspace_review_authority_enroll",
                    "request": {"record_path": str(candidate_path)},
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            response = native_resident_client_request(
                executable=status.identity.path,
                guard_home=state_base.parent,
                environment=_isolated_environment(),
                payload=payload,
                timeout_seconds=5,
            )
            if response is None:
                raise ValueError("native_workspace_review_authority_install_failed")
            try:
                accepted = json.loads(response)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError("native_workspace_review_authority_install_failed") from error
            if accepted != {"status": "enrolled"}:
                raise ValueError("native_workspace_review_authority_install_failed")
    finally:
        if candidate_path is not None:
            candidate_path.unlink(missing_ok=True)


def _state_base(store: GuardStore) -> Path:
    """The native runtime state directory the enrollment records live in."""
    return store.guard_home / "native-runtime"


def refresh_native_workspace_review_authority(
    store: GuardStore,
    auth_context: dict[str, object],
    *,
    now: datetime | None = None,
) -> bool:
    """Return true only when a newly verified authority was installed."""
    if EXACT_CLOUD_REVIEW_OPERATION not in exact_cloud_review_operations(store):
        return False
    state_base = _state_base(store)
    base_authority = state_base / "approval-authority.v1.json"
    if state_base.is_symlink() or base_authority.is_symlink() or not base_authority.is_file():
        return False
    current = (now or datetime.now(timezone.utc)).isoformat()
    connection = {field: auth_context.get(field) for field in _BINDING_FIELDS}
    binding = store.workspace_review_enrollment_due(connection, now=current)
    if binding is None:
        return False
    changed = False
    outcome = "unavailable"
    detail: dict[str, object]
    try:
        encoded = _fetch_authority(auth_context)
        target = state_base / "workspace-review-authority.v1.json"
        if target.is_symlink():
            raise ValueError("native_workspace_review_state_unavailable")
        if target.is_file():
            with target.open("rb") as installed:
                previous = installed.read(_MAX_RECORD_BYTES + 1)
        else:
            previous = None
        _install_authority(state_base, encoded)
        changed = previous != encoded
        detail = {"record": encoded.decode("utf-8")}
        outcome = "enrolled"
    except HTTPError as error:
        detail = {"http_status": error.code}
        _LOGGER.info("Cloud Review workspace enrollment unavailable: HTTP %d", error.code)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        # Logged before the schedule write, so a failed write cannot hide it.
        _LOGGER.warning("Cloud Review workspace enrollment failed: %s", type(error).__name__)
        detail = {
            "error_type": type(error).__name__,
            "error_code": str(error) if isinstance(error, ValueError) else None,
        }
    store.record_workspace_review_enrollment(binding, outcome=outcome, now=current, **detail)
    return changed


__all__ = ["refresh_native_workspace_review_authority"]
