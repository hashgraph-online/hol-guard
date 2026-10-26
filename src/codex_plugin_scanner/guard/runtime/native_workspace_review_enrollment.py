"""Refresh root-signed workspace-review enrollment outside hook execution."""

from __future__ import annotations

import hashlib
import json
import logging
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.error import HTTPError

from ..native_resident_client import native_resident_client_request
from ..native_runtime import _isolated_environment, _run_native_process, native_runtime_status
from .command_queue_protocol import command_api_url
from .exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION, exact_cloud_review_operations
from .runner import _guard_sync_request, _urlopen_json_with_timeout_retry

if TYPE_CHECKING:
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)
_STATE_KEY = "guard_cloud_review_workspace_enrollment"
_AUTHORITY_PATH = "/api/guard/review/v2/authority/current"
_CHECK_INTERVAL = timedelta(minutes=5)
_MAX_RECORD_BYTES = 16 * 1024
_RESIDENT_ENROLLMENT_FEATURE = "native-workspace-review-enrollment-resident-v1"


def _binding(auth_context: dict[str, object]) -> list[str] | None:
    fields = ("workspace_id", "machine_installation_id", "sync_url")
    values = [auth_context.get(field) for field in fields]
    if any(not isinstance(value, str) or not value for value in values):
        return None
    subject = auth_context.get("oauth_subject_hash")
    if subject is not None and (not isinstance(subject, str) or not subject):
        return None
    return [str(value) for value in values] + ([subject] if isinstance(subject, str) else [])


def _due(state: object, binding: list[str], now: datetime) -> bool:
    if not isinstance(state, dict) or state.get("binding") != binding:
        return True
    next_check = state.get("next_check_at")
    if not isinstance(next_check, str):
        return True
    try:
        scheduled = datetime.fromisoformat(next_check)
    except ValueError:
        return True
    if scheduled.tzinfo is None or scheduled - now > _CHECK_INTERVAL:
        return True
    return scheduled <= now


def _fetch_authority(auth_context: dict[str, object]) -> bytes:
    url = command_api_url(
        auth_context["sync_url"],
        "/current",
        base_path="/api/guard/review/v2/authority",
    )
    request = _guard_sync_request(
        auth_context,
        request_url=url,
        method="POST",
        data=b'{"protocolVersion":2}',
    )
    response = _urlopen_json_with_timeout_retry(request=request, timeout_seconds=5, retry_timeout_seconds=5)
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


def refresh_native_workspace_review_authority(
    store: GuardStore,
    auth_context: dict[str, object],
    *,
    now: datetime | None = None,
) -> bool:
    """Return true only when a newly verified authority was installed."""
    if EXACT_CLOUD_REVIEW_OPERATION not in exact_cloud_review_operations(store):
        return False
    binding = _binding(auth_context)
    if binding is None:
        return False
    state_base = store.guard_home / "native-runtime"
    base_authority = state_base / "approval-authority.v1.json"
    if state_base.is_symlink() or base_authority.is_symlink() or not base_authority.is_file():
        return False
    current = now or datetime.now(timezone.utc)
    state = store.get_sync_payload(_STATE_KEY)
    if not _due(state, binding, current):
        return False
    next_state: dict[str, object] = {
        "binding": binding,
        "next_check_at": (current + _CHECK_INTERVAL).isoformat(),
    }
    changed = False
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
        next_state["record_digest"] = hashlib.sha256(encoded).hexdigest()
        next_state["status"] = "enrolled"
    except HTTPError as error:
        next_state["status"] = "unavailable"
        next_state["http_status"] = error.code
        _LOGGER.info("Cloud Review workspace enrollment unavailable: HTTP %d", error.code)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        next_state["status"] = "unavailable"
        code = str(error) if isinstance(error, ValueError) else ""
        next_state["error_code"] = code if code.startswith("native_workspace_review_") else type(error).__name__
        _LOGGER.warning("Cloud Review workspace enrollment failed: %s", next_state["error_code"])
    store.set_sync_payload(_STATE_KEY, next_state, current.isoformat())
    return changed


__all__ = ["refresh_native_workspace_review_authority"]
