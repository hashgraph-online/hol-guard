"""Ask the resident's ``local_tool_eligibility`` operation from tests.

No runtime path asks this question from Python: the resident answers it on its
own hook path. Tests keep this client to pin what the operation decides.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast
from uuid import uuid4

from codex_plugin_scanner.guard.native_context import (
    _canonical_request_sha256,
    _resolve_existing_digest_home,
    ensure_resident_prerequisite,
)
from codex_plugin_scanner.guard.native_execution import _resident_request
from codex_plugin_scanner.guard.trusted_local_tools import _accepted

LOCAL_TOOL_ELIGIBILITY_FEATURE: Final = "local-tool-eligibility-v1"
_ELIGIBILITY_REQUEST_SCHEMA: Final = "guard-local-tool-eligibility-request.v1"
_ELIGIBILITY_RESULT_SCHEMA: Final = "guard-local-tool-eligibility-result.v1"
_ELIGIBILITY_TIMEOUT_SECONDS: Final = 10.0
# The request carries the caller environment, which the launch identity binds.
_ELIGIBILITY_MAX_REQUEST_BYTES: Final = 2 * 1024 * 1024
_ELIGIBILITY_PAYLOAD_KEYS: Final = frozenset(
    {"tool_name", "tool_identity_hash", "capability", "read_only_reason", "trust_basis", "indefinite_allowed"}
)


@dataclass(frozen=True, slots=True)
class LocalToolApprovalEligibility:
    tool_name: str
    tool_identity_hash: str
    capability: str
    read_only_reason: str
    trust_basis: Literal["verified-files", "package-profile"] = "verified-files"
    indefinite_allowed: bool = False

    def to_evidence(self) -> dict[str, object]:
        return {
            "source": "trusted_local_tool",
            "version": 1,
            "eligible": True,
            "tool_name": self.tool_name,
            "tool_identity_hash": self.tool_identity_hash,
            "capability": self.capability,
            "read_only_reason": self.read_only_reason,
            "trust_basis": self.trust_basis,
            "indefinite_allowed": self.indefinite_allowed,
        }


def local_tool_approval_eligibility(
    command: str,
    *,
    cwd: Path,
    home_dir: Path | None,
) -> LocalToolApprovalEligibility | None:
    """Ask the resident whether the command may carry a reusable local tool grant.

    Any missing, failed or malformed answer is ``None``: not eligible, never
    more permissive.
    """

    try:
        request: dict[str, object] = {
            "schema": _ELIGIBILITY_REQUEST_SCHEMA,
            "request_id": f"local-tool-eligibility-{uuid4().hex}",
            "command": command,
            "cwd": str(cwd),
            "home_dir": None if home_dir is None else str(home_dir),
            "user_home": str(Path.home()),
            "launch_env": dict(os.environ),
        }
        digest = "sha256:" + _canonical_request_sha256(request)
        guard_home = _resolve_existing_digest_home(None)
        if not ensure_resident_prerequisite(guard_home):
            return None
        response = _resident_request(
            operation="local_tool_eligibility",
            request=request,
            guard_home=guard_home,
            timeout_seconds=_ELIGIBILITY_TIMEOUT_SECONDS,
            required_feature=LOCAL_TOOL_ELIGIBILITY_FEATURE,
            response_schema=_ELIGIBILITY_RESULT_SCHEMA,
            max_request_bytes=_ELIGIBILITY_MAX_REQUEST_BYTES,
        )
    except Exception:
        return None
    answer = _accepted(response, request_id=request["request_id"], digest=digest, schema=_ELIGIBILITY_RESULT_SCHEMA)
    return None if answer is None else _eligibility_from_payload(answer.get("payload"))


def _eligibility_from_payload(payload: object) -> LocalToolApprovalEligibility | None:
    if not isinstance(payload, dict) or set(payload) != _ELIGIBILITY_PAYLOAD_KEYS:
        return None
    fields = cast(dict[str, object], payload)
    tool_name, identity_hash = fields["tool_name"], fields["tool_identity_hash"]
    capability, read_only_reason = fields["capability"], fields["read_only_reason"]
    trust_basis, indefinite_allowed = fields["trust_basis"], fields["indefinite_allowed"]
    if (
        not isinstance(tool_name, str)
        or _nonempty_string(tool_name) is None
        or not isinstance(identity_hash, str)
        or not _is_sha256(identity_hash)
        or not isinstance(capability, str)
        or _nonempty_string(capability) is None
        or not isinstance(read_only_reason, str)
        or _nonempty_string(read_only_reason) is None
        or not isinstance(trust_basis, str)
        or trust_basis not in {"verified-files", "package-profile"}
        or not isinstance(indefinite_allowed, bool)
        or (indefinite_allowed and trust_basis != "package-profile")
    ):
        return None
    return LocalToolApprovalEligibility(
        tool_name=tool_name,
        tool_identity_hash=identity_hash,
        capability=capability,
        read_only_reason=read_only_reason,
        trust_basis=cast(Literal["verified-files", "package-profile"], trust_basis),
        indefinite_allowed=indefinite_allowed,
    )


def _nonempty_string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _is_sha256(value: str | None) -> bool:
    return value is not None and len(value) == 64 and all(character in "0123456789abcdef" for character in value)
