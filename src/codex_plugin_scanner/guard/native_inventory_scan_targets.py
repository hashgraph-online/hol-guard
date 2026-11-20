"""Resident bridge for the ``inventory_scan_targets`` op.

Which MCP configurations a Cisco inventory pass opens, which directory each
one is scanned under, what a finding calls it, and which skill collections the
skill scanner walks: the selection decides what the inventory can report at
all. A configuration left out is one nothing reads, and a skill collection
missed is instructions nothing reports on, so the resident chooses and this
module only carries the context across and hands the answer back.

The selection is also filesystem work -- ``is_file`` and ``is_dir`` on every
candidate, a recursive search for ``SKILL.md``, and ``Path.resolve()`` on
everything compared or deduplicated -- which is the resident's to do.

One request covers a whole pass, because ``run_cisco_inventory_scans`` is
called once per pass; asking per artifact would put the resident on the
critical path of every detected item.

Paths travel as the caller holds them, relative ones included, with the
caller's own working directory alongside: the resident has its own, and
resolving against that one would answer about a directory the caller never
stood in.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure
from .native_store_policy import _payload

INVENTORY_SCAN_TARGETS_FEATURE = "inventory-scan-targets-v1"
_REQUEST_SCHEMA = "guard-inventory-scan-targets-request.v1"
_RESULT_SCHEMA = "guard-inventory-scan-targets-result.v1"
_UNUSABLE_REPLY_REASON = "native_inventory_scan_targets_payload"
# The deadline covers one whole pass. The work is a bounded walk of the
# workspace and the home, so the floor is what a cold resident needs to answer
# at all, the per-artifact share covers the candidates a detection adds, and
# the ceiling is the point past which skipping the scan beats holding the
# snapshot open.
_TIMEOUT_FLOOR_SECONDS = 15.0
_TIMEOUT_PER_ARTIFACT_SECONDS = 0.02
_TIMEOUT_CEILING_SECONDS = 60.0
_TIMEOUT_EXHAUSTED_SECONDS = 0.001
# Mirrors ``INVENTORY_SCAN_TARGETS_MAX_BYTES``, which is itself held under the
# transport's own frame limit so an oversized request is refused for its size
# rather than as a malformed frame.
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_SKILL_ARTIFACT_TYPES = frozenset({"skill", "skill_file"})
_TARGET_ARTIFACT_TYPES = _SKILL_ARTIFACT_TYPES | {"mcp_server"}


class InventoryScanTargetsUnavailableError(RuntimeError):
    """The resident could not choose the inventory scan's targets."""

    code = "native_inventory_scan_targets_unavailable"


@dataclass(frozen=True, slots=True)
class CiscoMcpScanTarget:
    """One MCP configuration and the directory it is scanned under."""

    root: Path
    config_path: Path
    label: str


@dataclass(frozen=True, slots=True)
class CiscoScanTargets:
    """Everything one inventory pass is allowed to read."""

    mcp_targets: tuple[CiscoMcpScanTarget, ...]
    skill_roots: tuple[Path, ...]


def native_inventory_scan_targets(
    *,
    harness: str,
    home_dir: Path,
    workspace_dir: Path | None,
    artifacts: Sequence[object],
    cwd: Path | None = None,
    guard_home: Path | None = None,
    timeout_seconds: float | None = None,
) -> CiscoScanTargets:
    """Return the MCP configurations and skill collections this pass reads.

    ``artifacts`` are the detection's own artifacts; only their type, their
    configuration path and the ``skill_root`` their metadata recorded reach the
    resident, because nothing else takes part in the selection.

    Raises ``InventoryScanTargetsUnavailableError`` when the resident cannot
    answer. The caller reports the scan as unavailable rather than choosing
    targets here: a second selection would be the implementation this op
    exists to remove, and one that silently read less would report a clean
    inventory of configurations nobody opened.
    """

    try:
        home = Path(_resolve_digest_home(guard_home))
    except (OSError, RuntimeError, ValueError):
        raise InventoryScanTargetsUnavailableError from None
    if not ensure_resident_prerequisite(home):
        raise InventoryScanTargetsUnavailableError

    entries = [_artifact_wire(artifact) for artifact in artifacts]
    entries = [entry for entry in entries if entry is not None]
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"inventory-scan-targets-{uuid4().hex}",
        "harness": str(harness),
        "cwd": str(cwd if cwd is not None else Path.cwd()),
        "home_dir": str(home_dir),
        "artifacts": entries,
    }
    if workspace_dir is not None:
        wire["workspace_dir"] = str(workspace_dir)
    try:
        response = _resident_request(
            operation="inventory_scan_targets",
            request=wire,
            guard_home=home,
            timeout_seconds=_request_timeout_seconds(len(entries), timeout_seconds),
            required_feature=INVENTORY_SCAN_TARGETS_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise InventoryScanTargetsUnavailableError from None
    payload = _payload(response, wire, home)
    if not isinstance(payload, dict):
        raise InventoryScanTargetsUnavailableError
    try:
        return CiscoScanTargets(
            mcp_targets=_mcp_targets(payload.get("mcp_targets")),
            skill_roots=_skill_roots(payload.get("skill_roots")),
        )
    except InventoryScanTargetsUnavailableError:
        _record_unusable_reply(home)
        raise


def _record_unusable_reply(guard_home: Path) -> None:
    """Count a bound reply whose target lists this client cannot read.

    ``_payload`` has already recorded the reply as a resident success: it was
    bound to the request and carried an object payload, which is as far as the
    shared binding check looks. A resident that keeps answering with target
    lists this client refuses would otherwise clear the failure streak on every
    pass while no pass ever gets an inventory, so the circuit that exists for
    an unusable resident would never open.
    """

    identity = native_runtime_status().identity
    if identity is None:
        return
    native_record_resident_failure(identity.sha256, guard_home, reason=_UNUSABLE_REPLY_REASON)


def _artifact_wire(artifact: object) -> dict[str, object] | None:
    """Ship what one detected artifact contributes to the selection.

    An artifact of a type the selection never reads is dropped here rather
    than carried: the request is bounded, and spending that bound on artifacts
    the resident would skip is what makes a large detection fail closed.
    """

    artifact_type = str(getattr(artifact, "artifact_type", ""))
    if artifact_type not in _TARGET_ARTIFACT_TYPES:
        return None
    wire: dict[str, object] = {"artifact_type": artifact_type}
    config_path = getattr(artifact, "config_path", None)
    if isinstance(config_path, str):
        wire["config_path"] = config_path
    if artifact_type in _SKILL_ARTIFACT_TYPES:
        metadata = getattr(artifact, "metadata", None)
        skill_root = metadata.get("skill_root") if isinstance(metadata, dict) else None
        if isinstance(skill_root, str):
            wire["skill_root"] = skill_root
    return wire


def _mcp_targets(value: object) -> tuple[CiscoMcpScanTarget, ...]:
    """Read the MCP targets back, in the order the resident scanned them."""

    if not isinstance(value, list):
        raise InventoryScanTargetsUnavailableError
    targets: list[CiscoMcpScanTarget] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise InventoryScanTargetsUnavailableError
        root = entry.get("root")
        config_path = entry.get("config_path")
        label = entry.get("label")
        if not isinstance(root, str) or not isinstance(config_path, str) or not isinstance(label, str):
            raise InventoryScanTargetsUnavailableError
        targets.append(CiscoMcpScanTarget(root=Path(root), config_path=Path(config_path), label=label))
    return tuple(targets)


def _skill_roots(value: object) -> tuple[Path, ...]:
    """Read the skill collections back, in the resident's order."""

    if not isinstance(value, list):
        raise InventoryScanTargetsUnavailableError
    if not all(isinstance(entry, str) for entry in value):
        raise InventoryScanTargetsUnavailableError
    return tuple(Path(entry) for entry in value)


def _request_timeout_seconds(artifact_count: int, budget_seconds: float | None = None) -> float:
    """The deadline one pass of this size is allowed.

    ``budget_seconds`` is what the caller gave the whole inventory pass. The
    selection cannot outlast it: a call that ran to its own ceiling would spend
    time the scanners were promised and still leave them their full share.
    """

    deadline = min(
        _TIMEOUT_CEILING_SECONDS,
        _TIMEOUT_FLOOR_SECONDS + _TIMEOUT_PER_ARTIFACT_SECONDS * artifact_count,
    )
    if budget_seconds is None:
        return deadline
    # A spent budget still asks with a real deadline rather than zero, which a
    # socket reads as "do not block at all" instead of "answer at once".
    return max(min(deadline, float(budget_seconds)), _TIMEOUT_EXHAUSTED_SECONDS)
