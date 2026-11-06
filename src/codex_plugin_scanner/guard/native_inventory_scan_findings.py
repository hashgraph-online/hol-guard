"""Resident bridge for the ``inventory_scan_findings`` op.

A scan reports three things, and each one is a protection decision. A
severity decides how far an inventory's score moves. A scanner's completion
state decides whether an inventory shows that scanner as available, failed or
absent. A recorded symlink state decides whether the detector's own evidence
reaches the snapshot at all. The resident owns all three, and this module only
ships the runs and the items across and hands the answers back. Nothing is
decided here: an unavailable resident cannot normalize a severity down, call a
failed scanner merely missing, or drop an escaped symlink.

The finding text crosses a privacy boundary on the same trip. Scanner titles,
descriptions, messages and file paths quote the operator's own filesystem, and
the resident redacts them as it classifies them, so no caller can publish the
raw text by forgetting to redact first.

The whole scan is asked for at once. A snapshot covers every run and every item
a detection found, and asking per finding would put the resident on an
inventory's critical path a few hundred times over.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

INVENTORY_SCAN_FINDINGS_FEATURE = "inventory-scan-findings-v1"
_REQUEST_SCHEMA = "guard-inventory-scan-findings-request.v1"
_RESULT_SCHEMA = "guard-inventory-scan-findings-result.v1"
# The deadline covers the whole scan, and a scan is as large as the inventory
# it belongs to, so a fixed one would fail a big inventory for being big. The
# floor carries a small inventory; the per-entry share is what the redaction
# work actually scales with. The ceiling is what the snapshot is still worth
# waiting for: past it the caller has already lost, and failing closed beats
# hanging the inventory.
_TIMEOUT_FLOOR_SECONDS = 10.0
_TIMEOUT_PER_ENTRY_SECONDS = 0.02
_TIMEOUT_CEILING_SECONDS = 60.0
# Mirror ``INVENTORY_SCAN_FINDINGS_MAX_RUNS`` and ``_MAX_ITEMS``: the resident
# refuses a request carrying more than this, and the findings are deduplicated
# across the whole scan, so the request cannot be split into batches.
_MAX_RUNS = 256
_MAX_ITEMS = 8192
# The largest envelope this bridge will offer the transport. It is not the op's
# own ``INVENTORY_SCAN_FINDINGS_MAX_BYTES``: that measures the canonical request
# inside the envelope and this measures the envelope, which is the larger of the
# two. It is the transport's frame limit, which is what the client checks this
# same byte string against, so a scan this bridge accepts is one the client will
# frame and the op will answer for -- and a scan past it is refused for its size
# rather than dropped as a runtime that stopped answering.
_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_MISSING = object()


class InventoryScanFindingsUnavailableError(RuntimeError):
    """The resident could not classify the scan."""

    code = "native_inventory_scan_findings_unavailable"


def native_inventory_scan_findings(
    cisco_runs: Sequence[object],
    *,
    harness: str,
    items: Sequence[object],
    home_dir: Path,
    workspace_dir: Path | None = None,
    include_symlinks: bool = True,
    guard_home: Path | None = None,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Return the scan's findings and its scanner sources.

    The findings are the scanner findings followed by the symlink findings, in
    the order the runs and the items were given; the sources are one per
    recognised scanner run. Both carry the keyword arguments their dataclass
    takes, so the caller constructs the records without deciding anything.

    Raises ``InventoryScanFindingsUnavailableError`` when the resident cannot
    answer, so a caller fails closed rather than publishing a snapshot whose
    findings were never classified.
    """

    if not cisco_runs and not (items and include_symlinks):
        return [], []
    if len(cisco_runs) > _MAX_RUNS or len(items) > _MAX_ITEMS:
        raise InventoryScanFindingsUnavailableError
    try:
        home = Path(_resolve_digest_home(guard_home))
    except (OSError, RuntimeError, ValueError):
        raise InventoryScanFindingsUnavailableError from None
    if not ensure_resident_prerequisite(home):
        raise InventoryScanFindingsUnavailableError
    try:
        # The resident anchors a relative path here, and reading the working
        # directory is itself an I/O call: it raises when the directory the
        # process started in has since been removed. That is the same
        # unavailability every other failure reports, so it is named as such
        # rather than escaping as a bare OSError the callers do not expect.
        cwd = Path.cwd()
    except OSError:
        raise InventoryScanFindingsUnavailableError from None
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"inventory-scan-findings-{uuid4().hex}",
        "harness": harness,
        "home_dir": str(home_dir),
        "cwd": str(cwd),
        "include_symlinks": include_symlinks,
        "cisco_runs": [_run_wire(run) for run in cisco_runs],
        "items": [_item_wire(item) for item in items],
    }
    if workspace_dir is not None:
        wire["workspace_dir"] = str(workspace_dir)
    try:
        response = _resident_request(
            operation="inventory_scan_findings",
            request=wire,
            guard_home=home,
            timeout_seconds=_request_timeout_seconds(len(cisco_runs) + len(items)),
            required_feature=INVENTORY_SCAN_FINDINGS_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise InventoryScanFindingsUnavailableError from None
    payload = _payload(response, wire, home)
    if not isinstance(payload, dict):
        raise InventoryScanFindingsUnavailableError
    findings = _records(payload.get("findings"))
    sources = _records(payload.get("sources"))
    return findings, sources


def _records(value: object) -> list[dict[str, object]]:
    """Read one answer list, refusing a shape the caller cannot construct from."""

    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise InventoryScanFindingsUnavailableError
    return cast("list[dict[str, object]]", value)


def _request_timeout_seconds(entry_count: int) -> float:
    """The deadline a scan of this size is allowed."""

    return min(
        _TIMEOUT_CEILING_SECONDS,
        _TIMEOUT_FLOOR_SECONDS + _TIMEOUT_PER_ENTRY_SECONDS * entry_count,
    )


def _run_wire(run: object) -> dict[str, object]:
    """Ship the fields of one scanner run the finding grammar reads.

    An attribute the run does not carry is left out rather than sent as null,
    so the resident applies the same default the attribute read did.
    """

    wire: dict[str, object] = {}
    for key in ("source", "status", "message", "duration_ms", "metadata"):
        value = getattr(run, key, _MISSING)
        if value is not _MISSING:
            wire[key] = _json_safe(value)
    findings = getattr(run, "findings", None)
    if isinstance(findings, (list, tuple)):
        wire["findings"] = [_finding_wire(finding) for finding in findings]
    return wire


def _finding_wire(finding: object) -> dict[str, object]:
    """Ship the fields of one raw scanner finding."""

    wire: dict[str, object] = {}
    for key in ("rule_id", "title", "description", "file_path", "line_number"):
        value = getattr(finding, key, _MISSING)
        if value is not _MISSING:
            wire[key] = _json_safe(value)
    severity = getattr(finding, "severity", _MISSING)
    if severity is not _MISSING:
        # ``str(getattr(value, "value", value))`` — a severity enum carries the
        # token on ``.value``, and its ``str()`` would be the member name. The
        # resident still decides what the token normalizes to.
        wire["severity"] = str(getattr(severity, "value", severity))
    return wire


def _item_wire(item: object) -> dict[str, object]:
    """Ship an item's identity and the metadata the grammar reads.

    ``configPath`` associates a scanner finding with the artifact it belongs to
    and ``sourceOfTruth`` carries the symlink evidence; nothing else about an
    item is read, so nothing else is sent.
    """

    metadata = getattr(item, "metadata", None)
    kept: dict[str, object] = {}
    if isinstance(metadata, Mapping):
        for key in ("configPath", "sourceOfTruth"):
            if key in metadata:
                kept[key] = _json_safe(metadata[key])
    return {"item_id": str(getattr(item, "item_id", "")), "metadata": kept}


def _json_safe(value: object) -> object:
    """Render a duck-typed attribute as the resident's JSON equivalent.

    Scalars ride across as they are, so the resident sees the same type the
    attribute read saw and applies the same ``isinstance`` guards. Anything else
    becomes its ``str()``, which is what the Python source did with it.
    """

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return str(value)
