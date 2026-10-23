"""Resident bridge for the ``inventory_source_evidence`` op.

An inventory item carries two pieces of filesystem evidence: the source of
truth behind a symlinked config path, and the content hash of the artifact's
primary document. Both read the filesystem, follow links and decide what a
path is allowed to reach, so the resident derives them and this module only
ships the artifact's identity across and hands the answer back. Nothing is
computed here: an unavailable resident cannot soften a blocked link into a
hash, and a snapshot built without the resident carries no evidence at all.

The whole artifact set is asked for at once. One request per artifact would
put the resident on the critical path of every inventory item an AIBOM run
walks, which is the cost the native cutover exists to remove.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

# v3 is the resident that reads an overlay's instruction role as well as the
# item kind. This client derives neither, so an older resident would answer
# without the role and leave the snapshot short of it: asking for v3 turns
# that into plain unavailability instead of a silently thinner answer.
INVENTORY_SOURCE_EVIDENCE_FEATURE = "inventory-source-evidence-v3"
_REQUEST_SCHEMA = "guard-inventory-source-evidence-request.v1"
_RESULT_SCHEMA = "guard-inventory-source-evidence-result.v1"
# The deadline covers a whole batch, and a batch is as large as the contract
# allows, so a fixed one would fail an inventory purely for being big: the
# resident hashes every primary document and fingerprints every linked tree it
# is handed. The floor carries a small batch over a cold filesystem; the
# per-entry share is what the work actually scales with. The resident's own
# file-count bound on a linked tree keeps one entry from spending the batch.
# The ceiling is what the batch is still worth waiting for: past it the hook
# that asked has already lost, and failing closed beats hanging the snapshot.
_TIMEOUT_FLOOR_SECONDS = 10.0
_TIMEOUT_PER_ENTRY_SECONDS = 0.1
_TIMEOUT_CEILING_SECONDS = 60.0
# Mirrors ``INVENTORY_SOURCE_EVIDENCE_MAX_ENTRIES``: the resident refuses a
# request carrying more entries than this.
_MAX_ENTRIES = 512
_MAX_REQUEST_BYTES = 4 * 1024 * 1024


class InventorySourceEvidenceUnavailableError(RuntimeError):
    """The resident could not derive the inventory source evidence."""

    code = "native_inventory_source_evidence_unavailable"


def native_inventory_source_evidence(
    entries: Sequence[Mapping[str, object]],
    *,
    home_dir: Path,
    workspace_dir: Path | None = None,
    include_symlinks: bool = True,
    follow_unsafe_symlinks: bool = False,
    guard_home: Path | None = None,
) -> list[dict[str, object]]:
    """Return one evidence mapping per entry, in order.

    Each answer carries ``item_kind`` (the snapshot kind the artifact type
    maps onto), ``instruction_role`` (what an overlay's configured path names,
    or ``None``), ``source_of_truth`` (the metadata block for a symlinked
    config path, or ``None``) and ``primary_content_hash`` (``sha256:…`` for a
    document the artifact is allowed to hash, or ``None``).

    Raises ``InventorySourceEvidenceUnavailableError`` when the resident cannot
    answer, so a caller fails closed rather than publishing a snapshot whose
    evidence was never derived.
    """

    if not entries:
        return []
    try:
        home = Path(_resolve_digest_home(guard_home))
    except (OSError, RuntimeError, ValueError):
        raise InventorySourceEvidenceUnavailableError from None
    if not ensure_resident_prerequisite(home):
        raise InventorySourceEvidenceUnavailableError
    answers: list[dict[str, object]] = []
    for start in range(0, len(entries), _MAX_ENTRIES):
        answers.extend(
            _evidence_for_batch(
                entries[start : start + _MAX_ENTRIES],
                home,
                home_dir=home_dir,
                workspace_dir=workspace_dir,
                include_symlinks=include_symlinks,
                follow_unsafe_symlinks=follow_unsafe_symlinks,
            )
        )
    return answers


def _evidence_for_batch(
    entries: Sequence[Mapping[str, object]],
    home: Path,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
    include_symlinks: bool,
    follow_unsafe_symlinks: bool,
) -> list[dict[str, object]]:
    """Ask the resident about one batch the contract is willing to accept."""

    try:
        # A relative path in the inventory is anchored here, and reading the
        # working directory is itself an I/O call: it raises when the directory
        # the process started in has since been removed. That is the same
        # unavailability every other failure below reports, so it is named as
        # such rather than escaping as a bare OSError the callers do not expect.
        cwd = Path.cwd()
    except OSError:
        raise InventorySourceEvidenceUnavailableError from None
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"inventory-source-evidence-{uuid4().hex}",
        "home_dir": _absolute(str(home_dir), cwd),
        "include_symlinks": include_symlinks,
        "follow_unsafe_symlinks": follow_unsafe_symlinks,
        "entries": [_entry_wire(entry, cwd) for entry in entries],
    }
    if workspace_dir is not None:
        wire["workspace_dir"] = _absolute(str(workspace_dir), cwd)
    try:
        response = _resident_request(
            operation="inventory_source_evidence",
            request=wire,
            guard_home=home,
            timeout_seconds=_batch_timeout_seconds(len(entries)),
            required_feature=INVENTORY_SOURCE_EVIDENCE_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise InventorySourceEvidenceUnavailableError from None
    payload = _payload(response, wire, home)
    if not isinstance(payload, dict):
        raise InventorySourceEvidenceUnavailableError
    evidence = payload.get("evidence")
    if not isinstance(evidence, list) or len(evidence) != len(entries):
        raise InventorySourceEvidenceUnavailableError
    if not all(isinstance(item, dict) for item in evidence):
        raise InventorySourceEvidenceUnavailableError
    return cast("list[dict[str, object]]", evidence)


def _batch_timeout_seconds(entry_count: int) -> float:
    """The deadline one batch of this size is allowed."""

    return min(
        _TIMEOUT_CEILING_SECONDS,
        _TIMEOUT_FLOOR_SECONDS + _TIMEOUT_PER_ENTRY_SECONDS * entry_count,
    )


def _entry_wire(entry: Mapping[str, object], cwd: Path) -> dict[str, object]:
    """Ship an entry's identity, leaving out a config path it does not carry.

    The item kind is not sent: the resident maps it from the artifact type and
    answers with it, so the caller holds no copy of that mapping.
    """

    wire: dict[str, object] = {
        "harness": str(entry.get("harness", "")),
        "artifact_type": str(entry.get("artifact_type", "")),
    }
    config_path = entry.get("config_path")
    if isinstance(config_path, str) and config_path:
        anchored = _absolute(config_path, cwd)
        wire["config_path"] = anchored
        # The instruction role is a reading of the path a harness configured,
        # so the resident needs that path as well whenever anchoring changed
        # it: a relative `notes.md` names no role, but the working directory
        # this scan happens to run in can carry `docs/security` or
        # `.cursor/rules` and hand the anchored path a role the configured one
        # never had. An absolute path is already what the harness wrote, so
        # nothing is sent for it and the request keeps the shape every caller
        # has today.
        if anchored != config_path:
            wire["configured_path"] = config_path
    return wire


def _absolute(value: str, cwd: Path) -> str:
    """Anchor a relative path to the caller's working directory.

    The resident resolves a path before it checks containment, and it can only
    resolve an absolute one: a relative workspace or config path would arrive
    with nothing to resolve against and lose its evidence. Detection hands back
    whatever the harness wrote, so a relative path is ordinary input, not a
    caller mistake.

    The join is deliberate rather than ``Path.resolve()``: the config path's
    own final component is the symlink the inspection exists to read, and
    resolving here would hand the resident the target instead. A leading ``~``
    is left alone for the resident to expand, as the Python source did.
    """

    if not value or value.startswith("~"):
        return value
    path = Path(value)
    return value if path.is_absolute() else str(cwd / path)
