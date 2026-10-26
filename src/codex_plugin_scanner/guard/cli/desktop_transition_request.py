"""Decode reviewed Desktop receipts, deriving selection rather than accepting inverses."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path, PurePosixPath
from typing import cast

from packaging.version import InvalidVersion, Version

from ..adapters.base import HarnessContext
from ..codex_hook_file_integrity import hook_validation_deadline
from ..codex_hook_recovery import _snapshot
from ..private_file_io import read_private_regular_bytes
from ..runtime_transition import TransitionError, TransitionFile
from ..runtime_transition_prepare import RuntimeTransitionPreparation

REQUEST_SCHEMA = "hol-guard.desktop-transition-request.v1"
_POINTER_SCHEMA = "hol-guard-core-install.v1"


def _json_object(raw: bytes, *, reason: str) -> object:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError("nonfinite JSON number")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)
    except (ValueError, UnicodeDecodeError) as error:
        raise TransitionError(reason) from error


def _digest(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise TransitionError("artifact_digest_invalid")
    return value


def _string(value: object) -> str:
    if not isinstance(value, str) or not 0 < len(value) <= 4096 or "\0" in value:
        raise TransitionError("selection_receipt_invalid")
    return value


def _pointer_artifact(
    value: object,
    root: Path,
    executable_sha256: str,
    *,
    require_receipt: bool,
) -> dict[str, object]:
    fields = {"schema", "version", "sourceCommit", "target", "relativePath", "sha256", "installedAt"}
    if not isinstance(value, dict) or not fields <= set(value) <= fields | {"artifact"}:
        raise TransitionError("selection_receipt_invalid")
    pointer = cast(dict[str, object], value)
    for name in fields:
        _string(pointer[name])
    if pointer["schema"] != _POINTER_SCHEMA:
        raise TransitionError("selection_receipt_invalid")
    source = _string(pointer["sourceCommit"])
    if len(source) != 40 or any(c not in "0123456789abcdef" for c in source):
        raise TransitionError("selection_receipt_invalid")
    relative_text = _string(pointer["relativePath"])
    relative = PurePosixPath(relative_text)
    if (
        relative.is_absolute()
        or "\\" in relative_text
        or ":" in relative_text
        or any(part in {"", ".", ".."} for part in relative_text.split("/"))
    ):
        raise TransitionError("selection_path_invalid")
    path = root.joinpath(*relative.parts)
    try:
        canonical = path.resolve(strict=True)
    except OSError as error:
        raise TransitionError("artifact_dependency_unavailable") from error
    if not canonical.is_relative_to(root) or path.is_symlink():
        raise TransitionError("selection_path_invalid")
    archive_sha256 = _digest(pointer["sha256"])
    receipt = pointer.get("artifact")
    if receipt is None:
        if require_receipt or archive_sha256 != executable_sha256:
            raise TransitionError("selection_receipt_missing")
        format_name = "onefile"
        # A legacy pointer has no published artifact generation. Bind its exact
        # observed receipt locally, without pretending it carried a new receipt.
        generation = hashlib.sha256(json.dumps(pointer, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    else:
        required = {"format", "archiveSha256", "bootstrapSchema", "generation"}
        if not isinstance(receipt, dict) or not required <= set(receipt) <= required | {"minimumDesktopVersion"}:
            raise TransitionError("selection_receipt_invalid")
        format_name = _string(receipt["format"])
        if format_name not in {"onefile", "onedir-zip"}:
            raise TransitionError("selection_receipt_invalid")
        archive_sha256 = _digest(receipt["archiveSha256"])
        minimum = receipt.get("minimumDesktopVersion")
        if minimum is not None:
            _string(minimum)
        bootstrap_schema = _string(receipt["bootstrapSchema"])
        generation = _digest(receipt["generation"])
        identity = [
            pointer["version"],
            source,
            pointer["target"],
            format_name,
            archive_sha256,
            bootstrap_schema,
            minimum,
            executable_sha256,
        ]
        expected = hashlib.sha256(json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        if generation != expected:
            raise TransitionError("artifact_generation_changed")
        if format_name == "onefile" and (pointer["sha256"] != executable_sha256 or archive_sha256 != executable_sha256):
            raise TransitionError("artifact_generation_changed")
    return {
        "version": pointer["version"],
        "source_commit": source,
        "target": pointer["target"],
        "format": format_name,
        "sha256": archive_sha256,
        "path": str(path),
        "generation": generation,
    }


def load_desktop_transition_request(
    request_path: Path,
    *,
    context: HarnessContext,
    operation_id: str,
    deadline_epoch: float,
    deadline_monotonic: float,
    request_sha256: str,
) -> RuntimeTransitionPreparation:
    def check() -> None:
        if time.monotonic() >= deadline_monotonic:
            raise TransitionError("deadline_exceeded")

    check()
    raw = read_private_regular_bytes(request_path, max_bytes=64 * 1024, require_private_parent=True)
    check()
    if raw is None:
        raise TransitionError("transition_request_unavailable")
    if hashlib.sha256(raw).hexdigest() != _digest(request_sha256):
        raise TransitionError("transition_request_generation_changed")
    payload = _json_object(raw, reason="transition_request_invalid")
    fields = {
        "schema",
        "operation_id",
        "guard_home",
        "home_dir",
        "managed_root",
        "previous_pointer_sha256",
        "candidate_pointer",
        "executable_digests",
        "native_runtimes",
    }
    if not isinstance(payload, dict) or set(payload) != fields or payload["schema"] != REQUEST_SCHEMA:
        raise TransitionError("transition_request_invalid")
    if (
        payload["operation_id"] != operation_id
        or payload["guard_home"] != str(context.guard_home.resolve())
        or payload["home_dir"] != str(context.home_dir.resolve())
    ):
        raise TransitionError("plan_context_mismatch")
    root = Path(_string(payload["managed_root"]))
    if (
        not root.is_absolute()
        or root.is_symlink()
        or root != root.resolve(strict=True)
        or not root.is_relative_to(context.home_dir.resolve())
    ):
        raise TransitionError("selection_path_invalid")
    digests = payload["executable_digests"]
    if not isinstance(digests, dict) or set(digests) != {"candidate", "predecessor"}:
        raise TransitionError("artifact_digest_invalid")
    executable_digests = {side: _digest(value) for side, value in digests.items()}
    pointer_path = root / "current.json"
    with hook_validation_deadline(deadline_monotonic):
        previous_bytes = _snapshot(pointer_path)
        check()
        if previous_bytes is None or hashlib.sha256(previous_bytes).hexdigest() != _digest(
            payload["previous_pointer_sha256"]
        ):
            raise TransitionError("selection_generation_changed")
        if len(previous_bytes) > 64 * 1024:
            raise TransitionError("selection_receipt_invalid")
        previous_pointer = _json_object(previous_bytes, reason="selection_receipt_invalid")
        candidate_pointer = payload["candidate_pointer"]
        predecessor = _pointer_artifact(
            previous_pointer,
            root,
            executable_digests["predecessor"],
            require_receipt=False,
        )
        candidate = _pointer_artifact(candidate_pointer, root, executable_digests["candidate"], require_receipt=True)
        try:
            if Version(cast(str, candidate["version"])) < Version(cast(str, predecessor["version"])):
                raise TransitionError("artifact_downgrade_forbidden")
        except InvalidVersion as error:
            raise TransitionError("selection_receipt_invalid") from error
        if candidate["target"] != predecessor["target"] or candidate["path"] == predecessor["path"]:
            raise TransitionError("artifact_identity_invalid")
        after = json.dumps(candidate_pointer, ensure_ascii=False, indent=2).encode() + b"\n"
        mode = pointer_path.stat().st_mode & 0o777
        selection = TransitionFile(
            pointer_path, previous_bytes, after, before_mode=mode, after_mode=mode, kind="selection"
        )
        # The generic stable launcher is retained unchanged. Initial adoption
        # without that launcher needs its own complete prepared selection plan.
        shim_path = root / ("current-hol-guard.cmd" if os.name == "nt" else "current-hol-guard")
        shim = TransitionFile.identity_dependency(shim_path)
        check()
    native = payload["native_runtimes"]
    if not isinstance(native, dict):
        raise TransitionError("native_runtime_bindings_invalid")
    return RuntimeTransitionPreparation(
        operation_id,
        predecessor,
        candidate,
        (selection,),
        native,
        deadline_epoch,
        executable_digests,
        selection_dependencies=(shim,),
    )
