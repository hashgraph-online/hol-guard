"""Private captured repair plans for review, never forward authorization.

The file preserves the exact UUID, subject and dependencies between preparation
and authentication. Loading cannot grant repair or select a different runtime.
Factors and grants are deliberately absent from this protocol.
"""

from __future__ import annotations

import base64
import time
from dataclasses import replace
from pathlib import Path
from typing import cast

from .codex_hook_authority_record import AuthorityRecordRefusedError, open_authority_record, seal_authority_record
from .codex_hook_file_integrity import hook_validation_deadline
from .codex_hook_integrity import load_hook_secret
from .codex_hook_manifest import (
    CodexHookManifestSpec,
    PreparedCodexHookRepair,
    transition_file,
)
from .codex_hook_recovery import load_hook_authority_receipt
from .codex_publication_inverse_plan import (
    PreparedCodexPublicationInverse,
    bind_codex_publication_inverse_verification,
    prepare_authenticated_hook_publication_inverse,
)
from .native_runtime import NativeRuntimeIdentity
from .native_transition_files import publication, request_policy, require_deadline
from .runtime_transition import (
    RuntimeTransition,
    TransitionError,
    inverse_recovery_budget,
)

_SCHEMA = "hol-guard.codex-authority-repair-request.v1"
_PURPOSE = "codex-authority-repair-request"
_INVERSE_SCHEMA = "hol-guard.codex-publication-inverse-request.v1"
_INVERSE_PURPOSE = "codex-publication-inverse-request"
RepairPlan = PreparedCodexHookRepair | PreparedCodexPublicationInverse


def _inverse_from_payload(
    value: object,
    spec: CodexHookManifestSpec,
    deadline: float,
) -> PreparedCodexPublicationInverse:
    # Reconstruct targets and predecessor bytes from the authenticated live WAL.
    # Serialized targets and dependencies never independently confer authority.
    publication("repair_request_plan", spec.guard_home, kind="inverse", payload=value)
    if not isinstance(value, dict):
        raise TransitionError("authority_repair_request_plan_invalid")
    native = cast(dict[str, object], value["native_runtime"])
    operation = cast(str, value["operation_id"])
    workspace = cast(str, value["verification_workspace"])
    with inverse_recovery_budget(deadline), hook_validation_deadline(deadline):
        fresh = prepare_authenticated_hook_publication_inverse(spec)
        bound = bind_codex_publication_inverse_verification(
            replace(fresh, operation_id=operation),
            expected_runtime=NativeRuntimeIdentity(
                Path(cast(str, native["path"])),
                cast(int, native["size"]),
                cast(int, native["mtime_ns"]),
                cast(str, native["sha256"]),
            ),
            workspace=Path(workspace),
            deadline_monotonic=deadline,
        )
    # The runtime compares the reviewed payload with the plan rebuilt here.
    publication("repair_request_plan", spec.guard_home, kind="inverse_bound", payload=value, bound=bound.payload())
    return bound


def _plan_from_payload(value: object, *, home: Path, config: Path) -> PreparedCodexHookRepair:
    # The native runtime owns every shape, context and file-set check; it
    # answers which file is the manifest change.
    answer = publication(
        "repair_request_plan", home, kind="repair", payload=value, guard_home=str(home), config_path=str(config)
    )
    if not isinstance(answer, dict) or type(answer.get("change")) is not int or not isinstance(value, dict):
        raise TransitionError("authority_repair_request_plan_invalid")
    raw_files = cast(list[dict[str, object]], value["files"])
    files = tuple(transition_file(item) for item in raw_files)
    native = cast(dict[str, object], value["native_runtime"])
    plan = PreparedCodexHookRepair(
        files[answer["change"]],
        files,
        home,
        config,
        cast(str, value["operation_id"]),
        NativeRuntimeIdentity(
            Path(cast(str, native["path"])),
            cast(int, native["size"]),
            cast(int, native["mtime_ns"]),
            cast(str, native["sha256"]),
        ),
        Path(cast(str, value["verification_workspace"])),
    )
    # The runtime already refused any normalization that would change a reviewed payload.
    return plan


def _compare(plan: RepairPlan, deadline: float) -> None:
    require_deadline(deadline)
    with inverse_recovery_budget(deadline), hook_validation_deadline(deadline):
        if isinstance(plan, PreparedCodexPublicationInverse):
            plan.compare_before()
            require_deadline(deadline)
            return
        RuntimeTransition._compare(plan.payload(), "before")
        load_hook_authority_receipt(
            plan.guard_home,
            plan.config_path,
            require_manifest=(plan.manifest_change.after, "authority_repair_request_plan_invalid"),
        )
        RuntimeTransition._compare(plan.payload(), "before")
    require_deadline(deadline)


def _read(path: Path, home: Path, expected_sha256: str, deadline: float) -> bytes:
    """The artifact's bytes, only while they still carry the reviewed digest."""
    with inverse_recovery_budget(deadline):
        raw = publication("request_read", home, path=str(path), expected_sha256=expected_sha256)
    if not isinstance(raw, str):
        raise TransitionError("authority_repair_request_changed")
    return base64.b64decode(raw)


_FRAME_TOO_LARGE = "native_runner_authority_request_too_large"


def write_codex_hook_repair_request(
    path: Path,
    plan: RepairPlan,
    *,
    deadline_monotonic: float,
) -> str:
    """Exclusively create a private review artifact; return its exact digest."""
    require_deadline(deadline_monotonic)
    inverse = isinstance(plan, PreparedCodexPublicationInverse)
    if not inverse:
        plan = _plan_from_payload(plan.payload(), home=plan.guard_home, config=plan.config_path)
    _compare(plan, deadline_monotonic)
    material = load_hook_secret(plan.guard_home)
    stamp = request_policy("stamp", now=time.monotonic())
    payload: dict[str, object] = {
        "schema": _INVERSE_SCHEMA if inverse else _SCHEMA,
        "guard_home": str(plan.guard_home),
        "config_path": str(plan.config_path),
        "installation_id": material.installation_id,
        "created_monotonic": stamp["created"],
        "expires_monotonic": stamp["expires"],
        "plan": plan.payload(),
        "subject": plan.subject(),
    }
    try:
        encoded = seal_authority_record(
            "inverse_request" if inverse else "repair_request", payload, material, signed_at=plan.operation_id
        )
    except AuthorityRecordRefusedError as exc:
        raise TransitionError(f"authority_repair_request_{exc.reason}") from exc
    _compare(plan, deadline_monotonic)
    from .native_runner_authority import NativeRunnerAuthorityRefusalError

    with inverse_recovery_budget(deadline_monotonic):
        try:
            digest = publication(
                "request_create",
                plan.guard_home,
                path=str(path),
                encoded=base64.b64encode(encoded).decode("ascii"),
            )
        except NativeRunnerAuthorityRefusalError as exc:
            # A record too big to cross to the runtime is the capacity refusal,
            # raised before any file is created or changed.
            if str(exc) == _FRAME_TOO_LARGE:
                raise TransitionError("authority_repair_request_too_large") from exc
            raise
    if not isinstance(digest, str):
        raise TransitionError("authority_repair_request_changed")
    _compare(plan, deadline_monotonic)
    return digest


def load_codex_hook_repair_request(
    path: Path,
    *,
    guard_home: Path,
    config_path: Path,
    expected_sha256: str,
    deadline_monotonic: float,
    inverse_spec: CodexHookManifestSpec | None = None,
) -> RepairPlan:
    """Authenticate and compare the captured plan; never regenerate or grant."""
    require_deadline(deadline_monotonic)
    if not isinstance(expected_sha256, str):
        raise TransitionError("authority_repair_request_digest_invalid")
    raw = _read(path, guard_home, expected_sha256, deadline_monotonic)
    require_deadline(deadline_monotonic)
    home = guard_home.resolve(strict=False)
    config = config_path.parent.resolve(strict=False) / config_path.name
    inverse = inverse_spec is not None
    try:
        payload, signed_at = open_authority_record(
            "inverse_request" if inverse else "repair_request",
            raw,
            load_hook_secret(home),
            guard_home=str(home),
            config_path=str(config),
        )
    except AuthorityRecordRefusedError as exc:
        raise TransitionError(f"authority_repair_request_{exc.reason}") from exc
    plan = (
        _inverse_from_payload(payload["plan"], inverse_spec, deadline_monotonic)
        if inverse_spec is not None
        else _plan_from_payload(payload["plan"], home=home, config=config)
    )
    request_policy(
        "plan",
        signed_at=signed_at,
        operation_id=plan.operation_id,
        subject=payload["subject"],
        plan_subject=plan.subject(),
    )
    _compare(plan, deadline_monotonic)
    if _read(path, guard_home, expected_sha256, deadline_monotonic) != raw:
        raise TransitionError("authority_repair_request_changed")
    request_policy(
        "window",
        created=payload["created_monotonic"],
        expires=payload["expires_monotonic"],
        now=time.monotonic(),
    )
    require_deadline(deadline_monotonic)
    return plan
