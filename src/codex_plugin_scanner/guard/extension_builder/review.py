"""Explicit human review, bound to immutable discovery rather than untrusted hints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from ..runtime.command_reviewed_literal_matcher import validate_reviewed_literal_argv
from .errors import BuilderError
from .io import object_value
from .models import Discovery, Operation
from .review_invocations import validate_native_bindings
from .schemas import REVIEW_SCHEMA, validate_document
from .validation import https_reference, text

DEFAULT_GUIDANCE = "Inspect the exact target and required permissions before running this operation."


@dataclass(frozen=True, slots=True)
class Decision:
    state: str
    reviewed: bool = False
    rationale: str = ""
    evidence_url: str = ""
    risk_classes: tuple[str, ...] = ("execution",)
    safer_alternative: str = DEFAULT_GUIDANCE
    safe_argv: tuple[tuple[str, ...], ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state,
            "reviewed": self.reviewed,
            "rationale": self.rationale,
            "evidenceUrl": self.evidence_url,
            "riskClasses": list(self.risk_classes),
            "saferAlternative": self.safer_alternative,
            "safeArgv": [list(argv) for argv in self.safe_argv],
        }


@dataclass(frozen=True, slots=True)
class Review:
    discovery_digest: str
    entries: tuple[tuple[str, Decision], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": REVIEW_SCHEMA,
            "discoveryDigest": self.discovery_digest,
            "entries": {key: decision.to_dict() for key, decision in self.entries},
        }

    def by_id(self) -> dict[str, Decision]:
        return dict(self.entries)


def default_review(discovery: Discovery) -> Review:
    state = "review" if discovery.metadata.kind == "cli" else "inherit"
    return Review(discovery.binding, tuple(sorted((row.operation_id, Decision(state)) for row in discovery.operations)))


def _safe_invocations(discovery: Discovery, operation: Operation, decision: Decision) -> None:
    for argv in decision.safe_argv:
        try:
            validate_reviewed_literal_argv(discovery.metadata.executable, argv)
        except ValueError as exc:
            raise BuilderError("unsafe_variant", "Safe variants require a bounded exact literal invocation.") from exc
        if argv[: len(operation.path)] != operation.path:
            raise BuilderError("safe_variant_scope", "Safe arguments must begin with their reviewed operation path.")
        candidates = [row.path for row in discovery.operations if row.path and argv[: len(row.path)] == row.path]
        longest = max(candidates, key=len) if candidates else ()
        if longest != operation.path:
            raise BuilderError(
                "safe_variant_scope", "Review a safe invocation under its most specific known operation."
            )
        if not operation.path and any(not argument.startswith("-") for argument in argv):
            raise BuilderError(
                "safe_variant_scope", "Root safe variants may contain literal flags only, not unknown operations."
            )


def _decision(discovery: Discovery, operation: Operation, value: object) -> Decision:
    row = object_value(value)
    decision = Decision(
        state=cast(str, row["state"]),
        reviewed=cast(bool, row["reviewed"]),
        rationale=text(row["rationale"], maximum=512, empty=True),
        evidence_url=https_reference(row["evidenceUrl"], empty=True),
        risk_classes=tuple(sorted(cast(list[str], row["riskClasses"]))),
        safer_alternative=text(row["saferAlternative"], maximum=256),
        safe_argv=tuple(sorted(tuple(item) for item in cast(list[list[str]], row["safeArgv"]))),
    )
    default_state = "review" if discovery.metadata.kind == "cli" else "inherit"
    allowed = {"review", "block"} if discovery.metadata.kind == "cli" else {"inherit", "allow", "block"}
    if decision.state not in allowed or "execution" not in decision.risk_classes:
        raise BuilderError(
            "review_state", "Review state or execution risk is incompatible with this contribution kind."
        )
    if decision.reviewed:
        if not decision.rationale or not decision.evidence_url:
            raise BuilderError(
                "review_evidence", "Reviewed operations require rationale and an HTTPS evidence reference."
            )
    elif decision != Decision(default_state):
        raise BuilderError("review_required", "Edited operation behavior requires an explicit completed review.")
    if discovery.metadata.kind == "cli" and not operation.path and decision.state == "block":
        raise BuilderError(
            "root_block_scope",
            "Root inventory rows cannot block every invocation; use a scoped native detector for root-only blocking.",
        )
    if decision.safe_argv:
        if discovery.metadata.kind != "cli" or decision.state != "review" or not decision.reviewed:
            raise BuilderError(
                "safe_variant_state", "Only explicitly reviewed, nonblocked CLI operations can have safe variants."
            )
        _safe_invocations(discovery, operation, decision)
    return decision


def load_review(value: object, discovery: Discovery) -> Review:
    payload = validate_document(value, "review")
    if payload["discoveryDigest"] != discovery.binding:
        raise BuilderError(
            "stale_review", "Discovery changed. Regenerate and review the new snapshot before compiling decisions."
        )
    entries = object_value(payload["entries"])
    if set(entries) != {row.operation_id for row in discovery.operations}:
        raise BuilderError("review_operations", "Review must contain exactly the operations in its discovery snapshot.")
    decisions = {row.operation_id: _decision(discovery, row, entries[row.operation_id]) for row in discovery.operations}
    safe_argv = [argv for decision in decisions.values() for argv in decision.safe_argv]
    if len(safe_argv) > 256 or len(set(safe_argv)) != len(safe_argv):
        raise BuilderError("safe_variant_limit", "Safe invocations must be unique and stay within the aggregate limit.")
    if discovery.metadata.kind == "cli":
        safe_rows = tuple(
            (operation, argv)
            for operation in discovery.operations
            for argv in decisions[operation.operation_id].safe_argv
        )
        blocked_ids = frozenset(key for key, decision in decisions.items() if decision.state == "block")
        validate_native_bindings(discovery, safe_rows, blocked_ids)
    return Review(discovery.binding, tuple(sorted(decisions.items())))
