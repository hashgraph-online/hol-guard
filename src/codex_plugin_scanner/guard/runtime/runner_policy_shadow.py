"""Which stored policy bundle shadows a v2 candidate, and what their comparison decides.

Both answers come from the runner-authority resident; this module only shapes
the requests and checks the replies.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..models import PolicyDecision
from ..native_runner_authority import native_runner_authority
from .runner_native_authority import _malformed, _typed

_SHADOW_KEYS = ("harness", "scope", "artifact_id", "artifact_hash", "workspace", "publisher", "action", "expires_at")


def policy_shadow_source(
    candidate: Mapping[str, object],
    *,
    stored_legacy: object,
    existing: object,
) -> tuple[str | None, bool]:
    """Which stored bundle shadows a v2 candidate, and whether it only evaluates.

    Answers ``"stored"``, ``"existing"`` or ``None`` for the shadow. Only the
    fields the choice reads travel: each bundle's version and issue time, and
    the candidate's default mode. Whole bundles, escaped for transport, could
    outgrow one request even when each passed bundle validation.
    """

    def header(bundle: object) -> dict[str, object] | None:
        if not isinstance(bundle, dict):
            return None
        return {key: bundle[key] for key in ("contractVersion", "issuedAt") if key in bundle}

    candidate_fields: dict[str, object] = header(dict(candidate)) or {}
    payload_field = candidate.get("payload")
    spec = payload_field.get("spec") if isinstance(payload_field, dict) else None
    defaults = spec.get("defaults") if isinstance(spec, dict) else None
    if isinstance(defaults, dict) and "mode" in defaults:
        candidate_fields["payload"] = {"spec": {"defaults": {"mode": defaults["mode"]}}}
    payload = native_runner_authority(
        "policy_shadow_source",
        {"candidate": candidate_fields, "stored_legacy": header(stored_legacy), "existing": header(existing)},
    )
    source = _typed(payload, "legacy", str, nullable=True)
    if source not in (None, "stored", "existing"):
        raise _malformed()
    return source, _typed(payload, "evaluating", bool)


def policy_shadow_verdict(
    legacy: Sequence[PolicyDecision],
    canonical: Sequence[PolicyDecision],
    *,
    evaluating: bool,
    canonical_enforcement: bool,
) -> tuple[tuple[str, ...], str | None]:
    """Where the legacy and canonical rows disagree, and the refusal that follows.

    Rust answers both: the reason codes to record, and
    ``"canonical_shadow_mismatch"`` when a rollout device must keep the policy
    it already has, else ``None``.
    """

    def rows(decisions: Sequence[PolicyDecision]) -> list[dict[str, object]]:
        return [{key: getattr(decision, key) for key in _SHADOW_KEYS} for decision in decisions]

    payload = native_runner_authority(
        "policy_shadow_verdict",
        {
            "legacy": rows(legacy),
            "canonical": rows(canonical),
            "evaluating": evaluating,
            "canonical_enforcement": canonical_enforcement,
        },
    )
    reasons = _typed(payload, "reason_codes", list)
    if not all(isinstance(reason, str) for reason in reasons):
        raise _malformed()
    rejection = _typed(payload, "rejection", str, nullable=True)
    if rejection not in (None, "canonical_shadow_mismatch"):
        raise _malformed()
    return tuple(reasons), rejection
