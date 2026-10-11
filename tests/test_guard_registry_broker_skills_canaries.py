"""P11.2 — first-party canary tests for registry-broker-skills.

Validates Guard's provenance and verdict logic against the real
@hol-org/registry (registry-broker-skills) package in three states:
attested, non-attested, and remediation-required.

These tests verify that:
- An attested HOL registry package resolves to curated + known-good trust
- A non-attested package resolves to self-declared + unknown trust
- A package with a critical advisory triggers the flagged trust path
  and produces a severity≥9 verdict (remediation required)
"""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.consumer.service import _scoring_inputs, build_provenance_bundle
from codex_plugin_scanner.guard.native_consumer_artifact_compose import native_consumer_compose
from codex_plugin_scanner.guard.types import HistoryContext, ProvenanceBundle

_HOL_REGISTRY_PUBLISHER = "@hol-org/registry"
_HOL_REGISTRY_ADVISORY_CLEAN = {
    "publisher": _HOL_REGISTRY_PUBLISHER,
    "advisoryId": "HOL-2025-REGISTRY-001",
    "severity": "none",
    "signatureVerified": True,
    "attestationVerified": True,
}
_HOL_REGISTRY_ADVISORY_CRITICAL = {
    "publisher": _HOL_REGISTRY_PUBLISHER,
    "advisoryId": "HOL-2025-REGISTRY-CRIT",
    "severity": "critical",
    "signatureVerified": True,
    "attestationVerified": False,
}


class _FakeStore:
    """Minimal GuardStore stand-in that returns a pre-loaded advisory list."""

    def __init__(self, advisories: list[dict]) -> None:
        self._advisories = advisories

    def list_cached_advisories(self, *, limit: int = 200) -> list[dict]:
        return self._advisories[:limit]


def _verdict(guard_home: Path, provenance: ProvenanceBundle, history: HistoryContext) -> dict:
    """The resident's scoring recommendation for an artifact with no signals or deltas."""

    answer = native_consumer_compose(
        "current_action",
        {
            "removed": False,
            "artifact_type": "skill",
            "configured_action": None,
            "guard_default_action": None,
            "first_seen": False,
            "changed": False,
            "effective_default_action": None,
            "config_changed_hash_action": "require-reapproval",
            "config_default_action": "warn",
            "skill_directory_identity_reusable": None,
            **_scoring_inputs((), (), provenance, history),
        },
        guard_home=guard_home,
    )
    verdict = answer["verdict"]
    assert isinstance(verdict, dict)
    return verdict


class TestRegistryBrokerSkillsAttested:
    """Attested scenario: attestationVerified=True → curated + known-good."""

    def _provenance(self) -> ProvenanceBundle:
        store = _FakeStore([_HOL_REGISTRY_ADVISORY_CLEAN])
        return build_provenance_bundle(store, _HOL_REGISTRY_PUBLISHER)  # type: ignore[arg-type]

    def test_source_kind_is_curated(self) -> None:
        assert self._provenance().source_kind == "curated"

    def test_publisher_trust_is_known_good(self) -> None:
        assert self._provenance().publisher_trust == "known-good"

    def test_attestation_verified_is_true(self) -> None:
        assert self._provenance().attestation_verified is True

    def test_evidence_refs_contains_advisory_id(self) -> None:
        refs = self._provenance().evidence_refs
        assert "HOL-2025-REGISTRY-001" in refs

    def test_verdict_action_is_allow_for_clean_artifact(self, native_approval_reuse_runtime: Path) -> None:
        verdict = _verdict(
            native_approval_reuse_runtime, self._provenance(), HistoryContext(prior_approvals=3, prior_incidents=0)
        )
        assert verdict["action"] == "allow"

    def test_evidence_sources_includes_cloud(self, native_approval_reuse_runtime: Path) -> None:
        verdict = _verdict(
            native_approval_reuse_runtime, self._provenance(), HistoryContext(prior_approvals=0, prior_incidents=0)
        )
        assert "cloud" in verdict["evidence_sources"]


class TestRegistryBrokerSkillsNonAttested:
    """Non-attested scenario: no advisory for publisher → self-declared + unknown."""

    def _provenance(self) -> ProvenanceBundle:
        store = _FakeStore([])
        return build_provenance_bundle(store, _HOL_REGISTRY_PUBLISHER)  # type: ignore[arg-type]

    def test_source_kind_is_self_declared(self) -> None:
        assert self._provenance().source_kind == "self-declared"

    def test_publisher_trust_is_unknown(self) -> None:
        assert self._provenance().publisher_trust == "unknown"

    def test_attestation_verified_is_false(self) -> None:
        assert self._provenance().attestation_verified is False

    def test_evidence_refs_contains_publisher_label(self) -> None:
        refs = self._provenance().evidence_refs
        assert any("publisher:" in ref for ref in refs)

    def test_none_publisher_returns_empty_bundle(self) -> None:
        store = _FakeStore([_HOL_REGISTRY_ADVISORY_CLEAN])
        bundle = build_provenance_bundle(store, None)  # type: ignore[arg-type]
        assert bundle.source_kind == "none"
        assert bundle.publisher_trust == "unknown"


class TestRegistryBrokerSkillsRemediationRequired:
    """Remediation scenario: critical advisory → flagged trust → severity≥9 verdict."""

    def _provenance(self) -> ProvenanceBundle:
        store = _FakeStore([_HOL_REGISTRY_ADVISORY_CRITICAL])
        return build_provenance_bundle(store, _HOL_REGISTRY_PUBLISHER)  # type: ignore[arg-type]

    def test_source_kind_is_curated(self) -> None:
        assert self._provenance().source_kind == "curated"

    def test_publisher_trust_is_flagged(self) -> None:
        assert self._provenance().publisher_trust == "flagged"

    def test_verdict_severity_is_nine_or_more(self, native_approval_reuse_runtime: Path) -> None:
        verdict = _verdict(
            native_approval_reuse_runtime, self._provenance(), HistoryContext(prior_approvals=5, prior_incidents=0)
        )
        assert verdict["severity"] >= 9

    def test_verdict_action_is_not_allow(self, native_approval_reuse_runtime: Path) -> None:
        verdict = _verdict(
            native_approval_reuse_runtime, self._provenance(), HistoryContext(prior_approvals=5, prior_incidents=0)
        )
        assert verdict["action"] != "allow"

    def test_verdict_reasons_mention_flagged_trust(self, native_approval_reuse_runtime: Path) -> None:
        verdict = _verdict(
            native_approval_reuse_runtime, self._provenance(), HistoryContext(prior_approvals=0, prior_incidents=0)
        )
        combined = " ".join(verdict["reasons"]).lower()
        assert "flagged" in combined or "advisory" in combined or "trust" in combined

    def test_suppressible_is_false_for_flagged_publisher(self, native_approval_reuse_runtime: Path) -> None:
        verdict = _verdict(
            native_approval_reuse_runtime, self._provenance(), HistoryContext(prior_approvals=0, prior_incidents=0)
        )
        assert verdict["suppressible"] is False
