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

from codex_plugin_scanner.guard.consumer import projection
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_consumer_artifact_compose import native_consumer_compose

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

    guard_home: Path | None = None

    def list_cached_advisories(self, *, limit: int = 200) -> list[dict]:
        return self._advisories[:limit]

    def get_artifact_capability(self, harness: str, artifact_id: str) -> None:
        return None

    def find_inventory_item(self, artifact_id: str) -> None:
        return None

    def receipt_decision_counts(self, harness: str, artifact_id: str) -> dict[str, int]:
        return {}

    def list_events(self, *, limit: int = 100) -> list[dict]:
        return []


def _evidence(guard_home: Path, advisories: list[dict], publisher: str | None = _HOL_REGISTRY_PUBLISHER) -> dict:
    """The resident's evidence for a bare artifact of ``publisher`` with the given advisories."""

    store = _FakeStore(advisories)
    store.guard_home = guard_home
    artifact = GuardArtifact(
        artifact_id="codex:project:registry",
        name="registry",
        harness="codex",
        artifact_type="skill",
        source_scope="project",
        config_path="/tmp/registry/SKILL.md",
        publisher=publisher,
    )
    return projection.artifact_evidence(
        store,  # type: ignore[arg-type]
        artifact,
        payload=artifact.to_dict(),
        content_hash="hash",
        previous=None,
    )


def _provenance(guard_home: Path, advisories: list[dict], publisher: str | None = _HOL_REGISTRY_PUBLISHER) -> dict:
    provenance = _evidence(guard_home, advisories, publisher)["provenance"]
    assert isinstance(provenance, dict)
    return provenance


def _verdict(guard_home: Path, advisories: list[dict], prior_approvals: int) -> dict:
    """The resident's scoring recommendation for an artifact with no signals or deltas."""

    scoring = dict(_evidence(guard_home, advisories)["scoring"])
    scoring["prior_approvals"] = prior_approvals

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
            "signals": [],
            **scoring,
        },
        guard_home=guard_home,
    )
    verdict = answer["verdict"]
    assert isinstance(verdict, dict)
    return verdict


class TestRegistryBrokerSkillsAttested:
    """Attested scenario: attestationVerified=True → curated + known-good."""

    _advisories = (_HOL_REGISTRY_ADVISORY_CLEAN,)

    def test_provenance_is_curated_known_good_and_attested(self, native_approval_reuse_runtime: Path) -> None:
        provenance = _provenance(native_approval_reuse_runtime, list(self._advisories))
        assert provenance["source_kind"] == "curated"
        assert provenance["publisher_trust"] == "known-good"
        assert provenance["attestation_verified"] is True

    def test_evidence_refs_contains_advisory_id(self, native_approval_reuse_runtime: Path) -> None:
        refs = _provenance(native_approval_reuse_runtime, list(self._advisories))["evidence_refs"]
        assert "HOL-2025-REGISTRY-001" in refs

    def test_verdict_action_is_allow_for_clean_artifact(self, native_approval_reuse_runtime: Path) -> None:
        verdict = _verdict(native_approval_reuse_runtime, self._advisories, 3)
        assert verdict["action"] == "allow"

    def test_evidence_sources_includes_cloud(self, native_approval_reuse_runtime: Path) -> None:
        verdict = _verdict(native_approval_reuse_runtime, self._advisories, 0)
        assert "cloud" in verdict["evidence_sources"]


class TestRegistryBrokerSkillsNonAttested:
    """Non-attested scenario: no advisory for publisher → self-declared + unknown."""

    def test_provenance_is_self_declared_unknown_and_unattested(self, native_approval_reuse_runtime: Path) -> None:
        provenance = _provenance(native_approval_reuse_runtime, [])
        assert provenance["source_kind"] == "self-declared"
        assert provenance["publisher_trust"] == "unknown"
        assert provenance["attestation_verified"] is False

    def test_evidence_refs_contains_publisher_label(self, native_approval_reuse_runtime: Path) -> None:
        refs = _provenance(native_approval_reuse_runtime, [])["evidence_refs"]
        assert any("publisher:" in ref for ref in refs)

    def test_none_publisher_returns_empty_bundle(self, native_approval_reuse_runtime: Path) -> None:
        bundle = _provenance(native_approval_reuse_runtime, [_HOL_REGISTRY_ADVISORY_CLEAN], None)
        assert bundle["source_kind"] == "none"
        assert bundle["publisher_trust"] == "unknown"


class TestRegistryBrokerSkillsRemediationRequired:
    """Remediation scenario: critical advisory → flagged trust → severity≥9 verdict."""

    _advisories = (_HOL_REGISTRY_ADVISORY_CRITICAL,)

    def test_provenance_is_curated_and_flagged(self, native_approval_reuse_runtime: Path) -> None:
        provenance = _provenance(native_approval_reuse_runtime, list(self._advisories))
        assert provenance["source_kind"] == "curated"
        assert provenance["publisher_trust"] == "flagged"

    def test_verdict_severity_is_nine_or_more(self, native_approval_reuse_runtime: Path) -> None:
        assert _verdict(native_approval_reuse_runtime, self._advisories, 5)["severity"] >= 9

    def test_verdict_action_is_not_allow(self, native_approval_reuse_runtime: Path) -> None:
        assert _verdict(native_approval_reuse_runtime, self._advisories, 5)["action"] != "allow"

    def test_verdict_reasons_mention_flagged_trust(self, native_approval_reuse_runtime: Path) -> None:
        verdict = _verdict(native_approval_reuse_runtime, self._advisories, 0)
        combined = " ".join(verdict["reasons"]).lower()
        assert "flagged" in combined or "advisory" in combined or "trust" in combined

    def test_suppressible_is_false_for_flagged_publisher(self, native_approval_reuse_runtime: Path) -> None:
        assert _verdict(native_approval_reuse_runtime, self._advisories, 0)["suppressible"] is False
