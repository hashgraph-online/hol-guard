"""Trust specification coverage."""

from pathlib import Path

from codex_plugin_scanner.trust_specs import MCP_TRUST_SPEC, PLUGIN_TRUST_SPEC, SKILL_TRUST_SPEC

ROOT = Path(__file__).resolve().parents[1]


def _adapter_weight_map(spec) -> dict[str, float]:
    return {adapter.adapter_id: adapter.weight for adapter in spec.adapters}


def test_skill_trust_spec_matches_hcs_28_baseline():
    assert SKILL_TRUST_SPEC.spec_id == "HCS-28"
    assert SKILL_TRUST_SPEC.profile_id == "hcs-28/baseline"
    assert SKILL_TRUST_SPEC.profile_version == "0.1"
    assert "HCS-28" in SKILL_TRUST_SPEC.derived_from
    assert "HCS-26" in SKILL_TRUST_SPEC.derived_from
    assert _adapter_weight_map(SKILL_TRUST_SPEC) == {
        "verification.review-status": 0.50,
        "verification.publisher-bound": 0.20,
        "verification.repo-commit-integrity": 0.40,
        "verification.manifest-integrity": 0.30,
        "verification.domain-proof": 0.10,
        "metadata.links": 0.30,
        "metadata.description": 0.25,
        "metadata.taxonomy": 0.20,
        "metadata.provenance": 0.25,
        "upvotes": 1.0,
        "safety.cisco-scan": 1.0,
        "repository.health": 1.0,
    }
    assert (ROOT / SKILL_TRUST_SPEC.spec_path).exists()


def test_mcp_and_plugin_specs_follow_hcs_style_profiles():
    assert MCP_TRUST_SPEC.spec_id == "HOL-HCS-MCP-TRUST-DRAFT"
    assert PLUGIN_TRUST_SPEC.spec_id == "HOL-HCS-CODEX-PLUGIN-TRUST-DRAFT"
    assert MCP_TRUST_SPEC.profile_id == "hol-hcs-mcp-trust/baseline"
    assert PLUGIN_TRUST_SPEC.profile_id == "hol-codex-plugin-trust/baseline"
    assert all("." in adapter.adapter_id or adapter.adapter_id == "upvotes" for adapter in MCP_TRUST_SPEC.adapters)
    assert all("." in adapter.adapter_id for adapter in PLUGIN_TRUST_SPEC.adapters)
    assert (ROOT / MCP_TRUST_SPEC.spec_path).exists()
    assert (ROOT / PLUGIN_TRUST_SPEC.spec_path).exists()
