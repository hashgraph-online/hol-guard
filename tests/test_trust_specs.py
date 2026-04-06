"""Trust specification coverage."""

from pathlib import Path

from codex_plugin_scanner.trust_specs import MCP_TRUST_SPEC, PLUGIN_TRUST_SPEC, SKILL_TRUST_SPEC

ROOT = Path(__file__).resolve().parents[1]


def _adapter_weight_map(spec) -> dict[str, float]:
    return {adapter.adapter_id: adapter.weight for adapter in spec.adapters}


def test_skill_trust_spec_inherits_broker_weights():
    assert SKILL_TRUST_SPEC.spec_id == "HOL-HCS-28-SKILL-TRUST-LOCAL-DRAFT"
    assert "HCS-28" in SKILL_TRUST_SPEC.derived_from
    assert "HCS-26" in SKILL_TRUST_SPEC.derived_from
    assert "registry-broker skill trust service" in SKILL_TRUST_SPEC.derived_from
    assert _adapter_weight_map(SKILL_TRUST_SPEC) == {
        "verified": 1.0,
        "safety": 1.0,
        "metadata": 0.75,
    }
    assert (ROOT / SKILL_TRUST_SPEC.spec_path).exists()


def test_mcp_and_plugin_specs_exist_locally():
    assert MCP_TRUST_SPEC.spec_id == "HOL-HCS-MCP-TRUST-DRAFT"
    assert PLUGIN_TRUST_SPEC.spec_id == "HOL-HCS-CODEX-PLUGIN-TRUST-DRAFT"
    assert (ROOT / MCP_TRUST_SPEC.spec_path).exists()
    assert (ROOT / PLUGIN_TRUST_SPEC.spec_path).exists()
