"""Current source admission must preserve the separate historical auth authority."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from tests import claude_launcher_conformance as conformance

Evidence = tuple[dict[str, Any], dict[str, Any]]


@pytest.fixture
def evidence() -> Evidence:
    root = conformance.ROOT
    binding = json.loads((root / conformance.CURRENT_FIXTURE).read_bytes())
    inputs = {
        "historical_vectors": (root / conformance.HISTORICAL_FIXTURE).read_bytes(),
        "historical_generator": (root / conformance.HISTORICAL_GENERATOR).read_bytes(),
        "sources": {
            name: (root / "src/codex_plugin_scanner/guard" / name).read_bytes()
            for name in conformance.MODULES | {conformance.MARKER}
        },
    }
    return binding, inputs


def test_current_bridge_binding_preserves_historical_auth_authority(evidence: Evidence) -> None:
    binding, inputs = evidence
    result = conformance.validate_current_conformance(binding, **inputs)
    assert result["python_execution"] == "current_adapter_registered_python_argv"
    history = json.loads(inputs["historical_vectors"])
    assert result["bridge_modules"][conformance.BRIDGE] != history["bridge_modules"][conformance.BRIDGE]
    assert result["historical_auth_provenance"]["historical_bridge_executed"] is False
    assert result["installed_artifact"] is result["qualification_complete"] is False


@pytest.mark.parametrize(
    "case, reason",
    [
        ("not_object", "current_conformance_shape_invalid"),
        ("missing_module", "current_module_set_invalid"),
        ("unexpected_module", "current_module_set_invalid"),
        ("malformed_digest", "current_module_digest_invalid"),
        ("wrong_revision", "current_source_identity_invalid"),
        ("wrong_tree", "current_source_identity_invalid"),
        ("historical_execution_claim", "historical_auth_bytes_changed"),
        ("wrong_import_delta", "reviewed_import_delta_invalid"),
    ],
)
def test_malformed_current_binding_cannot_admit_source(evidence: Evidence, case: str, reason: str) -> None:
    binding, inputs = evidence
    value: object = binding
    if case == "not_object":
        value = []
    elif case == "missing_module":
        del binding["bridge_modules"][conformance.BRIDGE]
    elif case == "unexpected_module":
        binding["bridge_modules"]["../unbound.py"] = "0" * 64
    elif case == "malformed_digest":
        binding["bridge_modules"][conformance.BRIDGE] = True
    elif case == "wrong_revision":
        binding["source_revision"] = "0" * 40
    elif case == "wrong_tree":
        binding["source_tree"] = "0" * 40
    elif case == "historical_execution_claim":
        binding["historical_auth_provenance"]["historical_bridge_executed"] = True
    else:
        binding["reviewed_import_delta"]["added"] = "from unreviewed import marker"
    with pytest.raises(ValueError, match=reason):
        conformance.validate_current_conformance(value, **inputs)


@pytest.mark.parametrize("name", sorted(conformance.MODULES | {conformance.MARKER}))
def test_current_module_byte_drift_is_rejected(evidence: Evidence, name: str) -> None:
    binding, inputs = evidence
    inputs["sources"][name] += b"\n# changed after source binding\n"
    with pytest.raises(ValueError, match="current_module_source_drift"):
        conformance.validate_current_conformance(binding, **inputs)


@pytest.mark.parametrize(
    "content, pin", [("historical_vectors", "fixture_sha256"), ("historical_generator", "generator_sha256")]
)
def test_historical_bytes_cannot_be_relabelled_with_a_new_pin(evidence: Evidence, content: str, pin: str) -> None:
    binding, inputs = evidence
    inputs[content] += b"\n"
    binding["historical_auth_provenance"][pin] = hashlib.sha256(inputs[content]).hexdigest()
    with pytest.raises(ValueError, match="historical_auth_bytes_changed"):
        conformance.validate_current_conformance(binding, **inputs)


def test_repinning_an_extra_bridge_edit_cannot_bypass_reviewed_import_delta(evidence: Evidence) -> None:
    binding, inputs = evidence
    current = inputs["sources"][conformance.BRIDGE].replace(
        b"_HOOK_DEADLINE_SECONDS = 8", b"_HOOK_DEADLINE_SECONDS = 9"
    )
    assert current != inputs["sources"][conformance.BRIDGE]
    inputs["sources"][conformance.BRIDGE] = current
    changed = hashlib.sha256(current).hexdigest()
    binding["bridge_modules"][conformance.BRIDGE] = changed
    binding["reviewed_import_delta"]["current_sha256"] = changed
    with pytest.raises(ValueError, match="reviewed_import_delta_mismatch"):
        conformance.validate_current_conformance(binding, **inputs)


def test_repinning_current_transport_cannot_relabel_historical_authority(evidence: Evidence) -> None:
    binding, inputs = evidence
    name = "adapters/claude_daemon_hook_transport.py"
    inputs["sources"][name] += b"\n# changed transport\n"
    binding["bridge_modules"][name] = hashlib.sha256(inputs["sources"][name]).hexdigest()
    with pytest.raises(ValueError, match="historical_transport_source_drift"):
        conformance.validate_current_conformance(binding, **inputs)


def test_repinning_marker_source_cannot_retain_the_original_current_source_identity(evidence: Evidence) -> None:
    binding, inputs = evidence
    name = conformance.MARKER
    inputs["sources"][name] += b"\nCLAUDE_GUARD_DAEMON_HOOK_MARKER = 'unreviewed'\n"
    binding["marker_source"]["sha256"] = hashlib.sha256(inputs["sources"][name]).hexdigest()
    with pytest.raises(ValueError, match="current_marker_binding_changed"):
        conformance.validate_current_conformance(binding, **inputs)
