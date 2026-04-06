"""Local trust specifications used by the scanner."""

from __future__ import annotations

from .trust_models import TrustAdapterSpec, TrustSpecDefinition

SKILL_TRUST_SPEC = TrustSpecDefinition(
    spec_id="HOL-HCS-28-SKILL-TRUST-LOCAL-DRAFT",
    version="0.1.0",
    label="Skill Trust",
    spec_path="docs/trust/skill-trust-local.md",
    derived_from=(
        "HCS-28",
        "HCS-26",
        "registry-broker skill trust service",
    ),
    adapters=(
        TrustAdapterSpec(
            adapter_id="verified",
            label="Verification Signals",
            weight=1.0,
            component_keys=(
                "score",
                "publisherBound",
                "repoCommitIntegrity",
                "manifestIntegrity",
                "domainProof",
            ),
        ),
        TrustAdapterSpec(
            adapter_id="safety",
            label="Safety Signals",
            weight=1.0,
            component_keys=("score",),
        ),
        TrustAdapterSpec(
            adapter_id="metadata",
            label="Metadata Completeness",
            weight=0.75,
            component_keys=("score", "links", "description", "taxonomy", "provenance"),
        ),
    ),
)

MCP_TRUST_SPEC = TrustSpecDefinition(
    spec_id="HOL-HCS-MCP-TRUST-DRAFT",
    version="0.1.0",
    label="MCP Server Trust",
    spec_path="docs/trust/mcp-trust-draft.md",
    derived_from=("HCS-26", "HCS-28", "Codex MCP verification model"),
    adapters=(
        TrustAdapterSpec(
            adapter_id="verification",
            label="Verification Signals",
            weight=1.0,
            component_keys=("score", "configIntegrity", "executionSafety", "transportSecurity"),
        ),
        TrustAdapterSpec(
            adapter_id="metadata",
            label="Configuration Completeness",
            weight=0.75,
            component_keys=("score", "serverNaming", "commandOrEndpoint", "configShape"),
        ),
    ),
)

PLUGIN_TRUST_SPEC = TrustSpecDefinition(
    spec_id="HOL-HCS-CODEX-PLUGIN-TRUST-DRAFT",
    version="0.1.0",
    label="Codex Plugin Trust",
    spec_path="docs/trust/plugin-trust-draft.md",
    derived_from=("HCS-26", "HCS-28", "scanner quality gate"),
    adapters=(
        TrustAdapterSpec(
            adapter_id="verification",
            label="Manifest And Surface Integrity",
            weight=1.0,
            component_keys=("score", "manifestIntegrity", "interfaceIntegrity", "pathSafety", "marketplaceAlignment"),
        ),
        TrustAdapterSpec(
            adapter_id="security",
            label="Security Posture",
            weight=1.0,
            component_keys=("score", "disclosure", "license", "secretHygiene", "mcpSafety", "approvalHygiene"),
        ),
        TrustAdapterSpec(
            adapter_id="metadata",
            label="Metadata Completeness",
            weight=0.75,
            component_keys=("score", "documentation", "manifestMetadata", "discoverability", "provenance"),
        ),
        TrustAdapterSpec(
            adapter_id="operations",
            label="Operational Hygiene",
            weight=0.75,
            component_keys=("score", "actionPinning", "permissionScope", "untrustedCheckout", "updateAutomation"),
        ),
    ),
)
