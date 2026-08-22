from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DECISION_PATH = ROOT / "contracts" / "managed-controls" / "v1" / "product-decision.json"
ADR_PATH = ROOT / "docs" / "guard" / "adr" / "0011-extension-first-managed-controls.md"
ARCHITECTURE_PATH = ROOT / "docs" / "guard" / "command-extension-architecture.md"
GLOSSARY_PATH = ROOT / "docs" / "guard" / "managed-controls-glossary.md"
NAVIGATION_PATH = ROOT / "dashboard" / "src" / "shell-navigation-model.ts"
RULES_PAGE_PATH = ROOT / "dashboard" / "src" / "policy-workspace-page.tsx"
APP_PATH = ROOT / "dashboard" / "src" / "app.tsx"
APP_TITLE_TEST_PATH = ROOT / "dashboard" / "src" / "scrg171-172.test.ts"
DASHBOARD_BUNDLE_PATH = (
    ROOT
    / "src"
    / "codex_plugin_scanner"
    / "guard"
    / "daemon"
    / "static"
    / "assets"
    / "guard-dashboard.js"
)
POLICY_BUNDLE_PATH = (
    ROOT
    / "src"
    / "codex_plugin_scanner"
    / "guard"
    / "daemon"
    / "static"
    / "assets"
    / "chunks"
    / "policy-workspace-page.js"
)

EXPECTED_PRODUCT_DECISION: dict[str, object] = {
    "authority_modes": [
        "personal-shared",
        "workspace-shared",
        "managed-restrictive",
    ],
    "compatibility": {
        "internal_policy_bundle_names_retained": True,
        "policy_route_aliases_retained": True,
        "technical_guard_policy_names_retained": True,
    },
    "decision_id": "hol-guard.extension-first-managed-controls.v1",
    "definitions": {
        "control_set": (
            "A versioned, scoped, simulated, reviewed, signed, deployed, acknowledged, "
            "and auditable collection of Extension controls and contextual rules in Guard Cloud."
        ),
        "deployment": (
            "A signed Control Set version delivered to an eligible runtime cohort with "
            "acknowledgement, drift, pause, rollback, and audit state."
        ),
        "detector_rule": (
            "A Local runtime implementation detail that recognizes security-relevant evidence "
            "for an Extension permission. Detector rules do not grant authority and are not "
            "authored by Cloud by default."
        ),
        "exception": (
            "A time-bounded, reviewed contextual deviation. In release 3.0, an exception "
            "cannot weaken a managed-restrictive Extension or permission block."
        ),
        "extension": (
            "A stable Local capability boundary for a protected tool or capability domain, "
            "such as Git, Docker, Kubernetes, GitHub, npm, or MCP."
        ),
        "local_setting": (
            "A device-specific Extension or permission preference that can preserve or "
            "strengthen protection but cannot weaken a managed restriction or required floor."
        ),
        "managed_restriction": (
            "A signed workspace restriction that can disable an Extension, disable a permission, "
            "or activate global lockdown and cannot be weakened locally."
        ),
        "permission": (
            "A stable, independently configurable capability inside an Extension. Permissions "
            "own the detector rules needed to recognize that capability."
        ),
        "remembered_rule": (
            "A contextual local decision remembered from an approval. It is not an Extension "
            "setting and cannot bypass a managed restriction or required floor."
        ),
    },
    "enforcement": {
        "cloud_must_not_redefine_detector_matchers": True,
        "contextual_policy_precedence_preserved": True,
        "local_registry_authoritative": True,
        "managed_restrictive_actions": [
            "disable-extension",
            "disable-permission",
            "global-lockdown",
        ],
        "non_weakenable_authority_requires_negotiation": True,
        "package_manager_delegate": "package-firewall",
    },
    "product_language": {
        "cloud_primary_object": "Control Set",
        "cloud_surface": "Managed controls",
        "local_extension_surface": "Extensions",
        "local_rule_surface": "Rules & exceptions",
    },
    "schema_version": 1,
}


def _decision() -> dict[str, object]:
    value = json.loads(DECISION_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_managed_controls_decision_is_exact_versioned_and_complete() -> None:
    raw_decision = DECISION_PATH.read_text(encoding="utf-8")
    assert _decision() == EXPECTED_PRODUCT_DECISION
    assert raw_decision == json.dumps(EXPECTED_PRODUCT_DECISION, indent=2) + "\n"


def test_managed_controls_decision_preserves_security_boundaries() -> None:
    enforcement = _decision()["enforcement"]
    assert isinstance(enforcement, dict)
    assert enforcement["local_registry_authoritative"] is True
    assert enforcement["cloud_must_not_redefine_detector_matchers"] is True
    assert enforcement["contextual_policy_precedence_preserved"] is True
    assert enforcement["non_weakenable_authority_requires_negotiation"] is True
    assert enforcement["managed_restrictive_actions"] == [
        "disable-extension",
        "disable-permission",
        "global-lockdown",
    ]
    assert enforcement["package_manager_delegate"] == "package-firewall"


def test_adr_glossary_and_extension_architecture_share_the_authority_model() -> None:
    adr = ADR_PATH.read_text(encoding="utf-8")
    architecture = ARCHITECTURE_PATH.read_text(encoding="utf-8")
    glossary = GLOSSARY_PATH.read_text(encoding="utf-8")
    assert "hol-guard.extension-first-managed-controls.v1" in adr
    assert "contracts/managed-controls/v1/product-decision.json" in adr
    assert "(adr/0011-extension-first-managed-controls.md)" in architecture
    assert "Extension-first authority boundary" in architecture
    for term in (
        "Extension",
        "Permission",
        "Detector rule",
        "Remembered rule",
        "Control Set",
        "Managed restriction",
        "Deployment",
        "Exception",
    ):
        assert term in glossary


def test_local_navigation_uses_product_language_without_breaking_routes() -> None:
    navigation = NAVIGATION_PATH.read_text(encoding="utf-8")
    rules_page = RULES_PAGE_PATH.read_text(encoding="utf-8")
    app = APP_PATH.read_text(encoding="utf-8")
    app_title_test = APP_TITLE_TEST_PATH.read_text(encoding="utf-8")
    assert 'href: "/policy"' in navigation
    assert 'label: "Rules & exceptions"' in navigation
    assert 'shortLabel: "Rules"' in navigation
    assert 'href: "/extensions"' in navigation
    assert 'description: "Tools and capabilities protected on this device"' in navigation
    assert 'eyebrow="Rules & exceptions"' in rules_page
    assert 'title="Remembered decisions and exceptions"' in rules_page
    assert "Configure tools and capability posture in Extensions." in rules_page
    assert 'if (view === "policy") return "Rules & exceptions";' in app
    assert 'viewTitle("policy") === "Rules & exceptions"' in app_title_test
    assert "Managed extensions and integrations" not in navigation


def test_packaged_dashboard_matches_the_reviewed_product_vocabulary() -> None:
    dashboard_bundle = DASHBOARD_BUNDLE_PATH.read_text(encoding="utf-8")
    policy_bundle = POLICY_BUNDLE_PATH.read_text(encoding="utf-8")

    assert "Rules & exceptions" in dashboard_bundle
    assert "Tools and capabilities protected on this device" in dashboard_bundle
    assert "Rules & exceptions" in policy_bundle
    assert "Remembered decisions and exceptions" in policy_bundle
    assert "Configure tools and capability posture in Extensions." in policy_bundle

    for stale_copy in (
        "Managed extensions and integrations",
        "Remembered rules and exceptions",
        "Configure protection behavior in Settings.",
    ):
        assert stale_copy not in dashboard_bundle
        assert stale_copy not in policy_bundle
