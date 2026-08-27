from __future__ import annotations

import json
import re
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
MANAGED_CONTROLS_DOCS = (
    ROOT / "docs" / "guard" / "managed-controls-local-extensions.md",
    ROOT / "docs" / "guard" / "managed-controls-cloud-operator-guide.md",
    ROOT / "docs" / "guard" / "managed-controls-catalog-mismatch-recovery.md",
    ROOT / "docs" / "guard" / "managed-controls-policy-migration.md",
    ROOT / "docs" / "guard" / "managed-controls-support-runbook.md",
    ROOT / "docs" / "guard" / "managed-controls-invalid-bundle-incident-runbook.md",
    ROOT / "docs" / "guard" / "managed-controls-rollback-runbook.md",
    ROOT / "docs" / "guard" / "managed-controls-release-notes.md",
)
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
EXTENSION_CONTROL_API_PATH = (
    ROOT / "src" / "codex_plugin_scanner" / "guard" / "daemon" / "extension_control_api.py"
)
MANAGED_CONTROLS_API_PATH = (
    ROOT / "src" / "codex_plugin_scanner" / "guard" / "daemon" / "managed_controls_api.py"
)
POLICY_COMMAND_PATH = (
    ROOT / "src" / "codex_plugin_scanner" / "guard" / "cli" / "commands_dispatch_policy_document.py"
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


def test_managed_controls_user_and_operator_documentation_is_complete() -> None:
    documents = {path.name: path.read_text(encoding="utf-8") for path in MANAGED_CONTROLS_DOCS}

    local_guide = documents["managed-controls-local-extensions.md"]
    assert "hol-guard command controls status" in local_guide
    assert "hol-guard command controls preview" in local_guide
    assert "command-activity-privacy.md" in local_guide

    operator_guide = documents["managed-controls-cloud-operator-guide.md"]
    assert "Guard Cloud operator surface" in operator_guide
    assert "Use **Managed controls** at `/guard/controls`" in operator_guide
    assert "Code presence alone does not prove" in operator_guide
    assert "guard.controls.publish" in operator_guide
    assert "release-3-0-cloud-control-inventory.md" not in operator_guide
    assert "historical branch pin" in operator_guide
    assert "These projections prove device-local state only" in operator_guide

    mismatch = documents["managed-controls-catalog-mismatch-recovery.md"]
    assert "digest-only observation" in mismatch
    assert "does not advertise negotiated capabilities" in mismatch
    assert "`connect status` also does not prove them" in mismatch
    assert "A matching local digest alone is insufficient" in mismatch

    migration = documents["managed-controls-policy-migration.md"]
    assert "hol-guard policy export" in migration
    assert "policy export --include-provenance" in migration
    assert "provenance-redacted export cannot represent workspace-scoped rows" in migration
    assert "hol-guard policy validate" in migration
    assert "hol-guard policy diff" in migration
    assert "Unmapped legacy rules remain" in migration
    assert "no supported operator command that validates a proposed Cloud Control Set" in migration
    assert "Migrate through Guard Cloud" in migration
    assert "Run simulation and require zero broadening" in migration

    support = documents["managed-controls-support-runbook.md"]
    assert "set -o pipefail" in support
    assert "jq -e '{revision, catalog_digest, health}'" in support
    assert "cannot become an empty successful evidence file" in support
    assert "Do not attach unfiltered" in support
    assert "hol-guard doctor --json" in support
    assert "scope_rule_counts: ([.scopes | to_entries[] | .value])" in support
    assert "deliberately discards every scope identifier key" in support

    invalid_bundle = documents["managed-controls-invalid-bundle-incident-runbook.md"]
    assert "Correct the source Control Set" in invalid_bundle
    assert "Keep the failed candidate inactive" in invalid_bundle

    rollback = documents["managed-controls-rollback-runbook.md"]
    assert "Guard Cloud Control Set rollback" in rollback
    assert "exact current candidate bundle hash and version" in rollback
    assert "Available Local device-settings restore" in rollback

    release_notes = documents["managed-controls-release-notes.md"]
    assert "Guard Cloud now includes Extension-first Control Set authoring" in release_notes
    assert "default fail-closed" in release_notes
    for path in MANAGED_CONTROLS_DOCS[:-1]:
        assert path.name in release_notes

    stale_cloud_boundary = re.compile(
        r"corresponding (?:Guard )?Cloud PR|Cloud PR lands|Cloud implementation ships",
        re.IGNORECASE,
    )
    for name, document in documents.items():
        assert stale_cloud_boundary.search(document) is None, f"stale Cloud boundary in {name}"


def test_managed_controls_documentation_uses_only_resolvable_local_links() -> None:
    for document_path in MANAGED_CONTROLS_DOCS:
        text = document_path.read_text(encoding="utf-8")
        assert "http://" not in text
        assert "https://" not in text
        assert "Authorization:" not in text
        assert "Bearer " not in text
        for raw_target in MARKDOWN_LINK.findall(text):
            target = raw_target.split("#", 1)[0]
            if not target:
                continue
            relative_target = Path(target)
            assert not relative_target.is_absolute(), f"absolute link in {document_path}: {target}"
            assert ".." not in relative_target.parts, f"escaping link in {document_path}: {target}"
            resolved = document_path.parent / relative_target
            assert resolved.is_file(), f"broken link in {document_path}: {target}"

        if "| jq " in text:
            assert "set -o pipefail" in text
            assert "| jq -e " in text


def test_support_projection_fields_exist_in_current_local_apis() -> None:
    extension_api = "\n".join(
        (
            EXTENSION_CONTROL_API_PATH.read_text(encoding="utf-8"),
            MANAGED_CONTROLS_API_PATH.read_text(encoding="utf-8"),
        )
    )
    policy_command = POLICY_COMMAND_PATH.read_text(encoding="utf-8")

    for field in ("schema_version", "control_schema_version", "catalog_digest", "revision", "health"):
        assert f'"{field}"' in extension_api
    for field in ("digest", "rules", "compiled_rows", "actions", "scopes"):
        assert f'"{field}"' in policy_command


def test_managed_controls_release_runbook_uses_repository_tooling() -> None:
    release_runbook = (ROOT / "docs" / "guard" / "managed-controls-release-runbook.md").read_text(
        encoding="utf-8"
    )
    assert "uv run python scripts/ci/managed_controls_release_gate.py" in release_runbook
    assert "uv run pytest tests/managed_controls" in release_runbook
    assert "uv run pytest tests/test_managed_controls_contract_docs.py" in release_runbook
    assert "\npython scripts/ci/managed_controls_release_gate.py" not in release_runbook
    assert "\npytest tests/" not in release_runbook
