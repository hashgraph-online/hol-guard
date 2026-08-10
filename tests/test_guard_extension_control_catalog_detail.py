from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiService
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    COMMAND_EXTENSION_SCHEMA_VERSION,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import CONTROL_SCHEMA_VERSION
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore

_FIXTURE = Path(__file__).parent / "fixtures" / "extension-controls" / "catalog-baseline.v1.json"
_API_SCHEMA = "guard.daemon.extension-controls.v1"


def _service(tmp_path: Path) -> ExtensionControlApiService:
    view = ExtensionControlAuthorityView(
        AuthorityHealth.PROTECTED,
        1,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (),
    )
    return ExtensionControlApiService(
        store=GuardStore(tmp_path / "guard-home"),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(view),
    )


def _identity_snapshot() -> dict[str, object]:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    return {
        "catalog_digest": registry.catalog_digest,
        "extension_count": len(registry.extensions),
        "extension_ids": [extension.extension_id for extension in registry.extensions],
        "permission_count": sum(len(extension.permissions) for extension in registry.extensions),
        "permission_ids": [
            permission.permission_id for extension in registry.extensions for permission in extension.permissions
        ],
        "rule_count": sum(len(extension.rules) for extension in registry.extensions),
        "rule_ids": [rule.rule_id for extension in registry.extensions for rule in extension.rules],
    }


def test_catalog_identity_matches_generated_baseline_fixture() -> None:
    baseline = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    actual = _identity_snapshot()
    for key, value in actual.items():
        assert baseline[key] == value, f"canonical extension-control baseline changed at {key}"
    assert baseline["daemon_api_schema"] == _API_SCHEMA
    assert baseline["extension_schema_version"] == COMMAND_EXTENSION_SCHEMA_VERSION
    assert baseline["control_schema_version"] == CONTROL_SCHEMA_VERSION
    assert baseline["overview_route"] == "/extensions"
    assert baseline["installed_browser_config"] == "dashboard/playwright.installed.config.ts"


def test_catalog_exposes_deterministic_full_extension_permission_and_rule_contract(tmp_path: Path) -> None:
    service = _service(tmp_path)
    payload = service.catalog()
    repeated = service.catalog()
    assert payload == repeated
    assert payload["schema_version"] == _API_SCHEMA
    assert payload["control_schema_version"] == CONTROL_SCHEMA_VERSION
    assert payload["catalog_digest"] == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert payload["limits"] == {
        "max_body_bytes": 1_000_000,
        "max_controls": 4096,
        "max_observations": 2048,
    }

    extensions = payload["extensions"]
    assert isinstance(extensions, list)
    assert [item["extension_id"] for item in extensions] == sorted(item["extension_id"] for item in extensions)

    canonical_bytes = json.dumps(
        extensions,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    assert hashlib.sha256(canonical_bytes).hexdigest() == payload["catalog_digest"]

    global_rule_owners: Counter[str] = Counter()
    global_permission_ids: set[str] = set()
    for extension in extensions:
        assert isinstance(extension, dict)
        extension_id = extension["extension_id"]
        assert extension["schema_version"] == COMMAND_EXTENSION_SCHEMA_VERSION
        assert extension["permission_count"] == len(extension["permissions"])
        assert extension["rule_count"] == len(extension["rules"])
        assert isinstance(extension["aliases"], list)
        assert isinstance(extension["dependencies"], list)
        assert isinstance(extension["conflicts"], list)
        assert isinstance(extension["reference_urls"], list)

        rule_ids = {rule["rule_id"] for rule in extension["rules"]}
        owned_rule_ids: set[str] = set()
        extension_permission_ids: set[str] = set()
        for permission in extension["permissions"]:
            permission_id = permission["permission_id"]
            assert permission_id not in global_permission_ids
            global_permission_ids.add(permission_id)
            extension_permission_ids.add(permission_id)
            assert permission_id.startswith(f"{extension_id}.permission.")
            assert permission["extension_id"] == extension_id
            assert permission["risk_tier"] in {"low", "medium", "high", "critical"}
            assert permission["baseline_floor"] in {
                "allow",
                "warn",
                "review",
                "require-reapproval",
                "sandbox-required",
                "block",
            }
            assert isinstance(permission["configurable"], bool)
            assert isinstance(permission["dependencies"], list)
            assert isinstance(permission["conflicts"], list)
            assert isinstance(permission["implied_permissions"], list)
            for rule_id in permission["rule_ids"]:
                assert rule_id in rule_ids
                global_rule_owners[rule_id] += 1
                owned_rule_ids.add(rule_id)

        assert owned_rule_ids == rule_ids
        for rule in extension["rules"]:
            assert rule["rule_id"].startswith(f"{extension_id}.")
            assert rule["severity"] in {"low", "medium", "high", "critical"}
            assert rule["default_mode"] in {"required", "enforce", "review", "monitor", "disabled"}
            assert isinstance(rule["matcher_kind"], str) and rule["matcher_kind"]
            assert isinstance(rule["safe_variants"], list)

    assert global_rule_owners
    assert set(global_rule_owners.values()) == {1}, "every canonical rule must have exactly one permission owner"


def test_effective_and_preview_baseline_shapes_are_stable(tmp_path: Path) -> None:
    baseline = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    service = _service(tmp_path)
    effective = service.effective()
    assert list(effective) == baseline["effective_shape"]

    preview = service.preview(
        {
            "previous_revision": 1,
            "catalog_digest": BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            "layers": [],
            "actor_id": "baseline-test",
            "idempotency_key": "baseline-test-0001",
            "nonce": "baseline-test-0002",
        }
    )
    assert list(preview) == baseline["preview_shape"]
