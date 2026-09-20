from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

_RUNTIME = os.environ.get("HOL_GUARD_NATIVE_BINARY")
pytestmark = pytest.mark.skipif(not _RUNTIME, reason="compiled native runtime is required")

_SCHEMA = "hol-guard-native-rule-contract.v2"
_DOMAIN = b"hol-guard-native-rule-contract.v2\x00"
_COMPONENTS = (
    ("guard-rules", Path("rust/crates/guard-rules/src/lib.rs")),
    ("guard-scanner", Path("rust/crates/guard-scanner/src/lib.rs")),
    ("guard-secure-fs", Path("rust/crates/guard-secure-fs/src/lib.rs")),
    ("guard-secure-fs-source-path", Path("rust/crates/guard-secure-fs/src/source_path.rs")),
    ("guard-hook-core", Path("rust/crates/guard-hook-core/src/lib.rs")),
    ("guard-contracts", Path("rust/crates/guard-contracts/src/lib.rs")),
    ("guard-command-pretool", Path("rust/crates/guard-command/src/pretool.rs")),
    ("guard-command-pretool-generic", Path("rust/crates/guard-command/src/pretool/generic.rs")),
    ("guard-command-pretool-result", Path("rust/crates/guard-command/src/pretool/generic_result.rs")),
    ("guard-command-pretool-extract", Path("rust/crates/guard-command/src/pretool/generic_extract.rs")),
    ("guard-runtime-policy-enforcement", Path("rust/crates/guard-runtime/src/policy_enforcement.rs")),
    ("guard-runtime-policy-enforcement-facts", Path("rust/crates/guard-runtime/src/policy_enforcement_facts.rs")),
    (
        "guard-runtime-policy-enforcement-facts-tools",
        Path("rust/crates/guard-runtime/src/policy_enforcement_facts_tools.rs"),
    ),
    ("guard-runtime-policy-enforcement-policy", Path("rust/crates/guard-runtime/src/policy_enforcement_policy.rs")),
    ("guard-policy-snapshot", Path("rust/crates/guard-policy-snapshot/src/lib.rs")),
    ("guard-policy-snapshot-canonical", Path("rust/crates/guard-policy-snapshot/src/policy_snapshot_canonical.rs")),
    ("guard-policy-snapshot-crypto", Path("rust/crates/guard-policy-snapshot/src/policy_snapshot_crypto.rs")),
    ("guard-command-model", Path("rust/crates/guard-command/src/lib.rs")),
    ("guard-command-exact-command", Path("rust/crates/guard-command/src/exact_command.rs")),
    ("guard-policy-managed-configuration", Path("rust/crates/guard-policy-snapshot/src/managed_configuration.rs")),
    ("guard-policy-scoped-authority", Path("rust/crates/guard-policy-snapshot/src/scoped_authority.rs")),
    ("guard-policy-scoped-authority-decode", Path("rust/crates/guard-policy-snapshot/src/scoped_authority_decode.rs")),
    ("guard-policy-command-expression", Path("rust/crates/guard-policy-snapshot/src/command_expression.rs")),
    (
        "guard-policy-scoped-command-expression",
        Path("rust/crates/guard-policy-snapshot/src/scoped_command_expression.rs"),
    ),
    ("guard-policy-scoped-matcher", Path("rust/crates/guard-policy-snapshot/src/scoped_authority_match.rs")),
    ("guard-policy-snapshot-v4", Path("rust/crates/guard-policy-snapshot/src/policy_snapshot_v4.rs")),
    ("guard-runtime-policy-store-versioned", Path("rust/crates/guard-runtime/src/policy_store_versioned.rs")),
    ("guard-runtime-policy-scoped-request", Path("rust/crates/guard-runtime/src/policy_scoped_request.rs")),
    (
        "guard-runtime-policy-scoped-sensitive-read",
        Path("rust/crates/guard-runtime/src/policy_scoped_sensitive_read.rs"),
    ),
    (
        "guard-runtime-policy-sensitive-configuration",
        Path("rust/crates/guard-runtime/src/policy_sensitive_configuration.rs"),
    ),
    ("guard-runtime-policy-scoped-tool-request", Path("rust/crates/guard-runtime/src/policy_scoped_tool_request.rs")),
    ("guard-runtime-policy-scoped-managed", Path("rust/crates/guard-runtime/src/policy_scoped_managed.rs")),
    (
        "guard-runtime-policy-scoped-managed-catalog",
        Path("rust/crates/guard-runtime/src/policy_scoped_managed_catalog.json"),
    ),
    ("guard-runtime-edge-v4", Path("rust/crates/guard-runtime/src/edge_v4.rs")),
    ("guard-runtime-policy-scoped-enforcement", Path("rust/crates/guard-runtime/src/policy_scoped_enforcement.rs")),
    ("guard-runtime-approval", Path("rust/crates/guard-runtime/src/approval.rs")),
    ("guard-runtime-approval-context", Path("rust/crates/guard-runtime/src/approval_context.rs")),
    ("guard-runtime-approval-context-scoped", Path("rust/crates/guard-runtime/src/approval_context_scoped.rs")),
    ("guard-runtime-approval-v4", Path("rust/crates/guard-runtime/src/approval_v4.rs")),
    ("guard-runtime-policy-store-approval", Path("rust/crates/guard-runtime/src/policy_store_approval.rs")),
    ("guard-runtime-edge", Path("rust/crates/guard-runtime/src/edge.rs")),
    (
        "guard-runtime-policy-enforcement-admission",
        Path("rust/crates/guard-runtime/src/policy_enforcement_admission.rs"),
    ),
    ("guard-command-command-argument-semantics", Path("rust/crates/guard-command/src/command_argument_semantics.rs")),
    (
        "guard-command-command-common-cli-matcher-values",
        Path("rust/crates/guard-command/src/command_common_cli_matcher_values.rs"),
    ),
    ("guard-command-command-common-cli-matchers", Path("rust/crates/guard-command/src/command_common_cli_matchers.rs")),
    ("guard-command-command-curl-operations", Path("rust/crates/guard-command/src/command_curl_operations.rs")),
    ("guard-command-command-curl-targets", Path("rust/crates/guard-command/src/command_curl_targets.rs")),
    ("guard-command-command-database-matchers", Path("rust/crates/guard-command/src/command_database_matchers.rs")),
    ("guard-command-command-operand-matchers", Path("rust/crates/guard-command/src/command_operand_matchers.rs")),
    ("guard-command-command-option-parsing", Path("rust/crates/guard-command/src/command_option_parsing.rs")),
    ("guard-command-command-option-unicode", Path("rust/crates/guard-command/src/command_option_unicode.rs")),
    (
        "guard-command-command-option-unicode-ranges-a",
        Path("rust/crates/guard-command/src/command_option_unicode_ranges_a.rs"),
    ),
    (
        "guard-command-command-option-unicode-ranges-b",
        Path("rust/crates/guard-command/src/command_option_unicode_ranges_b.rs"),
    ),
    ("guard-command-command-reviewed-literal", Path("rust/crates/guard-command/src/command_reviewed_literal.rs")),
    (
        "guard-command-command-specialized-matchers",
        Path("rust/crates/guard-command/src/command_specialized_matchers.rs"),
    ),
    (
        "guard-command-command-structured-matchers-grammar",
        Path("rust/crates/guard-command/src/command_structured_matchers/grammar.rs"),
    ),
    ("guard-command-command-structured-matchers", Path("rust/crates/guard-command/src/command_structured_matchers.rs")),
    ("guard-command-executable-flag-contract", Path("rust/crates/guard-command/src/executable_flag_contract.rs")),
    ("guard-command-lib", Path("rust/crates/guard-command/src/lib.rs")),
    ("guard-command-native-command-controls", Path("rust/crates/guard-command/src/native_command_controls.rs")),
    ("guard-command-native-command-delegated", Path("rust/crates/guard-command/src/native_command_delegated.rs")),
    ("guard-command-native-command-program", Path("rust/crates/guard-command/src/native_command_program.rs")),
    (
        "guard-command-native-command-program-admission",
        Path("rust/crates/guard-command/src/native_command_program_admission.rs"),
    ),
    (
        "guard-command-native-command-program-compile",
        Path("rust/crates/guard-command/src/native_command_program_compile.rs"),
    ),
    (
        "guard-command-native-command-program-evaluation",
        Path("rust/crates/guard-command/src/native_command_program_evaluation.rs"),
    ),
    (
        "guard-command-native-command-program-observations",
        Path("rust/crates/guard-command/src/native_command_program_observations.rs"),
    ),
    ("guard-command-native-command-program-wire", Path("rust/crates/guard-command/src/native_command_program_wire.rs")),
    ("guard-command-pretool-search-glob-class", Path("rust/crates/guard-command/src/pretool/search/glob_class.rs")),
    ("guard-command-pretool-search-hint", Path("rust/crates/guard-command/src/pretool/search/hint.rs")),
    ("guard-command-pretool-search-options", Path("rust/crates/guard-command/src/pretool/search/options.rs")),
    ("guard-command-pretool-search", Path("rust/crates/guard-command/src/pretool/search.rs")),
    ("guard-contracts-native-command-controls", Path("rust/crates/guard-contracts/src/native_command_controls.rs")),
    (
        "guard-contracts-native-command-observations",
        Path("rust/crates/guard-contracts/src/native_command_observations.rs"),
    ),
    ("guard-contracts-native-hook-receipt", Path("rust/crates/guard-contracts/src/native_hook_receipt.rs")),
    ("guard-runtime-policy-store-command-floor", Path("rust/crates/guard-runtime/src/policy_store_command_floor.rs")),
    ("native-command-program-artifact", Path("rust/crates/../../contracts/extensions/native-command-program.v1.json")),
    ("guard-command-command-ascii-comparison", Path("rust/crates/guard-command/src/command_ascii_comparison.rs")),
    (
        "guard-command-command-compatibility-catalog",
        Path("rust/crates/guard-command/src/command_compatibility/catalog.rs"),
    ),
    (
        "guard-command-command-compatibility-domains",
        Path("rust/crates/guard-command/src/command_compatibility/domains.rs"),
    ),
    ("guard-command-command-compatibility-git", Path("rust/crates/guard-command/src/command_compatibility/git.rs")),
    (
        "guard-command-command-compatibility-github",
        Path("rust/crates/guard-command/src/command_compatibility/github.rs"),
    ),
    (
        "guard-command-command-compatibility-github-api",
        Path("rust/crates/guard-command/src/command_compatibility/github_api.rs"),
    ),
    (
        "guard-command-command-compatibility-github-options",
        Path("rust/crates/guard-command/src/command_compatibility/github_options.rs"),
    ),
    ("guard-command-command-compatibility", Path("rust/crates/guard-command/src/command_compatibility.rs")),
    ("guard-runtime-policy-store", Path("rust/crates/guard-runtime/src/policy_store.rs")),
    (
        "guard-runtime-policy-store-command-authority",
        Path("rust/crates/guard-runtime/src/policy_store_command_authority.rs"),
    ),
    ("guard-runtime-policy-store-authority", Path("rust/crates/guard-runtime/src/policy_store_authority.rs")),
    ("guard-runtime-policy-store-migration", Path("rust/crates/guard-runtime/src/policy_store_migration.rs")),
    ("guard-runtime-policy-store-request", Path("rust/crates/guard-runtime/src/policy_store_request.rs")),
    ("guard-runtime-policy-store-persistence", Path("rust/crates/guard-runtime/src/policy_store_persistence.rs")),
    ("guard-runtime-native-hook-receipt", Path("rust/crates/guard-runtime/src/native_hook_receipt.rs")),
    ("guard-runtime-policy-store-mutation", Path("rust/crates/guard-runtime/src/policy_store_mutation.rs")),
    ("guard-runtime-policy-store-withdrawal", Path("rust/crates/guard-runtime/src/policy_store_withdrawal.rs")),
    (
        "guard-runtime-policy-store-control-persistence",
        Path("rust/crates/guard-runtime/src/policy_store_control_persistence.rs"),
    ),
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _expected_contract() -> dict[str, object]:
    root = _repo_root()
    components: list[dict[str, str]] = []
    combined = hashlib.sha256()
    combined.update(_DOMAIN)
    for name, relative_path in _COMPONENTS:
        digest = hashlib.sha256((root / relative_path).read_bytes()).hexdigest()
        components.append({"name": name, "sha256": digest})
        combined.update(name.encode("utf-8"))
        combined.update(b"\x00")
        combined.update(digest.encode("ascii"))
        combined.update(b"\x00")
    return {
        "schema": _SCHEMA,
        "components": components,
        "rule_digest": combined.hexdigest(),
    }


def _runtime_json(*args: str) -> dict[str, object]:
    assert _RUNTIME is not None
    completed = subprocess.run(
        (_RUNTIME, *args),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        timeout=5.0,
    )
    payload = json.loads(completed.stdout)
    assert isinstance(payload, dict)
    return payload


def test_runtime_rule_contract_matches_exact_checkout_source_bytes() -> None:
    assert _runtime_json("rule-contract", "--json") == _expected_contract()


def test_capabilities_rule_digest_is_the_exact_rule_contract_digest() -> None:
    contract = _runtime_json("rule-contract", "--json")
    capabilities = _runtime_json("capabilities", "--json")
    assert capabilities["rule_digest"] == contract["rule_digest"]
    features = capabilities.get("features")
    assert isinstance(features, list)
    assert "rule-contract-v2" in features


def test_rule_contract_changes_when_any_component_bytes_change() -> None:
    expected = _expected_contract()
    components = expected["components"]
    assert isinstance(components, list)
    original = str(expected["rule_digest"])
    for index, component in enumerate(components):
        assert isinstance(component, dict)
        mutated_components = [dict(value) for value in components]
        digest = str(mutated_components[index]["sha256"])
        mutated_components[index]["sha256"] = ("0" if digest[0] != "0" else "1") + digest[1:]
        combined = hashlib.sha256()
        combined.update(_DOMAIN)
        for value in mutated_components:
            combined.update(str(value["name"]).encode("utf-8"))
            combined.update(b"\x00")
            combined.update(str(value["sha256"]).encode("ascii"))
            combined.update(b"\x00")
        assert combined.hexdigest() != original
