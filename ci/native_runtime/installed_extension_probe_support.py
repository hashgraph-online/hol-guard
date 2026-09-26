"""Focused helpers for the installed native-extension proof."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

from codex_plugin_scanner.guard.extension_builder.native_source_compiler import (
    compile_source,
    find_packaged_source_compiler,
    run_source_compiler,
    validate_source,
)
from codex_plugin_scanner.guard.native_approval_errors import (
    NATIVE_APPROVAL_ERROR_CODES,
    NATIVE_COMMAND_CONTROL_ERROR_CODES,
    NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.store import GuardStore


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise RuntimeError(f"installed_native_extensions_failed:{code}")


def _additive_source_request() -> dict[str, object]:
    """Return one ordinary data-only extension, independent of checkout assets."""

    extension_id = "command.installed-authoring-probe"
    permission_id = f"{extension_id}.permission.destroy"
    rule_id = f"{extension_id}.destroy"
    source = {
        "schema": "guard.command-extension-source.v1",
        "extension": {
            "extension_id": extension_id,
            "version": "1.0.0",
            "name": "Installed authoring probe",
            "description": "Synthetic data-only extension for installed compiler qualification.",
            "action_classes": ["installed probe destructive operation"],
            "risk_classes": ["destructive_shell"],
            "safer_alternatives": ["Inspect the synthetic plan with --dry-run."],
            "reference_urls": ["https://example.invalid/installed-authoring-probe"],
            "required": False,
            "source": "built-in",
            "aliases": [],
            "dependencies": [],
            "conflicts": [],
            "ecosystem_ids": [],
            "executables": ["installed-authoring-probe"],
            "project_markers": [],
            "permissions": [
                {
                    "permission_id": permission_id,
                    "implementation_version": "1.0.0",
                    "label": "Destroy synthetic resource",
                    "description": "Reviews the synthetic destructive operation.",
                    "risk_tier": "high",
                    "baseline_floor": "review",
                    "default_enabled": True,
                    "configurable": True,
                    "typed_capabilities": [],
                    "action_classes": ["installed probe destructive operation"],
                    "dependencies": [],
                    "conflicts": [],
                    "implied_permissions": [],
                    "introduced_version": "1.0.0",
                    "deprecated": False,
                    "safer_guidance": ["Inspect the synthetic plan with --dry-run."],
                    "example_command": "installed-authoring-probe destroy",
                }
            ],
            "rules": [
                {
                    "rule_id": rule_id,
                    "rule_version": "1.0.0",
                    "permission_id": permission_id,
                    "title": "Destroy synthetic resource",
                    "description": "Matches only the synthetic executable and argument.",
                    "severity": "high",
                    "risk_classes": ["destructive_shell"],
                    "action_classes": ["installed probe destructive operation"],
                    "safer_alternatives": ["Inspect the synthetic plan with --dry-run."],
                    "default_mode": "review",
                    "matcher": {
                        "op": "arguments.v1",
                        "config": {
                            "executables": ["installed-authoring-probe"],
                            "required_arguments": ["destroy"],
                        },
                    },
                    "safe_variants": [
                        {
                            "variant_id": "dry-run",
                            "title": "Inspect the synthetic plan",
                            "matcher": {
                                "op": "arguments.v1",
                                "config": {
                                    "executables": ["installed-authoring-probe"],
                                    "required_arguments": ["--dry-run"],
                                },
                            },
                        }
                    ],
                }
            ],
        },
    }
    trust = {
        "schemaVersion": "guard.extension-trust-class-map.v1",
        "publishers": {
            "hol": {"id": "hol", "displayName": "Hashgraph Online"},
            "hol-curated": {"id": "hol-curated", "displayName": "HOL curated library"},
        },
        "classes": {"first-party": [extension_id], "trusted-library": [], "external": []},
    }
    return {
        "schema": "guard.command-extension-build.v1",
        "base": "packaged",
        "sources": [source],
        "mcp_sources": [],
        "trust": trust,
    }


def prove_installed_data_only_authoring(package: Path) -> dict[str, object]:
    """Validate, compile, and simulate an additive source with packaged binaries."""

    native = package.parent / "_native"
    find_packaged_source_compiler()
    source_manifest = json.loads((native / "source-compiler-manifest.json").read_text(encoding="utf-8"))
    runtime_manifest = json.loads((native / "runtime-manifest.json").read_text(encoding="utf-8"))
    request = _additive_source_request()
    validated = validate_source(request)
    compiled = compile_source(request)
    program = compiled.get("program")
    _require(isinstance(program, dict), "authoring_program_missing")
    fixtures = {
        "schema": "guard.command-extension-fixtures.v1",
        "build": request,
        "cases": [
            {
                "id": "active",
                "command": "installed-authoring-probe destroy",
                "enabled_extensions": ["command.installed-authoring-probe"],
                "disabled_permissions": [],
                "expected_action": "review",
                "rule_id": "command.installed-authoring-probe.destroy",
                "expected_effective_segments": [0],
            },
            {
                "id": "dry-run",
                "command": "installed-authoring-probe destroy --dry-run",
                "enabled_extensions": ["command.installed-authoring-probe"],
                "disabled_permissions": [],
                "expected_action": "review",
                "rule_id": "command.installed-authoring-probe.destroy",
                "expected_effective_segments": [],
            },
        ],
    }
    tested = run_source_compiler("test", fixtures)
    base_program = BUILT_IN_COMMAND_EXTENSION_REGISTRY.program_digest
    implementation = BUILT_IN_COMMAND_EXTENSION_REGISTRY.implementation_digest
    _require(source_manifest["source_sha"] == runtime_manifest["source_sha"], "authoring_source_identity")
    _require(source_manifest["base_program_digest"] == base_program, "authoring_catalog_program")
    _require(source_manifest["implementation_digest"] == implementation, "authoring_implementation")
    _require(validated.get("program_digest") == program.get("program_digest"), "authoring_validate_compile")
    _require(validated.get("source_digest") == compiled.get("source_digest"), "authoring_validate_source")
    _require(validated.get("implementation_digest") == implementation, "authoring_validate_implementation")
    _require(compiled.get("base_program_digest") == base_program, "authoring_compile_base")
    _require(compiled.get("implementation_digest") == implementation, "authoring_compile_implementation")
    _require(compiled.get("catalog_projection_kind") == "addition-only-not-release-catalog", "authoring_projection")
    _require(tested.get("ok") is True and tested.get("target_commands_executed") == 0, "authoring_fixtures")
    _require(tested.get("scope") == "offline-simulation-not-authenticated-receipts", "authoring_fixture_scope")
    _require(tested.get("program_digest") == program.get("program_digest"), "authoring_fixture_program")
    return {
        "scope": tested["scope"],
        "target_commands_executed": tested["target_commands_executed"],
        "fixture_cases": len(tested["cases"]),
        "base_program_digest": base_program,
        "compiled_program_digest": program["program_digest"],
        "source_digest": compiled["source_digest"],
        "implementation_digest": implementation,
        "source_sha": source_manifest["source_sha"],
    }


def persisted_native_receipt_ids(store: GuardStore) -> set[str]:
    """Return the durable receipt identities without exposing receipt contents."""

    with store._connect() as connection:
        rows = connection.execute("select decision_id from native_hook_decision_receipts").fetchall()
    return {row["decision_id"] for row in rows if isinstance(row["decision_id"], str)}


class _ReceiptProgressWriter(Protocol):
    def stats(self) -> Mapping[str, object]: ...


def receipt_processed_count(writer: _ReceiptProgressWriter) -> int | None:
    """Read the bounded in-memory native-receipt progress counter when available."""

    try:
        snapshot = writer.stats()
    except Exception:
        return None
    if not isinstance(snapshot, Mapping):
        return None
    value = snapshot.get("receipt_processed")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return None
    return value


def await_persisted_native_receipt(
    store: GuardStore,
    known_ids: set[str],
    *,
    writer: _ReceiptProgressWriter | None = None,
    receipt_processed_before: int | None = None,
    timeout_seconds: float = 10.0,
) -> dict[str, object]:
    """Wait for one new durable receipt without starving the async SQLite writer.

    The installed daemon persists native receipts on its evidence-writer thread.
    When that writer is available, wait for its in-memory processed counter to
    advance before opening a competing SQLite reader. This matters on Windows,
    where aggressive reader polling can repeatedly consume the writer's short
    lock-acquisition budget. The durable row remains the source of truth: writer
    progress only decides when to query it.
    """

    deadline = time.monotonic() + max(0.0, timeout_seconds)
    writer_progress = (
        (writer, receipt_processed_before)
        if writer is not None and receipt_processed_before is not None
        else None
    )
    while time.monotonic() < deadline:
        should_read = writer_progress is None
        if writer_progress is not None:
            progress_writer, processed_mark = writer_progress
            processed = receipt_processed_count(progress_writer)
            if processed is None:
                writer_progress = None
                should_read = True
            elif processed > processed_mark:
                writer_progress = (progress_writer, processed)
                should_read = True
        if should_read:
            new_ids = persisted_native_receipt_ids(store) - known_ids
            if len(new_ids) > 1:
                raise RuntimeError("installed_native_extensions_failed:receipt_persistence_ambiguous")
            if new_ids:
                receipt = store.get_native_decision_receipt(next(iter(new_ids)))
                if receipt is not None:
                    return receipt
        time.sleep(0.02)
    raise RuntimeError("installed_native_extensions_failed:receipt_persistence_missing")


def receipt_binding_diagnostic(
    response: Mapping[str, object], receipt: Mapping[str, object], expected: Mapping[str, object], seen: list[str]
) -> dict[str, object]:
    """Describe a failed comparison without disclosing request or receipt data."""

    actual = receipt.get("command_extensions")
    actual = actual if isinstance(actual, dict) else {}
    fields = [
        "schema",
        "program_digest",
        "catalog_digest",
        "trust_digest",
        "control_revision",
        "managed_control_revision",
        "control_effective_digest",
        "observations_digest",
        "observation_count",
        "uncertainty_count",
    ]
    reasons = {
        "native_policy_not_ready",
        "native_hook_worker_unavailable",
        "native_hook_worker_unsupported",
        "native_hook_compatibility_disabled",
        "native_pre_tool_unavailable",
        "native_pre_tool_review",
        "native_hook_edge_invalid_response",
        "native_hook_edge_unavailable",
        "native_overloaded",
        "daemon_hook_deadline_exhausted",
        "daemon_hook_queue_capacity",
        "daemon_hook_queue_bytes",
        "daemon_worker_exception",
        "invalid_hook_payload_reference",
        "harness_not_managed",
    } | NATIVE_COMMAND_CONTROL_ERROR_CODES
    reason = response.get("reason_code")
    output = response.get("hookSpecificOutput")
    decision = output.get("permissionDecision") if isinstance(output, dict) else response.get("decision")

    def revision(binding: Mapping[str, object]) -> int | None:
        value = binding.get("control_revision")
        return value if type(value) is int and 0 <= value <= 2**64 - 1 else None

    return {
        "schema": "guard.installed-native-extension-receipt-failure.v1",
        "http_reason_code": reason if isinstance(reason, str) and reason in reasons else None,
        "http_decision": decision if isinstance(decision, str) and decision in {"allow", "ask", "deny"} else None,
        "mismatched_binding_fields": [key for key in fields if actual.get(key) != expected.get(key)],
        "expected_control_revision": revision(expected),
        "receipt_control_revision": revision(actual),
        "receipt_id_repeated": isinstance(receipt.get("decision_id"), str) and receipt["decision_id"] in seen,
    }


def policy_readiness_diagnostic(publisher: object) -> dict[str, object]:
    """Expose bounded lifecycle state without policy, path, or exception text."""

    allowed_errors = (
        NATIVE_APPROVAL_ERROR_CODES
        | NATIVE_COMMAND_CONTROL_ERROR_CODES
        | NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES
        | {
            "native_policy_snapshot_ack_invalid",
            "native_policy_snapshot_ack_mismatch",
            "native_policy_snapshot_expired",
            "native_policy_snapshot_integrity_key_unavailable",
            "native_policy_snapshot_native_disabled",
            "native_policy_snapshot_protocol_unsupported",
            "native_policy_snapshot_publish_failed",
            "native_policy_snapshot_resident_changed",
            "native_policy_snapshot_runtime_unavailable",
            "attributeerror",
            "databaseerror",
            "filenotfounderror",
            "integrityerror",
            "operationalerror",
            "oserror",
            "permissionerror",
            "runtimeerror",
            "timeouterror",
            "typeerror",
            "valueerror",
        }
    )
    error = getattr(publisher, "last_error", None)
    closed = getattr(publisher, "closed", None)
    thread = getattr(publisher, "_thread", None)
    return {
        "last_error_code": error if isinstance(error, str) and error in allowed_errors else None,
        "last_error_present": error is not None,
        "closed": closed if type(closed) is bool else None,
        "thread_alive": thread.is_alive() if isinstance(thread, threading.Thread) else None,
    }
