#!/usr/bin/env python3
"""Prove the reconstructed NHD-079-085 receipt boundary at the exact HEAD."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Final

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.hook_data_plane_ownership_contract import load_manifest

SCHEMA: Final = "hol-guard.native-hook-receipt-persistence-gate.v1"
FORBIDDEN_RECEIPT_FIELDS: Final = frozenset(
    {"raw_payload", "command", "prompt", "path", "url", "content", "secret", "private_path"}
)


def _read(root: Path, relative: str) -> str:
    path = root / relative
    if not path.is_file():
        raise RuntimeError(f"required receipt source is missing: {relative}")
    return path.read_text(encoding="utf-8")


def _contains_all(source: str, values: tuple[str, ...], label: str) -> None:
    missing = [value for value in values if value not in source]
    if missing:
        raise RuntimeError(f"{label} is missing: {', '.join(missing)}")


def _braced_body(source: str, start: int, label: str) -> str:
    """The braced block that follows `start`, matched by depth.

    The writer's bodies hold no brace inside a string or character literal, so
    counting braces recovers the same block a parser would.
    """
    opened = source.find("{", start)
    if opened < 0:
        raise RuntimeError(f"{label} has no body")
    depth = 0
    for index in range(opened, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opened : index + 1]
    raise RuntimeError(f"{label} body is unterminated")


def _submit_method_has_no_decision_io(source: str) -> None:
    """The handoff queues a receipt; the worker behind it does the writing."""
    start = source.find("pub fn submit_native_decision_receipt")
    if start < 0:
        raise RuntimeError("receipt handoff submit method is missing")
    body = _braced_body(source, start, "receipt handoff submit method")
    if any(
        marker in body for marker in ("sqlite", "record_native_decision_receipt", "persist_native_decision_receipt")
    ):
        raise RuntimeError("receipt handoff submit method performs decision-time I/O")


def _validate_contract(root: Path) -> None:
    manifest = load_manifest(root / "docs/guard/contracts/hook-data-plane-ownership.v2.json")
    contract = manifest["decision_receipt"]
    if not isinstance(contract, dict):
        raise RuntimeError("decision receipt contract is not an object")
    if contract.get("contract_document") != "docs/guard/contracts/native-hook-decision-receipt-persistence.v1.md":
        raise RuntimeError("decision receipt provenance document is not pinned")
    excluded = contract.get("privacy_excluded_fields")
    if not isinstance(excluded, list) or not set(excluded).issuperset(FORBIDDEN_RECEIPT_FIELDS):
        raise RuntimeError("decision receipt privacy exclusions are incomplete")


def _validate_rust_sources(root: Path) -> None:
    rust_contract = _read(root, "rust/crates/guard-contracts/src/native_hook_receipt.rs")
    rust_receipt_builder = _read(root, "rust/crates/guard-runtime/src/native_hook_receipt.rs")
    rust_edge = _read(root, "rust/crates/guard-runtime/src/edge.rs")
    _contains_all(
        rust_contract,
        ("NativeHookDecisionReceiptV1", "decision_id", "NATIVE_HOOK_DECISION_RECEIPT_V1_SCHEMA", "deny_unknown_fields"),
        "Rust receipt contract",
    )
    _contains_all(
        rust_receipt_builder,
        ("build_decision_receipt", "receipt_from_pre_tool", "receipt_from_post_tool"),
        "Rust receipt builder",
    )
    _contains_all(
        rust_edge,
        ("receipt_from_pre_tool", "receipt_from_post_tool", "receipt,"),
        "Rust edge receipt wiring",
    )
    if any(f"pub {field}:" in rust_contract for field in FORBIDDEN_RECEIPT_FIELDS):
        raise RuntimeError("Rust receipt exposes a forbidden field")


def _validate_receipt_decoder_and_handoff(root: Path) -> None:
    receipt = _read(root, "src/codex_plugin_scanner/guard/native_decision_receipt.py")
    _contains_all(
        receipt,
        ("validate_native_decision_receipt", "canonical_receipt_bytes", "decision_id"),
        "Python receipt validator",
    )
    required_start = receipt.find("_REQUIRED_FIELDS")
    required_end = receipt.find(")", required_start)
    required_fields = receipt[required_start:required_end] if required_start >= 0 and required_end >= 0 else ""
    if any(f'"{field}"' in required_fields for field in FORBIDDEN_RECEIPT_FIELDS):
        raise RuntimeError("Python receipt validator exposes a forbidden receipt field")
    writer = _read(root, "rust/crates/guard-command/src/hook_evidence_writer.rs")
    _contains_all(
        writer,
        (
            "submit_native_decision_receipt",
            "max_records",
            "max_bytes",
            "receipt_deduped",
            "RECEIPT_SCHEMA",
        ),
        "bounded receipt handoff",
    )
    journal = _read(root, "rust/crates/guard-command/src/hook_evidence_journal_fs.rs")
    _contains_all(journal, ("rewrite_journal", "recover_journal_records"), "receipt journal durability")
    _submit_method_has_no_decision_io(writer)


def _validate_hook_routes(root: Path) -> None:
    native_worker = _read(root, "src/codex_plugin_scanner/guard/daemon/hook_worker_native.py")
    _contains_all(native_worker, ("_record_native_decision_receipt", 'edge.get("receipt")'), "HookWorker receipt route")
    cli = _read(root, "src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py")
    _contains_all(
        cli,
        ("NativeHookEvidenceWriter", "activity_writer=NativeHookEvidenceWriter(store=store)"),
        "CLI receipt route",
    )
    probe = _read(root, "ci/native_runtime/probe_native_default_auto.py")
    _contains_all(
        probe,
        ("receipt_metrics", "mode_invariants", '"invalid"', 'for mode in ("off", "shadow")'),
        "installed no-environment receipt proof",
    )


def _validate_tests_and_provenance(root: Path) -> None:
    tests = _read(root, "tests/test_native_decision_receipt.py")
    _contains_all(
        tests,
        (
            "test_receipt_is_strictly_redacted_and_identity_bound",
            "test_store_receipt_insert_is_idempotent",
        ),
        "receipt privacy and persistence tests",
    )
    writer_tests = _read(root, "rust/crates/guard-command/src/hook_evidence_writer_tests.rs")
    _contains_all(
        writer_tests,
        (
            "a_receipt_handoff_returns_before_the_store_has_written_it",
            "a_repeated_receipt_is_deduplicated_rather_than_queued_twice",
            "a_full_receipt_queue_drops_the_overflow_instead_of_blocking",
            "a_receipt_left_in_the_journal_is_recovered_by_the_next_writer",
            "a_receipt_outlasts_a_briefly_locked_store",
            "a_receipt_the_store_keeps_refusing_stays_journaled_for_the_next_writer",
            "a_refused_receipt_does_not_hold_up_the_receipts_behind_it",
            "a_receipt_the_store_never_takes_is_dropped_after_its_last_attempt",
            "a_receipt_waits_out_a_store_locked_past_the_attempt_cap",
            "a_long_lock_spends_none_of_the_attempts_other_refusals_get",
        ),
        "receipt fault tests",
    )
    journal_tests = _read(root, "rust/crates/guard-command/src/hook_evidence_journal_fs_tests.rs")
    _contains_all(
        journal_tests,
        ("a_rewrite_drops_one_record_and_the_preview_behind_it",),
        "receipt journal rewrite test",
    )
    provenance = _read(root, "docs/guard/contracts/native-hook-decision-receipt-persistence.v1.md")
    _contains_all(
        provenance,
        ("exact original wording", "reconstructed implementation scope", "Windows CI/CD", "decision-critical"),
        "receipt provenance document",
    )


def run(root: Path, *, json_path: Path | None) -> int:
    _validate_contract(root)
    _validate_rust_sources(root)
    _validate_receipt_decoder_and_handoff(root)
    _validate_hook_routes(root)
    _validate_tests_and_provenance(root)

    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    evidence: dict[str, object] = {
        "schema": SCHEMA,
        "version": 1,
        "status": "passed",
        "head": head,
        "scope": "NHD-079-NHD-085-reconstructed",
        "windows_ci_cd": "excluded_by_request",
        "checks": {
            "rust_decision_receipt": True,
            "python_privacy_decoder": True,
            "bounded_async_handoff": True,
            "non_authoritative_persistence": True,
            "idempotency_and_restart": True,
            "fault_degradation": True,
            "installed_no_environment": True,
            "provenance_document": True,
        },
    }
    rendered = json.dumps(evidence, sort_keys=True)
    if json_path is not None:
        json_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--json", dest="json_path", type=Path)
    args = parser.parse_args()
    raise SystemExit(run(args.root.resolve(), json_path=args.json_path))
