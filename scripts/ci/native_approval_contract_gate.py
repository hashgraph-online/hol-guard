#!/usr/bin/env python3
"""Check the native approval contract and its ownership boundary.

This gate is intentionally source based. It catches accidental reintroduction
of the retired durable replay ledger, receipt/schema drift, unbounded error
forwarding, and release builds that omit the externally controlled enrollment
root. It never creates or accepts a private enrollment key.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Final

ACTIVE_RUST_FILES: Final = (
    Path("rust/crates/guard-contracts/src/approval_contracts.rs"),
    Path("rust/crates/guard-contracts/src/approval_v4_contracts.rs"),
    Path("rust/crates/guard-runtime/src/approval.rs"),
    Path("rust/crates/guard-runtime/src/approval_authority.rs"),
    Path("rust/crates/guard-runtime/src/approval_authority_tests.rs"),
    Path("rust/crates/guard-runtime/src/approval_context.rs"),
    Path("rust/crates/guard-runtime/src/approval_enrollment.rs"),
    Path("rust/crates/guard-runtime/src/approval_enrollment_platform.rs"),
    Path("rust/crates/guard-runtime/src/approval_replay_memory.rs"),
    Path("rust/crates/guard-runtime/src/approval_v4.rs"),
    Path("rust/crates/guard-runtime/src/approval_v4_assertion_state.rs"),
    Path("rust/crates/guard-runtime/src/approval_v4_authority.rs"),
    Path("rust/crates/guard-runtime/src/approval_v4_authority_tests.rs"),
    Path("rust/crates/guard-runtime/src/approval_v4_crypto.rs"),
    Path("rust/crates/guard-runtime/src/approval_v4_enrollment.rs"),
    Path("rust/crates/guard-runtime/src/approval_v4_negative_tests.rs"),
    Path("rust/crates/guard-runtime/src/approval_v4_secure_state.rs"),
    Path("rust/crates/guard-runtime/src/approval_v4_tests.rs"),
    Path("rust/crates/guard-runtime/src/approval_v3_lifecycle_tests.rs"),
    Path("rust/crates/guard-runtime/src/approval_v3_tests.rs"),
    Path("rust/crates/guard-runtime/src/edge.rs"),
    Path("rust/crates/guard-runtime/src/edge_tests.rs"),
    Path("rust/crates/guard-runtime/src/managed_resident.rs"),
    Path("rust/crates/guard-runtime/src/managed_resident_tests.rs"),
    Path("rust/crates/guard-runtime/src/policy_enforcement.rs"),
    Path("rust/crates/guard-runtime/src/policy_enforcement_tests.rs"),
    Path("rust/crates/guard-runtime/src/policy_store.rs"),
    Path("rust/crates/guard-runtime/src/policy_store_approval.rs"),
    Path("rust/crates/guard-runtime/src/policy_store_authority.rs"),
    Path("rust/crates/guard-runtime/src/policy_store_tests.rs"),
    Path("rust/crates/guard-runtime/src/resident_protocol.rs"),
)
DECODER = Path("src/codex_plugin_scanner/guard/native_response_decoder.py")
PROTOCOL = Path("src/codex_plugin_scanner/guard/native_approval_protocol.py")
V4_PROTOCOL = Path("src/codex_plugin_scanner/guard/native_approval_v4_protocol.py")
ERRORS = Path("src/codex_plugin_scanner/guard/native_approval_errors.py")
APPROVAL_CONTRACT = Path("rust/crates/guard-contracts/src/approval_contracts.rs")
V4_APPROVAL_CONTRACT = Path("rust/crates/guard-contracts/src/approval_v4_contracts.rs")
AUTHORITY = Path("rust/crates/guard-runtime/src/approval_authority.rs")
RUNTIME_APPROVAL = Path("rust/crates/guard-runtime/src/approval.rs")
REPLAY_MEMORY = Path("rust/crates/guard-runtime/src/approval_replay_memory.rs")
POLICY_AUTHORITY = Path("rust/crates/guard-runtime/src/policy_store_authority.rs")
RESIDENT_PROTOCOL = Path("rust/crates/guard-runtime/src/resident_protocol.rs")
MANAGED_RESIDENT = Path("rust/crates/guard-runtime/src/managed_resident.rs")
WORKFLOW = Path(".github/workflows/rust-authority-ownership.yml")
PUBLISH_WORKFLOW = Path(".github/workflows/publish.yml")
ENROLLMENT_DOC = Path("docs/guard/native-approval-enrollment.md")

OBSOLETE_FILES: Final = (
    Path("rust/crates/guard-runtime/src/approval_secret.rs"),
    Path("rust/crates/guard-runtime/src/approval_tests.rs"),
)
RETIRED_TOKENS: Final = (
    "ApprovalReplayLedger",
    "NATIVE_APPROVAL_REPLAY_LEDGER",
    "native-approval-replay-ledger",
    "replay_ledger",
    "replay-ledger",
    "approval_secret",
    "ApprovalSecret",
)
RECEIPT_FIELDS: Final = frozenset(
    {
        "schema",
        "version",
        "phase",
        "request_id",
        "request_digest",
        "action_digest",
        "policy_generation",
        "policy_digest",
        "rule_digest",
        "runtime_identity",
        "runtime_protocol_version",
        "runtime_package",
        "runtime_version",
        "runtime_binary_identity",
        "harness",
        "workspace_binding",
        "device_binding",
        "installation_binding",
        "publisher_binding",
        "artifact_binding",
        "scope_contract_version",
        "scope_contract_digest",
        "scope_binding",
        "resident_epoch",
        "nonce",
        "issued_at_ms",
        "expires_at_ms",
        "decision",
        "requested_action",
        "approved_action",
        "reason_code",
        "nonce_digest",
        "replay_claimed",
    }
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(f"required approval source is missing: {path}") from exc


def _struct_fields(text: str, name: str) -> frozenset[str]:
    match = re.search(rf"pub struct {re.escape(name)}\s*\{{(?P<body>.*?)\n\}}", text, re.DOTALL)
    if match is None:
        raise RuntimeError(f"approval contract struct is missing: {name}")
    return frozenset(re.findall(r"^\s*pub\s+([a-z][a-z0-9_]*)\s*:", match.group("body"), re.MULTILINE))


def _python_key_set(text: str, assignment: str) -> frozenset[str]:
    tree = ast.parse(text, filename=str(DECODER))
    assignments = {
        target.id: node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    resolving: set[str] = set()

    def evaluate(node: ast.AST) -> frozenset[str]:
        if isinstance(node, ast.Name):
            if node.id in resolving or node.id not in assignments:
                raise RuntimeError(f"decoder key set reference is invalid: {node.id}")
            resolving.add(node.id)
            try:
                return evaluate(assignments[node.id])
            finally:
                resolving.remove(node.id)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"set", "frozenset"}:
            if len(node.args) != 1 or node.keywords:
                raise RuntimeError(f"decoder key set expression is invalid: {assignment}")
            return evaluate(node.args[0])
        if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
            values: list[str] = []
            for element in node.elts:
                if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
                    raise RuntimeError(f"decoder key set contains a non-string: {assignment}")
                values.append(element.value)
            return frozenset(values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.BitOr, ast.Sub)):
            left = evaluate(node.left)
            right = evaluate(node.right)
            return frozenset(left | right) if isinstance(node.op, ast.BitOr) else frozenset(left - right)
        raise RuntimeError(f"decoder key set expression is unsupported: {assignment}")

    value = evaluate(assignments.get(assignment, ast.Constant(value=None)))
    if not value:
        raise RuntimeError(f"decoder key set is missing: {assignment}")
    return value


def _error_codes(text: str, marker: str) -> frozenset[str]:
    start = text.find(marker)
    if start < 0:
        raise RuntimeError(f"approval error list is missing: {marker}")
    end = text.find("];", start)
    if end < 0:
        end = text.find("\n_APPROVAL_HEX64", start)
    if end < 0:
        raise RuntimeError(f"approval error list is unterminated: {marker}")
    return frozenset(re.findall(r'"(native_[a-z0-9_]+|snapshot_expired)"', text[start:end]))


def _check_file_sizes(root: Path) -> None:
    for relative in ACTIVE_RUST_FILES:
        line_count = len(_read(root / relative).splitlines())
        if line_count > 500:
            raise RuntimeError(f"active approval file exceeds 500 lines: {relative} ({line_count})")


def _check_retired_refs(root: Path) -> None:
    active = "\n".join(_read(root / relative) for relative in ACTIVE_RUST_FILES)
    active += _read(root / DECODER)
    for token in RETIRED_TOKENS:
        if token in active:
            raise RuntimeError(f"retired approval replay/secret token remains active: {token}")
    for relative in OBSOLETE_FILES:
        if (root / relative).exists():
            tracked = subprocess.run(
                ["git", "ls-files", "--error-unmatch", relative.as_posix()],
                cwd=root,
                capture_output=True,
                check=False,
            )
            if tracked.returncode == 0:
                raise RuntimeError(f"obsolete approval source is tracked: {relative}")


def _check_replay_memory(root: Path) -> None:
    runtime = _read(root / RUNTIME_APPROVAL)
    store = _read(root / Path("rust/crates/guard-runtime/src/policy_store_approval.rs"))
    memory = _read(root / REPLAY_MEMORY)
    required = (
        "register_pending",
        "claim_approval_nonce_fenced",
        "consume_approval_nonce_fenced",
        "resident_epoch",
    )
    for token in required:
        if token not in runtime + store + memory:
            raise RuntimeError(f"approval replay memory integration is incomplete: {token}")
    if "NATIVE_APPROVAL_REPLAY_MEMORY_MAX_ENTRIES" not in memory or "expires_at_ms" not in memory:
        raise RuntimeError("approval replay memory is not bounded by capacity and TTL")
    if "random_epoch" not in memory or "approval_replay_memory" not in store:
        raise RuntimeError("approval replay memory has no per-resident epoch owner")


def _check_authority_fence(root: Path) -> None:
    source = _read(root / POLICY_AUTHORITY)
    if "Sha256" not in source or "authority_fingerprint" not in source:
        raise RuntimeError("authority fence is not SHA-256 based")
    if "DefaultHasher" in source or "hash_map::DefaultHasher" in source:
        raise RuntimeError("authority fence uses a non-cryptographic hash")
    if "authority_unchanged_fenced" not in _read(root / Path("rust/crates/guard-runtime/src/policy_store.rs")):
        raise RuntimeError("approval path has no fenced authority recheck")


def _check_contracts(root: Path) -> None:
    rust_contract = _read(root / APPROVAL_CONTRACT)
    rust_v4_contract = _read(root / V4_APPROVAL_CONTRACT)
    decoder = _read(root / DECODER)
    protocol = _read(root / PROTOCOL)
    protocol_v4 = _read(root / V4_PROTOCOL)
    errors = _read(root / ERRORS)
    if _struct_fields(rust_contract, "ApprovalReceiptV3") != RECEIPT_FIELDS:
        raise RuntimeError("native receipt fields do not match the declared contract")
    if _python_key_set(protocol, "_RECEIPT_KEYS") != RECEIPT_FIELDS:
        raise RuntimeError("Python receipt decoder fields drifted from the native contract")
    for rust_name, python_name in (
        ("ApprovalChallengeV4", "_CHALLENGE_V4_KEYS"),
        ("ApprovalArtifactV4", "_ARTIFACT_V4_KEYS"),
        ("ApprovalReceiptV4", "_RECEIPT_V4_KEYS"),
    ):
        if _struct_fields(rust_v4_contract, rust_name) != _python_key_set(protocol_v4, python_name):
            raise RuntimeError(f"V4 {rust_name} fields drifted from the Python transport contract")
    if "resident_epoch" not in _python_key_set(protocol, "_CHALLENGE_KEYS"):
        raise RuntimeError("Python challenge decoder does not bind the resident epoch")
    if "from .native_approval_errors import NATIVE_APPROVAL_ERROR_CODES" not in decoder:
        raise RuntimeError("Python response decoder does not use the canonical approval error vocabulary")
    if _error_codes(rust_contract, "NATIVE_APPROVAL_ERROR_CODES") != _python_key_set(
        errors, "NATIVE_APPROVAL_ERROR_CODES"
    ):
        raise RuntimeError("native and Python approval error allowlists differ")
    resident = _read(root / RESIDENT_PROTOCOL)
    if "NATIVE_APPROVAL_ERROR_CODES.contains(&code)" not in resident:
        raise RuntimeError("resident transport does not enforce the finite approval error allowlist")


def _check_release_root(root: Path, *, require_environment: bool) -> None:
    authority = _read(root / AUTHORITY)
    docs = _read(root / ENROLLMENT_DOC)
    names = (
        "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_HEX",
        "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_FINGERPRINT_HEX",
    )
    for name in names:
        if name not in authority or name not in docs:
            raise RuntimeError(f"release enrollment root contract is missing: {name}")
    if 'option_env!("HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_HEX")' not in authority:
        raise RuntimeError("production approval authority has no pinned compile-time root")
    if "cfg(test)" not in authority or "[42u8; 32]" not in authority:
        raise RuntimeError("test enrollment root is not isolated from production")
    if not require_environment:
        return
    encoded = os.environ.get(names[0])
    fingerprint = os.environ.get(names[1])
    if encoded is None or fingerprint is None:
        raise RuntimeError("external approval enrollment root is not configured for this release")
    if re.fullmatch(r"[0-9a-f]{64}", encoded) is None:
        raise RuntimeError("release enrollment root must be 32-byte lowercase hex")
    if re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
        raise RuntimeError("release enrollment root fingerprint must be lowercase SHA-256 hex")
    expected = hashlib.sha256(bytes.fromhex(encoded)).hexdigest()
    if fingerprint != expected:
        raise RuntimeError("release enrollment root fingerprint does not match the pinned root")


def _check_ownership_contract(root: Path) -> None:
    workflow = _read(root / WORKFLOW)
    if "native_approval_contract_gate.py" not in workflow:
        raise RuntimeError("Rust authority workflow does not run the approval-specific gate")
    if "--root ." not in workflow:
        raise RuntimeError("approval gate invocation is not rooted at the checkout")
    publish = _read(root / PUBLISH_WORKFLOW)
    if "--require-release-root" not in publish:
        raise RuntimeError("release workflow does not gate the external approval enrollment root")
    for name in ("HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_HEX", "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_FINGERPRINT_HEX"):
        if name not in publish:
            raise RuntimeError(f"release workflow does not pass the pinned enrollment root: {name}")
    managed = _read(root / MANAGED_RESIDENT)
    if "managed-resident-owner.v1.lock" not in managed or "_owner_lock" not in managed:
        raise RuntimeError("managed resident does not retain its owner lock for its full lifetime")
    managed_tests = _read(root / Path("rust/crates/guard-runtime/src/managed_resident_tests.rs"))
    if "managed_owner_lock_rejects_second_process" not in managed_tests:
        raise RuntimeError("approval owner lock has no two-process contention test")
    edge = _read(root / Path("rust/crates/guard-runtime/src/edge.rs"))
    edge_tests = _read(root / Path("rust/crates/guard-runtime/src/edge_tests.rs"))
    if "request_payload_identity" not in edge or "timestamp" not in edge_tests:
        raise RuntimeError("semantic request digest stability coverage is missing")
    policy = _read(root / Path("rust/crates/guard-runtime/src/policy_enforcement.rs"))
    policy_tests = _read(root / Path("rust/crates/guard-runtime/src/policy_enforcement_tests.rs"))
    if "validate_pre_tool_result_matrix" not in policy or "matrix" not in policy_tests:
        raise RuntimeError("action-floor matrix gate or tests are missing")


def run(root: Path, *, require_release_root: bool) -> None:
    _check_file_sizes(root)
    _check_retired_refs(root)
    _check_replay_memory(root)
    _check_authority_fence(root)
    _check_contracts(root)
    _check_release_root(root, require_environment=require_release_root)
    _check_ownership_contract(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--require-release-root",
        action="store_true",
        help="require the externally supplied release root and matching fingerprint",
    )
    args = parser.parse_args()
    try:
        run(args.root.resolve(), require_release_root=args.require_release_root)
    except (OSError, RuntimeError, SyntaxError, ValueError) as exc:
        print(f"native approval contract gate: {exc}", file=sys.stderr)
        return 1
    print("native approval contract gate: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
