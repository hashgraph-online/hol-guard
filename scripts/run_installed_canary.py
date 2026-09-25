"""Run installed-wheel corpus and dashboard smoke checks with immutable proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterable
from contextlib import closing
from importlib.metadata import distribution
from pathlib import Path
from typing import TYPE_CHECKING, cast

from scripts.installed_canary_proof import InstalledCanaryError, load_subject, verify_install

if TYPE_CHECKING:
    from tests.guard_command_corpus_oracle_types import OracleRecord

_FROZEN_MANIFEST_SHA256 = "9cb33472d122058e8ede6ede57d55d0ebf29b832f8b4eb5321a2309862cf3728"
# These counts belong to the source-bound 51k corpus validated by the manifest above.
_FROZEN_CORPUS_CASE_COUNT = 51_000
_FROZEN_NATIVE_REJECTION_COUNT = 27_084
_FROZEN_ORACLE_ABOVE_COUNT = 11_558


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _oracle_digest(records: Iterable[OracleRecord]) -> str:
    digest = hashlib.sha256()
    for record in records:
        payload = json.dumps(
            {
                "case_id": record.case_id,
                "workflow_family": record.workflow_family,
                "effects": list(record.effects),
                "target_scope": record.target_scope,
                "uncertainties": list(record.uncertainties),
                "required_proofs": list(record.required_proofs),
                "provided_proofs": list(record.provided_proofs),
                "minimum_floor": record.minimum_floor,
                "decision_status": record.decision_status,
                "source_id": record.source_id,
                "owner": record.owner,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _validate_corpus_bindings(repo_root: Path) -> dict[str, object]:
    from tests.guard_command_corpus import (
        KNOWN_GAPS_PATH,
        MANIFEST_PATH,
        PAIRS_PATH,
        corpus_digest,
        iter_adversarial_corpus,
        iter_benign_corpus,
        load_seed_manifest,
    )
    from tests.guard_command_corpus_oracle import iter_adversarial_oracle, iter_benign_oracle

    manifest = load_seed_manifest()
    expected_digests = cast(dict[str, str], manifest["canonical_digests"])
    actual_digests = {
        "benign": corpus_digest(iter_benign_corpus()),
        "adversarial": corpus_digest(iter_adversarial_corpus()),
        "oracle": _oracle_digest((*iter_benign_oracle(), *iter_adversarial_oracle())),
    }
    oracle_paths = tuple(sorted((repo_root / "tests").glob("guard_command_corpus_oracle*.py")))
    source_hashes = {path.name: _sha256(path) for path in oracle_paths}
    if (
        _sha256(MANIFEST_PATH) != _FROZEN_MANIFEST_SHA256
        or actual_digests != expected_digests
        or _sha256(repo_root / "tests/guard_command_corpus.py") != manifest["generator_source_sha256"]
        or source_hashes != manifest["oracle_source_sha256"]
        or _sha256(PAIRS_PATH) != manifest["pairs_sha256"]
        or _sha256(KNOWN_GAPS_PATH) != manifest["known_gaps_sha256"]
    ):
        raise InstalledCanaryError("Installed canary corpus does not match its frozen source and oracle bindings")
    return {
        "canonical_digests": actual_digests,
        "manifest_sha256": _sha256(MANIFEST_PATH),
        "source_files_verified": 1 + len(source_hashes),
    }


def _run_corpus(repo_root: Path) -> dict[str, object]:
    bindings = _validate_corpus_bindings(repo_root)
    native_root = Path(distribution("hol-guard").locate_file("codex_plugin_scanner/_native"))
    suffix = ".exe" if sys.platform == "win32" else ""
    runtime = native_root / f"hol-guard-runtime{suffix}"
    compiler = native_root / f"guard-command-source{suffix}"
    if not runtime.is_file() or not compiler.is_file():
        raise InstalledCanaryError("Installed Guard package is missing native corpus binaries")
    environment = os.environ.copy()
    environment["HOL_GUARD_NATIVE_BINARY"] = str(runtime)
    environment["HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER"] = str(compiler)
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            [sys.executable, str(repo_root / "scripts/run_installed_native_corpus.py")],
            cwd=repo_root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=240,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise InstalledCanaryError("Installed native corpus exceeded its time limit") from exc
    if completed.returncode != 0:
        raise InstalledCanaryError(
            f"Installed native corpus failed (exit {completed.returncode}): {completed.stderr[-1200:]}"
        )
    try:
        decoded = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise InstalledCanaryError("Installed native corpus report is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise InstalledCanaryError("Installed native corpus report is not an object")
    report = cast(dict[str, object], decoded)
    raw_groups = report.get("native_contract_groups")
    if not isinstance(raw_groups, dict) or any(
        not isinstance(values, list)
        or len(values) != 2
        or not isinstance(values[0], int)
        or isinstance(values[0], bool)
        for values in raw_groups.values()
    ):
        raise InstalledCanaryError("Installed native corpus report has invalid groups")
    groups = cast(dict[str, list[object]], raw_groups)
    count = sum(cast(int, values[0]) for values in groups.values())
    native_rejection_count = report.get("native_rejection_count")
    original_oracle_above_count = report.get("original_oracle_above_count")
    if (
        report.get("native_contract_equality") is not True
        or report.get("original_oracle_below_count") != 0
        or count != _FROZEN_CORPUS_CASE_COUNT
        or not isinstance(native_rejection_count, int)
        or isinstance(native_rejection_count, bool)
        or native_rejection_count != _FROZEN_NATIVE_REJECTION_COUNT
        or not isinstance(original_oracle_above_count, int)
        or isinstance(original_oracle_above_count, bool)
        or original_oracle_above_count != _FROZEN_ORACLE_ABOVE_COUNT
    ):
        raise InstalledCanaryError("Installed evaluator differs from the frozen 51k native corpus contract")
    return {
        "case_count": count,
        "elapsed_seconds": time.perf_counter() - started,
        "native_contract_groups": len(groups),
        "native_rejection_count": native_rejection_count,
        "original_oracle_above_count": original_oracle_above_count,
        "bindings": bindings,
    }


def _no_post_execution_proof_smoke() -> dict[str, object]:
    from codex_plugin_scanner.guard.adapters.contracts import contract_for
    from codex_plugin_scanner.guard.store import GuardStore

    harness = "opencode"
    contract = contract_for(harness)
    if contract is None or "tool_result" in contract.event_surfaces:
        raise InstalledCanaryError("Installed no-post-proof harness contract is invalid")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        guard_home = root / "guard-home"
        workspace = root / "workspace"
        workspace.mkdir()
        initialized = subprocess.run(
            ["git", "init", "--quiet", str(workspace)],
            capture_output=True,
            check=False,
            encoding="utf-8",
            timeout=10,
        )
        if initialized.returncode != 0:
            raise InstalledCanaryError("Installed no-post-proof workspace initialization failed")
        payload = {
            "hook_event_name": "PreToolUse",
            "event": "PreToolUse",
            "tool_name": "bash",
            "tool_input": {"command": "git diff --stat"},
            "cwd": str(workspace),
            "source_scope": "project",
        }
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "codex_plugin_scanner.cli",
                "guard",
                "hook",
                "--guard-home",
                str(guard_home),
                "--home",
                str(guard_home),
                "--workspace",
                str(workspace),
                "--harness",
                harness,
                "--json",
            ],
            input=json.dumps(payload),
            capture_output=True,
            check=False,
            cwd=workspace,
            encoding="utf-8",
            timeout=30,
        )
        if completed.returncode != 0:
            raise InstalledCanaryError(
                f"Installed no-post-proof hook returned {completed.returncode}, expected prompt-free continuation"
            )
        store = GuardStore(guard_home, prime_policy_integrity=False)
        with closing(sqlite3.connect(store.path)) as connection:
            row = cast(
                tuple[object, ...] | None,
                connection.execute(
                    """
                    select harness, hook_phase, execution_status, proof_level,
                           policy_action, decision_reason_code, match_count
                    from command_activity
                    """
                ).fetchone(),
            )
        expected = (harness, "pre", "allowed_unconfirmed", "pre_hook", "warn", "policy", 0)
        if row is None or tuple(row) != expected:
            raise InstalledCanaryError(
                f"Installed no-post-proof hook persisted unexpected activity evidence: {tuple(row) if row else None!r}"
            )
        return {
            "harness": harness,
            "post_execution_surface": False,
            "execution_status": str(row[2]),
            "proof_level": str(row[3]),
            "policy_action": str(row[4]),
            "decision_reason_code": str(row[5]),
        }


def _dashboard_smoke() -> dict[str, object]:
    import codex_plugin_scanner.guard.daemon.server as server

    static_root = Path(server.__file__).resolve().with_name("static")
    index = static_root / "index.html"
    script = static_root / "assets/guard-dashboard.js"
    stylesheet = static_root / "assets/index.css"
    for path in (index, script, stylesheet):
        if not path.is_file() or path.stat().st_size == 0:
            raise InstalledCanaryError(f"Installed dashboard asset is missing: {path.name}")
    index_text = index.read_text(encoding="utf-8")
    if "/assets/guard-dashboard.js" not in index_text or "/assets/index.css" not in index_text:
        raise InstalledCanaryError("Installed dashboard shell does not reference its packaged assets")
    bun = shutil.which("bun")
    if bun is None:
        raise InstalledCanaryError("Installed dashboard smoke requires Bun")
    with tempfile.TemporaryDirectory() as output_text:
        output = Path(output_text)
        try:
            _ = subprocess.run(
                [
                    bun,
                    "build",
                    str(script),
                    str(stylesheet),
                    "--target",
                    "browser",
                    "--outdir",
                    str(output),
                    "--minify",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise InstalledCanaryError("Installed dashboard assets do not produce a browser bundle") from exc
        bundled_script = output / "guard-dashboard.js"
        bundled_stylesheet = output / "index.css"
        if not bundled_script.is_file() or not bundled_stylesheet.is_file():
            raise InstalledCanaryError("Installed dashboard browser bundle is incomplete")
        return {
            "asset_count": sum(1 for path in static_root.rglob("*") if path.is_file()),
            "index_sha256": hashlib.sha256(index.read_bytes()).hexdigest(),
            "browser_bundle_bytes": bundled_script.stat().st_size + bundled_stylesheet.stat().st_size,
        }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--subject", type=Path, required=True)
    _ = parser.add_argument("--version", required=True)
    _ = parser.add_argument("--source-sha", required=True)
    _ = parser.add_argument("--repo-root", type=Path, required=True)
    _ = parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    subject_path = cast(Path, args.subject)
    version = cast(str, args.version)
    source_sha = cast(str, args.source_sha)
    repo_root = cast(Path, args.repo_root)
    output_path = cast(Path, args.output)
    try:
        subject = load_subject(subject_path, version=version, source_sha=source_sha)
        report = {
            "schema_version": "hol-guard.installed-canary-evidence.v1",
            "installed": verify_install(subject, repo_root),
            "corpus": _run_corpus(repo_root),
            "no_post_execution_proof": _no_post_execution_proof_smoke(),
            "dashboard": _dashboard_smoke(),
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        _ = output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (InstalledCanaryError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
