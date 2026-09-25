"""Run installed-wheel corpus and dashboard smoke checks with immutable proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import defaultdict
from collections.abc import Iterable
from contextlib import closing
from itertools import chain, islice
from pathlib import Path
from typing import TYPE_CHECKING, cast

from scripts.installed_canary_proof import InstalledCanaryError, load_subject, verify_install

if TYPE_CHECKING:
    from tests.guard_command_corpus_oracle_types import OracleRecord

_FROZEN_MANIFEST_SHA256 = "9cb33472d122058e8ede6ede57d55d0ebf29b832f8b4eb5321a2309862cf3728"


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


def _framed_case_ids(case_ids: list[str]) -> str:
    digest = hashlib.sha256()
    for case_id in sorted(case_ids):
        encoded = case_id.encode("ascii")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _native_executable_names() -> tuple[str, str]:
    if os.name == "nt":
        return "guard-command-source.exe", "hol-guard-runtime.exe"
    return "guard-command-source", "hol-guard-runtime"


def _platform_wheel_markers() -> tuple[str, ...]:
    machine = platform.machine().lower()
    if sys.platform == "win32":
        return ("win_amd64",)
    if sys.platform == "darwin":
        if machine in {"arm64", "aarch64"}:
            return ("macosx_11_0_arm64",)
        return ("macosx_13_0_x86_64",)
    return ("manylinux_2_17_x86_64",)


def _packaged_native_binaries() -> tuple[Path, Path] | None:
    try:
        from codex_plugin_scanner.guard.extension_builder.native_source_compiler import (
            NativeSourceCompilerError,
            find_packaged_source_compiler,
        )
    except ImportError:
        return None
    try:
        compiler = find_packaged_source_compiler()
    except NativeSourceCompilerError:
        return None
    runtime = compiler.parent / _native_executable_names()[1]
    if compiler.is_file() and runtime.is_file():
        return compiler, runtime
    return None


def _checkout_native_binaries(repo_root: Path) -> tuple[Path, Path] | None:
    compiler_name, runtime_name = _native_executable_names()
    for profile in ("release", "debug"):
        directory = repo_root / "rust" / "target" / profile
        compiler = directory / compiler_name
        runtime = directory / runtime_name
        if compiler.is_file() and runtime.is_file():
            return compiler, runtime
    return None


def _extract_native_binary(archive: zipfile.ZipFile, member: str, destination: Path) -> None:
    info = archive.getinfo(member)
    if info.is_dir() or info.file_size <= 0 or info.file_size > 128 * 1024 * 1024:
        raise InstalledCanaryError("Installed canary native compiler payload is invalid")
    payload = archive.read(info)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(destination, flags, 0o700)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if os.name != "nt":
        destination.chmod(0o700)


def _extract_native_binaries(dist_dir: Path) -> tuple[Path, Path] | None:
    if not dist_dir.is_dir():
        return None
    compiler_name, runtime_name = _native_executable_names()
    members = (
        f"codex_plugin_scanner/_native/{compiler_name}",
        f"codex_plugin_scanner/_native/{runtime_name}",
    )
    markers = _platform_wheel_markers()
    for wheel in sorted(dist_dir.glob("hol_guard-*.whl")):
        if wheel.is_symlink() or not any(marker in wheel.name for marker in markers):
            continue
        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
            if not set(members) <= names:
                continue
            destination = Path(tempfile.mkdtemp(prefix="hol-guard-canary-native-"))
            _extract_native_binary(archive, members[0], destination / compiler_name)
            _extract_native_binary(archive, members[1], destination / runtime_name)
            return destination / compiler_name, destination / runtime_name
    return None


def _pin_installed_native_binaries(repo_root: Path) -> None:
    compiler_env = "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER"
    runtime_env = "HOL_GUARD_NATIVE_BINARY"
    packaged = _packaged_native_binaries()
    if packaged is not None:
        os.environ[compiler_env], os.environ[runtime_env] = (str(packaged[0]), str(packaged[1]))
        return
    extracted = _extract_native_binaries(repo_root / "dist")
    if extracted is not None:
        os.environ[compiler_env], os.environ[runtime_env] = (str(extracted[0]), str(extracted[1]))
        return
    configured_compiler = os.environ.get(compiler_env)
    configured_runtime = os.environ.get(runtime_env)
    if (
        configured_compiler
        and configured_runtime
        and Path(configured_compiler).is_file()
        and Path(configured_runtime).is_file()
    ):
        return
    checkout = _checkout_native_binaries(repo_root)
    if checkout is not None:
        os.environ[compiler_env], os.environ[runtime_env] = (str(checkout[0]), str(checkout[1]))
        return
    raise InstalledCanaryError("Installed canary native compiler is unavailable")


def _run_corpus(repo_root: Path) -> dict[str, object]:
    sys.path.insert(0, str(repo_root))
    _pin_installed_native_binaries(repo_root)
    from codex_plugin_scanner.guard.action_lattice import guard_action_severity
    from tests.guard_command_corpus import iter_adversarial_corpus, iter_benign_corpus
    from tests.guard_command_corpus_native import (
        NATIVE_CORPUS_BATCH_SIZE,
        evaluate_native_corpus_batch,
        pin_neutral_attribution,
    )
    from tests.guard_command_corpus_native_contract import expected_native_groups, validate_native_case
    from tests.guard_command_corpus_oracle import iter_adversarial_oracle, iter_benign_oracle

    pin_neutral_attribution()
    bindings = _validate_corpus_bindings(repo_root)
    ranks = {
        action: guard_action_severity(action)
        for action in ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block")
    }
    ranks["monitor"] = ranks["warn"]
    contract_groups: defaultdict[str, list[str]] = defaultdict(list)
    count = 0
    started = time.perf_counter()
    streams = chain(
        zip(iter_benign_corpus(), iter_benign_oracle(), strict=True),
        zip(iter_adversarial_corpus(), iter_adversarial_oracle(), strict=True),
    )
    cwd = repo_root / "workspace"
    home_dir = repo_root / "home"
    while batch := tuple(islice(streams, NATIVE_CORPUS_BATCH_SIZE)):
        evaluations = evaluate_native_corpus_batch([case for case, _oracle in batch], cwd=cwd, home_dir=home_dir)
        for (case, oracle), reviewed in zip(batch, evaluations, strict=True):
            decision = reviewed.evaluation
            observed = decision.decision_plane.action
            if ranks[observed] < ranks[oracle.minimum_floor]:
                raise InstalledCanaryError("Installed evaluator is below the frozen corpus oracle")
            try:
                group_id = validate_native_case(case, oracle, reviewed)
            except ValueError as error:
                raise InstalledCanaryError(str(error)) from error
            contract_groups[group_id].append(case.case_id)
            count += 1
        del evaluations
    observed_contract = {
        key: (len(ids), _framed_case_ids(ids)) for key, ids in contract_groups.items()
    }
    if count != 51_000 or observed_contract != expected_native_groups():
        raise InstalledCanaryError("Installed evaluator differs from the frozen native corpus contract")
    return {
        "case_count": count,
        "elapsed_seconds": time.perf_counter() - started,
        "known_gap_groups": len(observed_contract),
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
