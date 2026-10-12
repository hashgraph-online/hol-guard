#!/usr/bin/env python3
"""Record AIBOM discovery vectors from the ORIGINAL Python implementation.

Run against a checkout that still holds `guard/aibom_detection.py` and
`guard/codex_skill_config.py` (the base of the commit that introduced the
native `aibom_*` runner-authority kinds), never from Rust output:

    cd <base-worktree>
    HOL_GUARD_NATIVE_BINARY=<release hol-guard-runtime> \\
        PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each case materializes a fixture tree under a temporary root (files, modes,
symlinks), runs the original Python function against it and records the
expected result. Paths are written with `<ROOT>` for the fixture root and
`<MID>` for the marketplace id (a digest of the marketplace file path, which
depends on the root); the Rust replay substitutes both before comparing.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from codex_plugin_scanner.guard import aibom_detection as old
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection

if not hasattr(old, "discover_shared_workspace_aibom_artifacts") or hasattr(old, "NativeAibomError"):
    sys.exit("refusing to record: the original Python AIBOM implementation is gone")
if not os.environ.get("HOL_GUARD_NATIVE_BINARY"):
    sys.exit("set HOL_GUARD_NATIVE_BINARY to a release hol-guard-runtime")


from aibom_vector_cases import cases as workspace_cases
from aibom_vector_helpers import HOME, USER_HOME, WORK, mcp_cases


def provision_native(guard_home: Path) -> None:
    """Point every native transport at one keyed resident, as the test harness does."""

    from codex_plugin_scanner.guard import native_context
    from codex_plugin_scanner.guard.native_policy_snapshot import provision_native_policy_verifier_key
    from codex_plugin_scanner.guard.runtime import approval_context

    (guard_home / "native-runtime").mkdir(mode=0o700, parents=True)
    provision_native_policy_verifier_key(guard_home, b"\x07" * 32)
    os.environ.update(
        {
            "HOL_GUARD_NATIVE": "force",
            "HOL_GUARD_TEST_MODE": "1",
            "HOL_GUARD_NATIVE_DIAGNOSTIC": "1",
            "HOL_GUARD_RESIDENT_TEST_SEAMS": "1",
        }
    )
    native_context.context_digest_guard_home = lambda: guard_home
    approval_context._context_digest_guard_home = lambda _home: guard_home
    probe = native_context.native_context_digest(
        "launch_argv_digest", {"argv": ["guard-context-warmup"]}, guard_home=guard_home
    )
    if not probe:
        sys.exit("native resident did not answer; refusing to record unbound hashes")


def artifact_dict(artifact: GuardArtifact) -> dict:
    payload = dataclasses.asdict(artifact)
    payload.pop("runtime_private_metadata", None)
    payload["args"] = list(artifact.args)
    return payload


def materialize(root: Path, case: dict) -> None:
    (root / WORK).mkdir(parents=True)
    (root / HOME).mkdir()
    (root / USER_HOME).mkdir()
    for entry in case.get("files", []):
        target = root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(entry["text"], encoding="utf-8")
        target.chmod(entry["mode"])
    for entry in case.get("symlinks", []):
        target = root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(entry["target"].replace("<ROOT>", str(root)))
    for relative in case.get("dirs", []):
        (root / relative).mkdir(parents=True, exist_ok=True)


def scrub(value: object, root: Path, marketplace_ids: dict[str, str]) -> object:
    text = json.dumps(value, ensure_ascii=False)
    for identifier, placeholder in marketplace_ids.items():
        text = text.replace(identifier, placeholder)
    return json.loads(text.replace(str(root), "<ROOT>"))


def marketplace_ids(root: Path, case: dict) -> dict[str, str]:
    found: dict[str, str] = {}
    for relative in case.get("marketplace_files", []):
        resolved = (root / relative).resolve()
        found[hashlib.sha256(str(resolved).encode()).hexdigest()[:12]] = "<MID>"
    return found


def run_case(case: dict) -> dict:
    root = Path(tempfile.mkdtemp(prefix="aibom-vec-")).resolve()
    saved_home = os.environ.get("HOME")
    os.environ["HOME"] = str(root / USER_HOME)
    try:
        materialize(root, case)
        home_dir, workspace_dir = root / HOME, root / WORK
        kind = case["kind"]
        args = {"harness": case["harness"]}
        outcome: dict
        try:
            if kind == "workspace_artifacts":
                args["workspace_dir"] = "<ROOT>/" + WORK
                found = old.discover_shared_workspace_aibom_artifacts(
                    case["harness"], home_dir=home_dir, workspace_dir=workspace_dir
                )
                outcome = {"artifacts": [artifact_dict(item) for item in found]}
            elif kind == "merge_plan":
                existing = [GuardArtifact(**item) for item in resolve_existing(case["existing"], root)]
                detection = HarnessDetection(
                    harness=case["harness"],
                    installed=True,
                    command_available=True,
                    config_paths=tuple(case.get("config_paths", [])),
                    artifacts=tuple(existing),
                    warnings=(),
                )
                merged = old.extend_detection_with_workspace_aibom(
                    detection, home_dir=home_dir, workspace_dir=workspace_dir
                )
                args["workspace_dir"] = "<ROOT>/" + WORK
                args["existing"] = [
                    {key: item.get(key) for key in ("artifact_id", "artifact_type", "harness", "config_path")}
                    for item in case["existing"]
                ]
                outcome = {
                    "artifacts": [artifact_dict(item) for item in merged.artifacts],
                    "config_paths": list(merged.config_paths),
                }
            elif kind == "codex_skills":
                args["home_dir"] = "<ROOT>/" + HOME
                args["workspace_dir"] = None if case.get("no_workspace") else "<ROOT>/" + WORK
                args["user_home"] = "<ROOT>/" + USER_HOME
                found = old.discover_codex_skill_artifacts(
                    case["harness"],
                    home_dir=home_dir,
                    workspace_dir=None if case.get("no_workspace") else workspace_dir,
                )
                outcome = {"artifacts": [artifact_dict(item) for item in found]}
            else:
                raise AssertionError(kind)
        except ValueError:
            outcome = {"refused": True}
        record = {
            "name": case["name"],
            "kind": kind,
            "files": case.get("files", []),
            "symlinks": case.get("symlinks", []),
            "dirs": case.get("dirs", []),
            "marketplace_files": case.get("marketplace_files", []),
            "args": args,
        }
        if kind == "merge_plan":
            record["existing_artifacts"] = scrub(
                [artifact_dict(GuardArtifact(**item)) for item in resolve_existing(case["existing"], root)],
                root,
                {},
            )
            record["existing_config_paths"] = case.get("config_paths", [])
        record.update(scrub(outcome, root, marketplace_ids(root, case)))
        return record
    finally:
        if saved_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = saved_home
        shutil.rmtree(root, ignore_errors=True)


def resolve_existing(existing: list[dict], root: Path) -> list[dict]:
    return [
        {
            "artifact_id": item["artifact_id"],
            "name": item.get("name", "existing"),
            "harness": item["harness"],
            "artifact_type": item["artifact_type"],
            "source_scope": item.get("source_scope", "project"),
            "config_path": (item["config_path"] or "").replace("<ROOT>", str(root)),
            "metadata": item.get("metadata", {}),
        }
        for item in existing
    ]


def main() -> None:
    destination = Path(sys.argv[1])
    guard_home = Path(tempfile.mkdtemp(prefix="aibom-guard-home-")).resolve()
    provision_native(guard_home)
    recorded = []
    for case in [*workspace_cases(), *mcp_cases()]:
        recorded.append(case if case["kind"] == "mcp_metadata" else run_case(case))
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    close_native_residents(guard_home)
    shutil.rmtree(guard_home, ignore_errors=True)
    document = {"schema": "guard-aibom-vectors.v1", "cases": recorded}
    destination.write_text(json.dumps(document, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"recorded {len(recorded)} cases")


if __name__ == "__main__":
    main()
