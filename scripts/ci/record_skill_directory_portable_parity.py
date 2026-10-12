#!/usr/bin/env python3
"""Freeze original portable skill-tree outcomes before native cutover.

This authoring recorder refuses changed sources and is never a runtime oracle.
"""

from __future__ import annotations

import dataclasses
import errno
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src/codex_plugin_scanner/guard"
PINNED = {
    "portable_skill_directory_identity.py": "75835799760e43464f58ba6adebc9e31ccb128d0538d4cd679490f7cf2e7a5b2",
    "portable_skill_directory_discovery.py": "b1789e9c9984282d3477befa8a28c1e21d4504d616781ea12bad9ba5e4ab6eaf",
    "portable_skill_directory_support.py": "bae0167a22c48559d49c10a37da8829e90e9a07b8e0377e657baad8d863af915",
    "skill_directory_identity.py": "d87c71bb4a338a35e5b38cc714accdfb267e7836e3d42537d004365458e48c85",
    "skill_directory_discovery.py": "9e10610144fd841bb0ade909b7dae8fc0993c39daffaaf6d78d879b14cac8583",
    "native_skill_directory_identity.py": "8d97e399b957a9cd42d7a2e4129ee36abd174c5dac3595c83482b976ba59103d",
}


def main() -> None:
    for name, digest in PINNED.items():
        if hashlib.sha256((SOURCE / name).read_bytes()).hexdigest() != digest:
            raise SystemExit(f"Original source changed: {name}; recorded outcomes must not be regenerated.")
    sys.path.insert(0, str(ROOT / "src"))
    from codex_plugin_scanner.guard import portable_skill_directory_identity as original_identity
    from codex_plugin_scanner.guard.portable_skill_directory_discovery import discover_skill_documents
    from codex_plugin_scanner.guard.portable_skill_directory_identity import inspect_skill_directory
    from codex_plugin_scanner.guard.skill_directory_identity_contract import SkillDirectoryIdentityLimits

    spec = importlib.util.spec_from_file_location(
        "original_skill_vectors", ROOT / "tests/test_guard_skill_directory_identity_vectors.py"
    )
    assert spec is not None and spec.loader is not None
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    fixture = json.loads(
        (ROOT / "rust/crates/guard-runtime/tests/fixtures/skill_directory_identity_vectors.json").read_text()
    )
    frozen: dict[str, object] = {
        "schema": "guard.skill-directory-portable-parity.v1",
        "source_sha256": PINNED,
        "platform": sys.platform,
    }
    for action in ("inspect", "discover"):
        cases = []
        for original in fixture[action]:
            case = {key: value for key, value in original.items() if not key.startswith("expected")}
            with tempfile.TemporaryDirectory(prefix="skill-vector-") as temporary:
                base = Path(temporary).resolve()
                helper._build(base, case)
                try:
                    limits = SkillDirectoryIdentityLimits(**case.get("limits", {}))
                    if action == "inspect":
                        identity = inspect_skill_directory(
                            base / case["document"], scope_root=base / case.get("scope", ""), limits=limits
                        )
                        case["expected"] = dataclasses.asdict(identity)
                        # Replay the exact original Windows mode projection, while keeping
                        # host I/O honest. This freezes digests, not Windows I/O proof.
                        mode = original_identity._security_mode
                        windows_mode = types.FunctionType(
                            mode.__code__, {**mode.__globals__, "os": types.SimpleNamespace(name="nt")}
                        )
                        try:
                            original_identity._security_mode = windows_mode
                            projected = inspect_skill_directory(
                                base / case["document"], scope_root=base / case.get("scope", ""), limits=limits
                            )
                            case["expected_windows_mode_projection"] = dataclasses.asdict(projected)
                        finally:
                            original_identity._security_mode = mode
                    else:
                        root = base / case["root"]
                        result = discover_skill_documents(root, limits=limits)
                        case["expected"] = {
                            "documents_hex": [os.fsencode(path.relative_to(root)).hex() for path in result.documents],
                            "issues": [
                                {
                                    "relative_path_hex": os.fsencode(issue.relative_path).hex(),
                                    "failure_reason": issue.failure_reason,
                                    "issue_id": issue.issue_id,
                                    "identity": dataclasses.asdict(issue.identity),
                                }
                                for issue in result.issues
                            ],
                        }
                finally:
                    helper._restore_modes(base)
            if "expected_linux" in original:
                case["expected_linux"] = original["expected_linux"]
            cases.append(case)
        frozen[action] = cases
    byte_cases = []
    if os.name != "nt":
        for root_bytes in (b"ordinary", b"root-\xff"):
            for name_bytes in (b"SKILL.md", b"child-\xff"):
                with tempfile.TemporaryDirectory(prefix="skill-path-") as temporary:
                    base = Path(temporary).resolve()
                    root = base / os.fsdecode(root_bytes)
                    try:
                        root.mkdir()
                        (root / "SKILL.md").write_bytes(b"# Fixture\n")
                        if name_bytes != b"SKILL.md":
                            (root / os.fsdecode(name_bytes)).write_bytes(b"content")
                    except OSError as error:
                        if error.errno != errno.EILSEQ:
                            raise
                        # Some filesystems cannot create byte names. Never invent their outcomes.
                        continue
                    identity = inspect_skill_directory(root / "SKILL.md", scope_root=base)
                    discovery = discover_skill_documents(root)
                    byte_cases.append(
                        {
                            "root_hex": root_bytes.hex(),
                            "entry_hex": name_bytes.hex(),
                            "identity": dataclasses.asdict(identity),
                            "documents_hex": [
                                os.fsencode(path.relative_to(root)).hex() for path in discovery.documents
                            ],
                        }
                    )
    frozen["byte_paths"] = byte_cases
    output = ROOT / "rust/crates/guard-runtime/tests/fixtures/skill_directory_portable_vectors.json"
    output.write_text(json.dumps(frozen, ensure_ascii=True, sort_keys=True, indent=2) + "\n")
    print(f"Recorded {sum(len(frozen[key]) for key in ('inspect', 'discover', 'byte_paths'))} original cases")


if __name__ == "__main__":
    main()
