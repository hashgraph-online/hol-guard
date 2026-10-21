#!/usr/bin/env python3
"""Record OpenClaw detection vectors from the ORIGINAL Python implementation.

Run against a checkout that still holds `openclaw_support.config_artifacts`
(the base of the commit that introduced the native `openclaw_detect`
runner-authority kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each case materializes a fixture tree under a temporary root, runs the
original `detect` from that root and records the artifacts and config paths
plus the request the native facade sends: the config path and the payload the
Python loader still reads, as JSON text. The executable lookup stays in Python
and is switched off. An inventory that would carry a lone surrogate is
recorded as a refusal. `<ROOT>` stands for the fixture root. A skill root or
directory digest hashes the resolved absolute path, so it is recorded as
`<DIGEST path>` with the resolved path it hashed, and the replay hashes the
path under its own root.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "gemini"))

from openclaw_vector_cases import openclaw_cases  # noqa: E402
from record_adapter_vectors import artifact_dict, materialize, release, scrub  # noqa: E402

from codex_plugin_scanner.guard.adapters import openclaw, openclaw_support  # noqa: E402
from codex_plugin_scanner.guard.adapters.base import HarnessContext  # noqa: E402
from codex_plugin_scanner.guard.adapters.openclaw_config import load_config  # noqa: E402

openclaw._command_available = lambda _executable: False


def facade_args(context: HarnessContext) -> dict:
    """The request the native facade sends for this context."""

    path = openclaw_support.config_path(context)
    workspace = context.workspace_dir
    return {
        "harness": "openclaw",
        "home": str(context.home_dir),
        "workspace": None if workspace is None else str(workspace),
        "cwd": os.getcwd(),
        "config_path": str(path),
        "payload": json.dumps(load_config(path)),
    }


def digest_tokens(outcome: dict) -> dict:
    """Each skill root and directory digest, mapped to its resolved path."""

    tokens: dict[str, str] = {}
    for artifact in outcome["artifacts"]:
        metadata = artifact["metadata"]
        if artifact["artifact_type"] != "skill":
            continue
        for path_key, id_key in (("skill_root", "skill_root_id"), ("skill_dir", "skill_dir_id")):
            resolved = str(Path(metadata[path_key]).resolve())
            if openclaw_support._path_digest(Path(resolved)) != metadata[id_key]:
                sys.exit(f"digest of {resolved} does not match {metadata[id_key]}")
            tokens[metadata[id_key]] = f"<DIGEST {resolved}>"
    return tokens


def tokenize(value: object, tokens: dict[str, str]) -> object:
    text = json.dumps(value, ensure_ascii=False)
    for digest, token in tokens.items():
        text = text.replace(digest, token)
    return json.loads(text)


def run_case(spec: dict, guard_home: Path) -> dict:
    root = Path(tempfile.mkdtemp(prefix="openclaw-vec-")).resolve()
    previous_cwd = os.getcwd()
    try:
        materialize(root, spec)
        os.chdir(root)
        base = Path() if spec["relative"] else root
        context = HarnessContext(
            home_dir=base / spec["home"],
            workspace_dir=None if spec["workspace"] is None else base / spec["workspace"],
            guard_home=guard_home,
        )
        args = facade_args(context)
        try:
            detection = openclaw.OpenClawHarnessAdapter().detect(context)
            outcome: dict = {
                "artifacts": [artifact_dict(item) for item in detection.artifacts],
                "found_paths": list(detection.config_paths),
                "warnings": list(detection.warnings),
            }
            # A lone surrogate CPython would carry cannot cross the UTF-8
            # wire, so the resident refuses the inventory instead.
            json.dumps(outcome, ensure_ascii=False).encode("utf-8")
            outcome = tokenize(outcome, digest_tokens(outcome))
        except (ValueError, TypeError, RecursionError, OSError, RuntimeError):
            outcome = {"refused": True}
        record = {key: spec[key] for key in ("name", "files", "symlinks", "dirs", "dir_modes", "home", "workspace")}
        record["relative"] = spec["relative"]
        record["args"] = scrub(args, root)
        record.update(scrub(outcome, root))
        return record
    finally:
        os.chdir(previous_cwd)
        release(root)


def main() -> None:
    destination = Path(sys.argv[1])
    if not hasattr(openclaw_support, "config_artifacts"):
        sys.exit("refusing to record: the original Python OpenClaw discovery is gone")
    guard_home = Path(tempfile.mkdtemp(prefix="openclaw-vec-guard-")).resolve() / "guard"
    recorded = [run_case(spec, guard_home) for spec in openclaw_cases()]
    document = {"schema": "guard-openclaw-vectors.v1", "cases": recorded}
    destination.write_text(json.dumps(document, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"recorded {len(recorded)} cases")


if __name__ == "__main__":
    main()
