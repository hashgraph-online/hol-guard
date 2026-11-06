#!/usr/bin/env python3
"""Record Codex detection vectors from the ORIGINAL Python implementation.

Run against a checkout that still holds `CodexHarnessAdapter.detect` with its
Python MCP and hook discovery (the base of the commit that introduced the
native `codex_detect` runner-authority kind), never from Rust output:

    cd <base-worktree>
    HOL_GUARD_NATIVE_BINARY=<release hol-guard-runtime> \\
        PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each case materializes a fixture tree under a temporary root, runs the
original `detect` over it and records the artifacts, config paths and
warnings plus the request the native facade sends. `<ROOT>` stands for the
fixture root and `<CMD>` for the managed hook command an install writes.
The manifest, its HMAC and legacy-adoption selection stay in Python, so the
recorder feeds their results to the request exactly as the facade does.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from codex_vector_cases import HOME, cases

from codex_plugin_scanner.guard.adapters import codex
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_hook_sources import parse_json_object, parse_toml_object
from codex_plugin_scanner.guard.models import GuardArtifact

if not hasattr(codex, "_codex_hook_artifacts"):
    sys.exit("refusing to record: the original Python Codex discovery is gone")
if not os.environ.get("HOL_GUARD_NATIVE_BINARY"):
    sys.exit("set HOL_GUARD_NATIVE_BINARY to a release hol-guard-runtime")

CMD = "<CMD>"
AUTHENTICATED: list[dict] = []


def provision_native(guard_home: Path) -> None:
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


def walk(value: object, change) -> object:
    if isinstance(value, str):
        return change(value)
    if isinstance(value, list):
        return [walk(item, change) for item in value]
    if isinstance(value, dict):
        return {change(key): walk(item, change) for key, item in value.items()}
    return value


def encoded(command: str) -> str:
    return json.dumps(command)[1:-1]


def placeholders(data: bytes, command: str, root: Path) -> bytes:
    """File bytes with the managed command (as embedded in JSON text) and the root as placeholders."""
    scrubbed = data.replace(encoded(command).encode(), b"<CMD>").replace(command.encode(), b"<CMD>")
    return scrubbed.replace(str(root).encode(), b"<ROOT>")


def materialize(root: Path, spec: dict, command: str) -> None:
    (root / HOME).mkdir(parents=True)
    locked: list[tuple[Path, int]] = []
    for entry in spec["files"]:
        target = root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        if "hex" in entry:
            target.write_bytes(bytes.fromhex(entry["hex"]))
        else:
            target.write_text(entry["text"].replace(CMD, encoded(command)), encoding="utf-8")
        locked.append((target, entry["mode"]))
    for relative in spec["dirs"]:
        (root / relative).mkdir(parents=True, exist_ok=True)
    for entry in spec["symlinks"]:
        target = root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(entry["target"].replace("<ROOT>", str(root)))
    for path, mode in locked:
        path.chmod(mode)
    for relative, mode in spec["dir_modes"].items():
        (root / relative).chmod(mode)


def release(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if not path.is_symlink():
            path.chmod(0o755)
    shutil.rmtree(root, ignore_errors=True)


def legacy(context: HarnessContext, payload: dict) -> list[dict]:
    if not payload:
        return []
    hooks = payload.get("hooks")
    return codex._current_install_legacy_bindings(context, hooks if isinstance(hooks, dict) else {})


def request_for(context: HarnessContext, spec: dict, root: Path, command: str) -> dict:
    adapter = codex.CodexHarnessAdapter
    hook_config = adapter._hook_config_path(context)
    contents = None
    if spec.get("contents") is not None:
        contents = {}
        for relative, text in spec["contents"].items():
            contents[root / relative] = None if text is None else text.replace(CMD, encoded(command)).encode("utf-8")
    sources = []
    for config_path, hooks_path in adapter._config_hook_pairs(context):
        try:
            if contents is None:
                config_payload = codex._read_toml(config_path)
                hooks_payload = codex._json_object(hooks_path)
            else:
                config_payload = parse_toml_object(contents[config_path], path=config_path, label="Codex config file")
                hooks_payload = parse_json_object(contents[hooks_path], path=hooks_path, label="Codex hooks file")
            config_legacy = legacy(context, config_payload)
            hooks_legacy = legacy(context, hooks_payload)
        except (ValueError, RecursionError, OSError):
            config_legacy = hooks_legacy = []
        sources.append(
            {
                "config_path": str(config_path),
                "hooks_path": str(hooks_path),
                "config_scope": adapter._scope_for(context, config_path),
                "hooks_scope": adapter._scope_for(context, hooks_path),
                "authenticated": config_path == hook_config,
                "config_legacy": config_legacy,
                "hooks_legacy": hooks_legacy,
            }
        )
    return {
        "harness": "codex",
        "authenticated_bindings": list(AUTHENTICATED),
        "sources": sources,
        "contents": None
        if contents is None
        else {
            str(path): None if data is None else placeholders(data, command, root).hex()
            for path, data in contents.items()
        },
    }


def run_case(spec: dict) -> dict:
    root = Path(tempfile.mkdtemp(prefix="codex-vec-")).resolve()
    saved_home = os.environ.get("HOME")
    os.environ["HOME"] = str(root / "uhome")
    try:
        workspace = {"work": root / "work", "root": root, None: None}[spec.get("workspace", "work")]
        context = HarnessContext(home_dir=root / HOME, workspace_dir=workspace, guard_home=root / "guard-home")
        command = codex._hook_command(context)
        materialize(root, spec, command)
        AUTHENTICATED[:] = walk(spec.get("authenticated", []), lambda text: text.replace(CMD, command))
        request = request_for(context, spec, root, command)
        contents = None
        if spec.get("contents") is not None:
            contents = {
                root / relative: None if text is None else text.replace(CMD, encoded(command)).encode("utf-8")
                for relative, text in spec["contents"].items()
            }
        try:
            detection = codex.CodexHarnessAdapter().detect(context, config_contents=contents)
            outcome: dict = {
                "artifacts": [artifact_dict(item) for item in detection.artifacts],
                "found_paths": list(detection.config_paths),
                "warnings": list(detection.warnings),
            }
        except (ValueError, RecursionError, OSError):
            outcome = {"refused": True}

        def scrub(text: str) -> str:
            return text.replace(command, CMD).replace(str(root), "<ROOT>")

        record = {key: spec[key] for key in ("name", "files", "symlinks", "dirs", "dir_modes")}
        record["args"] = walk(request, scrub)
        record.update(walk(outcome, scrub))
        return record
    finally:
        AUTHENTICATED.clear()
        if saved_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = saved_home
        release(root)


def main() -> None:
    destination = Path(sys.argv[1])
    guard_home = Path(tempfile.mkdtemp(prefix="codex-guard-home-")).resolve()
    provision_native(guard_home)
    # The manifest, its HMAC and the packaged-file hashing stay in Python and
    # are exercised elsewhere; the vectors feed their results in directly.
    codex.extend_detection_with_workspace_aibom = lambda detection, **_kwargs: detection
    codex.extend_codex_runtime_inventory = lambda detection, **_kwargs: detection
    codex.load_hook_manifest_baseline = lambda _spec: None
    codex._hook_manifest_spec = lambda _context: None
    codex._manifest_bindings = lambda _manifest: list(AUTHENTICATED)
    recorded = [run_case(spec) for spec in cases()]
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    close_native_residents(guard_home)
    shutil.rmtree(guard_home, ignore_errors=True)
    document = {"schema": "guard-codex-vectors.v1", "cases": recorded}
    destination.write_text(json.dumps(document, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"recorded {len(recorded)} cases")


if __name__ == "__main__":
    main()
