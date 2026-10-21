#!/usr/bin/env python3
"""Record Gemini, Antigravity, Devin, Grok, Kimi, OpenCode and Cursor detection
vectors from the ORIGINAL Python implementation.

Run against a checkout that still holds the original helper `ORIGINALS` names
for the harness (the base of the commit that introduced its native
`<harness>_detect` runner-authority kind), never from Rust output:

    cd <base-worktree>
    HOL_GUARD_NATIVE_BINARY=<release hol-guard-runtime> \\
        PYTHONPATH=$PWD/src python3 <this-file> <harness> <output vectors.json>

Each case materializes a fixture tree under a temporary root, runs the
original `detect` over it and records the artifacts, config paths and warnings
plus the request the native facade sends. Skill discovery, directory identity
and MCP metadata digests come from the release resident, so the recorder
refuses to run without one. An inventory that would carry a lone surrogate is
recorded as a refusal. Workspace AIBOM discovery is not part of the port and
is switched off; so are the Grok executable lookup, version probe and stale
managed-entry check, which stay in Python, and the OpenCode and Cursor MCP
firewall, Cursor managed hook and CLI lookups and the OpenCode command lookup,
which the ports keep in Python around the native call. An OpenCode case with
`snapshot` records `load_opencode_install_snapshot` instead of `detect`. The Grok system policy files are
read from `<ROOT>/etc/grok`. `<ROOT>` stands for the fixture root, in paths, in
file contents and in a case's environment.
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

from adapter_vector_cases import cases

from codex_plugin_scanner.ecosystems.opencode import _load_json_or_jsonc
from codex_plugin_scanner.guard.adapters import (
    antigravity,
    cursor,
    devin,
    gemini,
    grok,
    grok_config,
    kimi,
    opencode,
    opencode_artifacts,
)
from codex_plugin_scanner.guard.adapters._modules.opencode import opencode_install_snapshot
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.grok_executable import GrokExecutableResolution
from codex_plugin_scanner.guard.models import GuardArtifact

ADAPTERS = {
    "gemini": gemini.GeminiHarnessAdapter,
    "antigravity": antigravity.AntigravityHarnessAdapter,
    "devin": devin.DevinHarnessAdapter,
    "grok": grok.GrokHarnessAdapter,
    "kimi": kimi.KimiHarnessAdapter,
    "opencode": opencode.OpenCodeHarnessAdapter,
    "cursor": cursor.CursorHarnessAdapter,
}
# The original helper each port removed; its presence proves the source is
# the original Python.
ORIGINALS = {
    "gemini": (gemini.GeminiHarnessAdapter, "_entry_hook_command"),
    "antigravity": (antigravity.AntigravityHarnessAdapter, "_mcp_source"),
    "devin": (devin.DevinHarnessAdapter, "_claude_hooks_overlap"),
    "grok": (grok_config, "append_mcp_artifacts"),
    "kimi": (kimi.KimiHarnessAdapter, "_append_mcp_artifacts"),
    "opencode": (opencode_artifacts, "append_config_artifacts"),
    "cursor": (cursor, "enrich_mcp_server_metadata"),
}

for module in (gemini, devin, grok, kimi, opencode, opencode_install_snapshot, cursor):
    module.extend_detection_with_workspace_aibom = lambda detection, **_: detection
opencode_artifacts.enrich_artifact_with_mcp_skill_firewall = lambda artifact: artifact
cursor.enrich_artifact_with_mcp_skill_firewall = lambda artifact: artifact
cursor.detect_managed_cursor_hook_artifact = lambda _path, _payload: None
cursor.cursor_cli_command_available = lambda _context: False
opencode._command_available = lambda _executable: False
grok.resolve_trusted_grok_executable = lambda _context: GrokExecutableResolution(None)
grok.GrokHarnessAdapter._version_probe = staticmethod(lambda _context, _resolution: {})
grok.GrokHarnessAdapter._has_stale_guard_entries = lambda _self, _context: False
SYSTEM_POLICY = ("managed_config.toml", "requirements.toml")


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


def materialize(root: Path, spec: dict) -> None:
    if not any(entry["path"] == "work" for entry in spec["symlinks"]):
        (root / "work").mkdir(parents=True)
    (root / spec["home"]).mkdir(parents=True, exist_ok=True)
    locked: list[tuple[Path, int]] = []
    for entry in spec["files"]:
        target = root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        if "hex" in entry:
            target.write_bytes(bytes.fromhex(entry["hex"]))
        else:
            target.write_bytes(entry["text"].replace("<ROOT>", str(root)).encode("utf-8", "surrogatepass"))
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
    for directory, _, _ in os.walk(root):
        os.chmod(directory, 0o755)
    for path in root.rglob("*"):
        if not path.is_symlink():
            path.chmod(0o755)
    shutil.rmtree(root, ignore_errors=True)


def scrub(value: object, root: Path) -> object:
    return json.loads(json.dumps(value, ensure_ascii=False).replace(str(root), "<ROOT>"))


def system_policy_paths(root: Path) -> list[Path]:
    return [root / "etc" / "grok" / name for name in SYSTEM_POLICY]


def opencode_request(context: HarnessContext, snapshot: bool) -> dict:
    """The OpenCode configs as the port sends them: parsed, non-empty
    payloads for `detect`, normalized payloads for the install snapshot."""

    if snapshot:
        loaded = opencode_install_snapshot.load_opencode_install_snapshot(context, command_available=False)
        configs = [(config.path, config.scope, config.payload) for config in loaded.configs]
    else:
        configs = []
        for path in opencode_artifacts.config_paths(context):
            payload, parse_error, _reason = _load_json_or_jsonc(path)
            if not parse_error and payload:
                configs.append((path, opencode.OpenCodeHarnessAdapter._scope_for(context, path), payload))
    config_dir = opencode_artifacts.configured_config_dir(context)
    return {
        "configs": [
            {"path": str(path), "scope": scope, "payload": json.dumps(payload)} for path, scope, payload in configs
        ],
        "skip_verified_mcp_companions": not snapshot,
        "config_dir": None if config_dir is None else str(config_dir),
    }


def detect(harness: str, context: HarnessContext, snapshot: bool):
    if snapshot:
        return opencode_install_snapshot.load_opencode_install_snapshot(context, command_available=False).detection
    return ADAPTERS[harness]().detect(context)


def facade_args(harness: str, context: HarnessContext, root: Path, snapshot: bool = False) -> dict:
    """The request the native facade sends for this context."""

    home = context.home_dir
    if harness == "kimi":
        home = kimi.KimiHarnessAdapter._kimi_home_dir(context)
    workspace = context.workspace_dir
    request: dict[str, object] = {
        "harness": harness,
        "home": str(home),
        "workspace": None if workspace is None else str(workspace),
    }
    if harness == "grok":
        request["grok_home"] = str(grok.GrokHarnessAdapter._grok_home_dir(context))
        request["system_policy_paths"] = [
            str(path) for path in system_policy_paths(root) if path.is_file() and os.access(path, os.R_OK)
        ]
    if harness == "opencode":
        request.update(opencode_request(context, snapshot))
    if harness == "cursor":
        request["configs"] = [
            {"path": str(path), "payload": json.dumps(payload)}
            for path in cursor.CursorHarnessAdapter._editor_config_paths(context)
            if (payload := cursor._json_payload(path))
        ]
    if not home.is_absolute() or (workspace is not None and not workspace.is_absolute()):
        request["cwd"] = os.getcwd()
    if harness == "devin":
        request["config_dir"] = str(devin.DevinHarnessAdapter._devin_config_dir(context))
    return request


def run_case(harness: str, spec: dict, guard_home: Path) -> dict:
    root = Path(tempfile.mkdtemp(prefix="adapter-vec-")).resolve()
    previous_cwd = os.getcwd()
    previous_env = {name: os.environ.get(name) for name in spec.get("env", {})}
    try:
        materialize(root, spec)
        for name, value in spec.get("env", {}).items():
            os.environ[name] = value.replace("<ROOT>", str(root))
        grok.SYSTEM_MANAGED_CONFIG, grok.SYSTEM_REQUIREMENTS = system_policy_paths(root)
        base = Path() if spec["relative"] else root
        if spec["relative"]:
            os.chdir(root)
        context = HarnessContext(
            home_dir=base / spec["home"],
            workspace_dir=None if spec["workspace"] is None else base / spec["workspace"],
            guard_home=guard_home,
        )
        snapshot = bool(spec.get("snapshot"))
        args = facade_args(harness, context, root, snapshot)
        try:
            detection = detect(harness, context, snapshot)
            outcome: dict = {
                "artifacts": [artifact_dict(item) for item in detection.artifacts],
                "found_paths": list(detection.config_paths),
                "warnings": list(detection.warnings),
            }
            # A lone surrogate CPython would carry cannot cross the UTF-8
            # wire, so the resident refuses the inventory instead.
            json.dumps(outcome, ensure_ascii=False).encode("utf-8")
        except (ValueError, TypeError, RecursionError, OSError, RuntimeError):
            outcome = {"refused": True}
        record = {key: spec[key] for key in ("name", "files", "symlinks", "dirs", "dir_modes", "home", "workspace")}
        record["relative"] = spec["relative"]
        if snapshot:
            record["snapshot"] = True
        record["args"] = scrub(args, root)
        record.update(scrub(outcome, root))
        return record
    finally:
        os.chdir(previous_cwd)
        for name, value in previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        release(root)


def main() -> None:
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    harness, destination = sys.argv[1], Path(sys.argv[2])
    owner, helper = ORIGINALS[harness]
    if not hasattr(owner, helper):
        sys.exit(f"refusing to record: the original Python {harness} discovery is gone")
    if not os.environ.get("HOL_GUARD_NATIVE_BINARY"):
        sys.exit("set HOL_GUARD_NATIVE_BINARY to a release hol-guard-runtime")
    guard_home = Path(tempfile.mkdtemp(prefix="adapter-vec-guard-")).resolve() / "guard"
    provision_native(guard_home)
    try:
        recorded = [run_case(harness, spec, guard_home) for spec in cases(harness)]
    finally:
        close_native_residents(guard_home)
        shutil.rmtree(guard_home.parent, ignore_errors=True)
    document = {"schema": f"guard-{harness}-vectors.v1", "cases": recorded}
    destination.write_text(json.dumps(document, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"recorded {len(recorded)} cases")


if __name__ == "__main__":
    main()
