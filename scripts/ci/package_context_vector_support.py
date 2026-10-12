"""Shared pieces of the package-execution-context build parity vectors.

The recorder (``package_context_vector_recorder.py``) runs scenarios against the
Python implementation that preceded the resident ``package_context_build`` op,
and the Rust replay test
(``rust/crates/guard-command/tests/package_context_vectors.rs``) replays the same
scenarios against ``guard_command::package_context_build``. Both sides agree on:

* the step format (``write``/``mkdir``/``symlink``), with ``{root}`` standing in
  for the per-run scratch directory,
* the normalisation below, which replaces the scratch directory in every string
  the implementation hashes or hands to a native hook, so recorded digests do
  not depend on where a replay ran, and
* the hook log: every native digest, environment-policy and launch-identity
  call the build made, in order, with its normalised arguments and result.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT_TOKEN = "{root}"
MANAGERS = (
    "bun",
    "bunx",
    "bundle",
    "bundler",
    "cargo",
    "composer",
    "gem",
    "go",
    "gradle",
    "gradlew",
    "mvn",
    "mvnw",
    "npm",
    "npx",
    "pip",
    "pip3",
    "pipenv",
    "pipx",
    "pnpm",
    "poetry",
    "uv",
    "uvx",
    "yarn",
)


def substitute(value: object, root: str, token: str = ROOT_TOKEN) -> Any:
    """Replace every occurrence of ``root`` in strings (and keys) of a JSON value."""

    if isinstance(value, str):
        return value.replace(root, token)
    if isinstance(value, list | tuple):
        return [substitute(item, root, token) for item in value]
    if isinstance(value, dict):
        return {str(substitute(key, root, token)): substitute(item, root, token) for key, item in value.items()}
    return value


def expand(value: object, root: str) -> Any:
    return substitute(value, ROOT_TOKEN, root)


def canonical_digest(value: object) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def apply_step(root: str, step: dict[str, Any]) -> None:
    path = Path(root) / str(step["path"])
    op = step["op"]
    if op == "write":
        path.parent.mkdir(parents=True, exist_ok=True)
        if "size" in step:
            with path.open("wb") as handle:
                handle.truncate(int(step["size"]))
        elif "repeat" in step:
            path.write_bytes(str(step["repeat"]).encode("utf-8") * int(step["count"]))
        elif "hex" in step:
            path.write_bytes(bytes.fromhex(str(step["hex"])))
        else:
            path.write_bytes(expand(str(step["text"]), root).encode("utf-8"))
        path.chmod(0o755 if step.get("exec") else 0o644)
    elif op == "mkdir":
        path.mkdir(parents=True, exist_ok=True)
    elif op == "symlink":
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(expand(step["target"], root), path)
    else:
        raise ValueError(f"unknown step {op}")


def materialize(root: str, steps: list[dict[str, Any]]) -> None:
    for step in steps:
        apply_step(root, step)


def identity_stub(root: str, mode: str):
    """A deterministic stand-in for the native runtime launch identity.

    It reads the same inputs the native op does and is a pure function of them,
    so the replay can return the recorded value and the vectors stay independent
    of the native binary.
    """

    def resolve(command: str, search_path: str | None, cwd: Path | None) -> Path | None:
        if "/" in command or "\\" in command:
            raw = Path(command).expanduser()
            candidate = raw if raw.is_absolute() else (cwd or Path.cwd()) / raw
            try:
                return candidate.resolve(strict=True)
            except OSError:
                return None
        found = shutil.which(command, path=search_path)
        return Path(found).resolve() if found else None

    def build(
        command: object,
        *,
        args: object = (),
        structured_command: bool = False,
        direct_executable: bool = False,
        search_path: str | None = None,
        cwd: Path | None = None,
        home_dir: Path | None = None,
        launch_env: Mapping[str, str] | None = None,
    ) -> dict[str, object]:
        target = resolve(str(command), search_path, cwd)
        digest = hashlib.sha256(target.read_bytes()).hexdigest() if target is not None and target.is_file() else None
        status = "verified" if digest is not None else "unresolved"
        if mode == "unverified":
            status = "unresolved"
        if mode == "mismatch" and digest is not None:
            digest = "0" * 64
        identity: dict[str, object] = {
            "args_sha256": canonical_digest(list(args)),  # type: ignore[call-overload]
            "command": str(command),
            "entrypoints": [
                {"path": str(Path(cwd) / "script.js") if cwd is not None else "script.js", "sha256": "1" * 64},
                {"path": "relative/entry.js", "sha256": "2" * 64},
                "not-a-mapping",
            ],
            "executable": {"path": str(target) if target is not None else None, "sha256": digest, "status": status},
            "launch_cwd": str(cwd) if cwd is not None else None,
            "structured": structured_command,
        }
        if mode == "no_executable":
            del identity["executable"]
        if mode == "nonce":
            identity["reuse_nonce"] = "fixed-nonce"
        return identity

    return build


def reusable_stub(identity: object) -> bool:
    def has_nonce(value: object) -> bool:
        if isinstance(value, dict):
            return "reuse_nonce" in value or any(has_nonce(item) for item in value.values())
        if isinstance(value, list):
            return any(has_nonce(item) for item in value)
        return False

    return not has_nonce(identity)
