"""Allow PR trust-map edits only for new, opt-in external contributions."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[2]
TRUST_PATH = "contracts/extensions/trust-class-map.v1.json"
SOURCE_PREFIXES = ("contributions/command-sources/", "contributions/mcp-servers/")


def _object(raw: bytes, label: str) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key in {label}: {key}")
            result[key] = value
        return result

    if len(raw) > 4 * 1024 * 1024:
        raise ValueError(f"Oversized trust/source input: {label}")
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError(f"Expected an object in {label}")
    return cast(dict[str, object], value)


def _classes(payload: dict[str, object]) -> dict[str, set[str]]:
    classes = payload.get("classes")
    if payload.get("schemaVersion") != "guard.extension-trust-class-map.v1" or not isinstance(classes, dict):
        raise ValueError("Invalid trust-map contract")
    if set(classes) != {"external", "first-party", "trusted-library"}:
        raise ValueError("Invalid trust classes")
    result: dict[str, set[str]] = {}
    seen: set[str] = set()
    for kind, entries in classes.items():
        if not isinstance(entries, list) or any(not isinstance(item, str) or not item for item in entries):
            raise ValueError("Trust class entries must be nonempty strings")
        ids = set(cast(list[str], entries))
        if len(ids) != len(entries) or seen.intersection(ids):
            raise ValueError("Duplicate or overlapping trust identities")
        result[kind] = ids
        seen.update(ids)
    return result


def verify_external_additions(
    base: dict[str, object], head: dict[str, object], new_contribution_ids: set[str]
) -> list[str]:
    before, after = _classes(base), _classes(head)

    def without_external(payload: dict[str, object]) -> dict[str, object]:
        classes = cast(dict[str, object], payload["classes"])
        return {**payload, "classes": {key: value for key, value in classes.items() if key != "external"}}

    if without_external(base) != without_external(head):
        raise ValueError("Non-external trust classes and publisher metadata are maintainer-owned")
    if not before["external"] <= after["external"]:
        raise ValueError("Existing external identities cannot be removed or reclassified")
    added = after["external"] - before["external"]
    existing = {identity for identities in before.values() for identity in identities}
    if added != new_contribution_ids - existing:
        raise ValueError("Only newly added canonical contribution IDs may be added to external")
    return sorted(added)


def _git(*arguments: str) -> bytes:
    return subprocess.check_output(["git", *arguments], cwd=ROOT, stderr=subprocess.PIPE, timeout=60)


def _new_contribution_ids(base_sha: str) -> set[str]:
    paths = _git("diff", "--name-only", "--diff-filter=A", base_sha, "--", *SOURCE_PREFIXES).decode().splitlines()
    ids: set[str] = set()
    for name in paths:
        path = ROOT / name
        if path.suffix != ".json" or path.name == "migration-manifest.json":
            continue
        if path.is_symlink():
            raise ValueError("Canonical contribution sources cannot be symlinks")
        payload = _object(path.read_bytes(), name)
        if name.startswith(SOURCE_PREFIXES[0]):
            directory = SOURCE_PREFIXES[0]
            extension = payload.get("extension")
            identity = extension.get("extension_id") if isinstance(extension, dict) else None
            prefix = "command."
        else:
            directory = SOURCE_PREFIXES[1]
            identity = payload.get("id")
            prefix = "mcp."
        if path.parent != ROOT / directory:
            raise ValueError(f"Canonical contribution source must be directly under {directory}")
        if not isinstance(identity, str) or not identity.startswith(prefix) or path.stem != identity:
            raise ValueError(f"Canonical source filename/identity mismatch: {name}")
        ids.add("command.mcp-" + identity.removeprefix("mcp.") if prefix == "mcp." else identity)
    return ids


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--changed-from", required=True, help="Full PR base commit SHA.")
    args = parser.parse_args()
    try:
        base_sha = args.changed_from
        if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", base_sha) is None:
            raise ValueError("Expected a full base commit SHA")
        try:
            _git("cat-file", "-e", f"{base_sha}^{{commit}}")
        except subprocess.CalledProcessError:
            _ = _git("fetch", "--no-tags", "--depth=1", "origin", base_sha)
        base = _object(_git("show", f"{base_sha}:{TRUST_PATH}"), "base trust map")
        path = ROOT / TRUST_PATH
        if path.is_symlink():
            raise ValueError("Trust map cannot be a symlink")
        head = _object(path.read_bytes(), "head trust map")
        added = verify_external_additions(base, head, _new_contribution_ids(base_sha))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Contribution trust-map check failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "added_external_ids": added}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
