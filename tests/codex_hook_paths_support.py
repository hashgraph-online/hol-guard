"""Where a Guard home keeps the Codex hook identity files, for tests that seed or inspect them.

The runtime names these paths (``codex-hook-paths``); production Python asks
it. Tests reach the same files without a runtime round trip, and
``test_codex_hook_paths_native`` holds this derivation to the runtime's
answer.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path


def hook_manifest_path(guard_home: Path, config_path: Path) -> Path:
    target_hash = hashlib.sha256(str(config_path.expanduser().resolve(strict=False)).encode("utf-8")).hexdigest()[:24]
    return guard_home / "managed" / "codex" / f"hooks-{target_hash}.manifest.json"


def hook_secret_path(guard_home: Path) -> Path:
    return guard_home / "managed" / "codex" / "hook-manifest.key"


def hook_authority_receipt_path(guard_home: Path, config_path: Path) -> Path:
    manifest = hook_manifest_path(guard_home, config_path)
    return manifest.with_name(manifest.name.replace(".manifest.json", ".authority-receipt.json"))


def canonical_manifest_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
