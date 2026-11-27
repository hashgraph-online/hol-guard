"""Refresh or check the pinned public-suffix snapshot used for `site-group` grants.

The snapshot lives in `rust/crates/guard-command-catalog-data/public-suffix/`. The catalog-data
build refuses a list whose SHA-256 differs from `snapshot.v1.json`, so a refresh always rewrites
both files together. `--check` verifies the pin offline; it is what reviewers run on a refresh.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_DIR = ROOT / "rust/crates/guard-command-catalog-data/public-suffix"
MANIFEST = SNAPSHOT_DIR / "snapshot.v1.json"
LIST_NAME = "public_suffix_list.dat"
SOURCE = "https://publicsuffix.org/list/public_suffix_list.dat"
MAX_BYTES = 4 * 1024 * 1024
LICENSE_LINE = "// This Source Code Form is subject to the terms of the Mozilla Public"
VERSION_RE = re.compile(r"^// VERSION: (\S+)$", re.MULTILINE)
COMMIT_RE = re.compile(r"^// COMMIT: ([0-9a-f]{40})$", re.MULTILINE)


def manifest_for(data: bytes) -> dict[str, str]:
    """Validate a downloaded list and describe it; raise ValueError when it is not the list."""
    if len(data) > MAX_BYTES:
        raise ValueError("public-suffix list is larger than the bound")
    text = data.decode("utf-8")
    if not text.startswith(LICENSE_LINE):
        raise ValueError("public-suffix list is missing its license header")
    if "// ===BEGIN ICANN DOMAINS===" not in text or "// ===END PRIVATE DOMAINS===" not in text:
        raise ValueError("public-suffix list is missing a section marker")
    version = VERSION_RE.search(text)
    commit = COMMIT_RE.search(text)
    if version is None or commit is None:
        raise ValueError("public-suffix list is missing its version or commit line")
    return {
        "schema": "guard.public-suffix-snapshot.v1",
        "source": SOURCE,
        "license": "MPL-2.0",
        "version": version.group(1),
        "commit": commit.group(1),
        "file": LIST_NAME,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def check() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    data = (SNAPSHOT_DIR / LIST_NAME).read_bytes()
    expected = manifest_for(data)
    if manifest != expected:
        print("public-suffix snapshot pin does not match the list", file=sys.stderr)
        return 1
    print(f"public-suffix snapshot {expected['version']} pinned at {expected['sha256']}")
    return 0


def refresh() -> int:
    request = urllib.request.Request(SOURCE, headers={"User-Agent": "hol-guard-psl-refresh"})
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed HTTPS source
        data = response.read(MAX_BYTES + 1)
    manifest = manifest_for(data)
    (SNAPSHOT_DIR / LIST_NAME).write_bytes(data)
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"public-suffix snapshot refreshed to {manifest['version']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify the pin without network access")
    arguments = parser.parse_args(argv)
    return check() if arguments.check else refresh()


if __name__ == "__main__":
    raise SystemExit(main())
