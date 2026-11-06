#!/usr/bin/env python3
"""Write artifact checksums and provenance without reading signing secrets."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    artifact_hash = _sha256(args.artifact)
    args.artifact.with_suffix(args.artifact.suffix + ".sha256").write_text(
        f"{artifact_hash}  {args.artifact.name}\n", encoding="utf-8"
    )
    payload = {
        "schemaVersion": "hol-guard-release-evidence.v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "artifact": {"name": args.artifact.name, "sha256": artifact_hash},
        "releaseManifestSha256": _sha256(args.manifest),
        "sbomSha256": _sha256(args.sbom),
    }
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
