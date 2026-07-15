#!/usr/bin/env python3
"""Generate a deterministic CycloneDX dependency inventory for frozen runtimes."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    components = []
    for distribution in sorted(importlib.metadata.distributions(), key=lambda item: item.metadata["Name"].lower()):
        name = distribution.metadata["Name"]
        if not name:
            continue
        components.append(
            {
                "type": "library",
                "name": name,
                "version": distribution.version,
                "purl": f"pkg:pypi/{name.lower().replace('_', '-')}@{distribution.version}",
            }
        )
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "HOL Guard", "version": args.version}},
        "components": components,
    }
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
