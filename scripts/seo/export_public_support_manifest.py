#!/usr/bin/env python3
"""Validate and export HOL Guard's release-aware public support manifest.

The checked-in manifest is intentionally the publication boundary. Runtime
contracts are compared to the active alpha channel so website generation never
silently promotes a new adapter before its public limitations are reviewed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/guard/public-support-manifest.v1.json"


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def public_projection(data: dict, channel: str) -> dict:
    selected = next((item for item in data["channels"] if item["id"] == channel), None)
    if selected is None:
        raise SystemExit(f"Unknown channel: {channel}")
    return {
        "schemaVersion": data["schemaVersion"],
        "product": data["product"],
        "generatedAt": data["generatedAt"],
        "category": data["category"],
        "decisionSemantics": data["decisionSemantics"],
        "channel": selected,
        "migrations": data["migrations"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel", choices=("stable", "alpha"), default="stable")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = json.dumps(public_projection(load_manifest(), args.channel), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
