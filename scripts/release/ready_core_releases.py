"""Filter release discovery to stable (or exact alpha) tags whose package and provenance are uploaded."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_TAG_PATTERNS = {
    "stable": re.compile(r"v((0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))"),
    "alpha": re.compile(r"alpha/v(3\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)a[1-9][0-9]*)"),
}


def ready_tags(inventory: Path, platform: str, channel: str = "stable") -> list[str]:
    tags = []
    for line in inventory.read_text().splitlines():
        item = json.loads(line)
        tag = item["tag"]
        match = _TAG_PATTERNS[channel].fullmatch(tag)
        if not match:
            continue
        version = match[1]
        assets = set(item["assets"])
        wheel = re.compile(rf"hol_guard-{re.escape(version)}-py3-none-{platform}\.whl")
        if f"hol-guard-v{version}.intoto.jsonl" in assets and sum(bool(wheel.fullmatch(name)) for name in assets) == 1:
            tags.append(tag)
    return tags


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--platform", choices=("macosx_.*_arm64", "manylinux_.*_x86_64"), required=True)
    parser.add_argument("--channel", choices=tuple(_TAG_PATTERNS), default="stable")
    args = parser.parse_args()
    for tag in ready_tags(args.inventory, args.platform, args.channel):
        print(tag)
