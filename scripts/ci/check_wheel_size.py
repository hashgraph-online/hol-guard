#!/usr/bin/env python3
"""Report and enforce release-wheel download and installed-payload budgets."""

from __future__ import annotations

import argparse
import json
import os
import zipfile
from pathlib import Path

MIB = 1024 * 1024
NATIVE = "codex_plugin_scanner/_native/"
BUDGETS = Path(__file__).resolve().parents[2] / "ci/package_size/budgets.json"


def inspect_wheel(path: Path, budgets: dict[str, dict[str, int]]) -> tuple[str, list[str]]:
    """Use ZIP metadata only; do not extract or execute wheel contents."""
    platform = path.stem.rsplit("-", 1)[-1]
    if platform not in budgets:
        raise ValueError(f"No package-size budget for platform {platform}")
    budget = budgets[platform]
    failures = []
    with zipfile.ZipFile(path) as archive:
        files = [entry for entry in archive.infolist() if not entry.is_dir()]
    sizes = {
        "download": path.stat().st_size,
        "unpacked": sum(entry.file_size for entry in files),
        "runtime": sum(
            entry.file_size
            for entry in files
            if entry.filename
            in {
                NATIVE + "hol-guard-runtime",
                NATIVE + "hol-guard-runtime.exe",
            }
        ),
        "compiler": sum(
            entry.file_size
            for entry in files
            if entry.filename
            in {
                NATIVE + "guard-command-source",
                NATIVE + "guard-command-source.exe",
            }
        ),
    }
    lines = [f"### Package size: {path.name}", "", "| Payload | MiB | Budget MiB |", "| --- | ---: | ---: |"]
    for name, size in sizes.items():
        limit = budget[name]
        lines.append(f"| {name} | {size / MIB:.2f} | {limit / MIB:.2f} |")
        if size > limit:
            failures.append(f"{path.name}: {name} exceeds budget ({size} > {limit} bytes)")
    lines.extend(["", "Largest compressed members:", ""])
    for entry in sorted(files, key=lambda item: item.compress_size, reverse=True)[:10]:
        lines.append(
            f"- `{entry.filename}`: {entry.compress_size / MIB:.2f} MiB download, "
            f"{entry.file_size / MIB:.2f} MiB unpacked"
        )
    return "\n".join(lines) + "\n", failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, required=True)
    arguments = parser.parse_args()
    budgets = json.loads(BUDGETS.read_text(encoding="utf-8"))
    wheels = sorted(arguments.dist_dir.glob("*.whl"))
    if not wheels:
        parser.error("distribution directory contains no wheels")
    failed = False
    for wheel in wheels:
        report, failures = inspect_wheel(wheel, budgets)
        print(report)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with Path(summary).open("a", encoding="utf-8") as output:
                output.write(report + "\n")
        for failure in failures:
            print(failure)
        failed |= bool(failures)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
