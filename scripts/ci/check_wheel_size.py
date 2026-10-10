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


def check_sizes(label: str, sizes: dict[str, int], budget: dict[str, int]) -> tuple[list[str], list[str]]:
    failures = []
    lines = [f"### Package size: {label}", "", "| Payload | MiB | Budget MiB |", "| --- | ---: | ---: |"]
    for name, size in sizes.items():
        limit = budget[name]
        lines.append(f"| {name} | {size / MIB:.2f} | {limit / MIB:.2f} |")
        if size > limit:
            failures.append(f"{label}: {name} exceeds budget ({size} > {limit} bytes)")
    return lines, failures


def inspect_native(directory: Path, platform: str, budgets: dict[str, dict[str, int]]) -> tuple[str, list[str]]:
    suffix = ".exe" if platform.startswith("win") else ""
    sizes = {
        "runtime": (directory / ("hol-guard-runtime" + suffix)).stat().st_size,
        "compiler": (directory / ("guard-command-source" + suffix)).stat().st_size,
    }
    lines, failures = check_sizes(platform + " native binaries", sizes, budgets[platform])
    return "\n".join(lines) + "\n", failures


def inspect_wheel(path: Path, budgets: dict[str, dict[str, int]]) -> tuple[str, list[str]]:
    """Use ZIP metadata only; do not extract or execute wheel contents."""
    platform = path.stem.rsplit("-", 1)[-1]
    if platform not in budgets:
        raise ValueError(f"No package-size budget for platform {platform}")
    budget = budgets[platform]
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
    lines, failures = check_sizes(path.name, sizes, budget)
    lines.extend(["", "Largest compressed members:", ""])
    for entry in sorted(files, key=lambda item: item.compress_size, reverse=True)[:10]:
        lines.append(
            f"- `{entry.filename}`: {entry.compress_size / MIB:.2f} MiB download, "
            f"{entry.file_size / MIB:.2f} MiB unpacked"
        )
    return "\n".join(lines) + "\n", failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--dist-dir", type=Path)
    inputs.add_argument("--native-dir", type=Path)
    parser.add_argument("--platform")
    arguments = parser.parse_args()
    budgets = json.loads(BUDGETS.read_text(encoding="utf-8"))
    if arguments.native_dir:
        if arguments.platform not in budgets:
            parser.error("native binary inspection requires a supported --platform")
        results = [inspect_native(arguments.native_dir, arguments.platform, budgets)]
    else:
        wheels = sorted(arguments.dist_dir.glob("*.whl"))
        if not wheels:
            parser.error("distribution directory contains no wheels")
        results = [inspect_wheel(wheel, budgets) for wheel in wheels]
    failed = False
    for report, failures in results:
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
