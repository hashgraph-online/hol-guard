#!/usr/bin/env python3
"""Write deterministic PyInstaller Windows version metadata."""

from __future__ import annotations

import argparse
from pathlib import Path

from packaging.version import InvalidVersion, Version


def _numeric_version(version: Version) -> tuple[int, int, int, int]:
    prerelease = version.pre[1] if version.pre is not None else 0
    values = (version.major, version.minor, version.micro, prerelease)
    if any(value < 0 or value > 65_535 for value in values):
        raise ValueError("version components must fit Windows version resources")
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        version = Version(args.version)
        numeric = _numeric_version(version)
    except (InvalidVersion, ValueError) as exc:
        parser.error(str(exc))
    dotted = ", ".join(str(value) for value in numeric)
    payload = f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers=({dotted}), prodvers=({dotted}), mask=0x3f, flags=0x0,
    OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'Hashgraph Online'),
      StringStruct('FileDescription', 'HOL Guard'),
      StringStruct('FileVersion', '{version}'),
      StringStruct('InternalName', 'hol-guard'),
      StringStruct('OriginalFilename', 'hol-guard.exe'),
      StringStruct('ProductName', 'HOL Guard'),
      StringStruct('ProductVersion', '{version}')
    ])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
