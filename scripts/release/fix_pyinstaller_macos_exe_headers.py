#!/usr/bin/env python3
"""Expand onefile Mach-O LINKEDIT so codesign can cover a rewritten CArchive."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_file():
        raise SystemExit(f"Binary does not exist: {args.binary}")
    try:
        from PyInstaller.utils.osx import fix_exe_for_code_signing
    except ImportError as error:
        raise SystemExit("PyInstaller is required to repair onefile Mach-O headers") from error
    try:
        fix_exe_for_code_signing(str(args.binary.resolve()))
    except (AssertionError, OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    print(f"repaired onefile Mach-O headers for {args.binary.name}")


if __name__ == "__main__":
    main()
