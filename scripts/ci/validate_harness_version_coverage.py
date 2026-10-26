"""Validate the bundled harness version coverage manifest.

Default: the source manifest must parse under the runtime validator.
``--release``: every record must name the Guard version being released, so a
release never ships evidence that was bound to another build.
``--wheel PATH``: the built wheel must carry the same manifest bytes.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from codex_plugin_scanner.guard.harness_versions.manifest import (  # noqa: E402
    MANIFEST_FILENAME,
    ManifestError,
    bundled_manifest_path,
    parse_manifest,
)
from codex_plugin_scanner.version import __version__  # noqa: E402

WHEEL_MEMBER = f"codex_plugin_scanner/guard/schemas/{MANIFEST_FILENAME}"


def _validate(raw: bytes, *, release: bool) -> list[str]:
    try:
        manifest = parse_manifest(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, ManifestError) as error:
        return [f"manifest is invalid: {error}"]
    problems: list[str] = []
    if release:
        for harness, coverage in manifest.harnesses.items():
            for record in coverage.records:
                if record.guard_version != __version__:
                    problems.append(
                        f"{harness} {record.harness_version.canonical} is bound to Guard {record.guard_version}, "
                        f"not {__version__}; re-promote or remove it"
                    )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true", help="require records bound to this Guard version")
    parser.add_argument("--wheel", type=Path, help="also check the manifest inside a built wheel")
    args = parser.parse_args(argv)

    source = bundled_manifest_path().read_bytes()
    problems = _validate(source, release=args.release)
    if args.wheel is not None:
        with zipfile.ZipFile(args.wheel) as wheel:
            try:
                packaged = wheel.read(WHEEL_MEMBER)
            except KeyError:
                problems.append(f"{args.wheel.name} does not include {WHEEL_MEMBER}")
            else:
                if packaged != source:
                    problems.append(f"{args.wheel.name} carries a different coverage manifest")
    for problem in problems:
        print(f"harness version coverage: {problem}", file=sys.stderr)
    if not problems:
        print("harness version coverage manifest is valid")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
