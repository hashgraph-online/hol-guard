#!/usr/bin/env python3
"""Build and run the portable MDM contract lab without network access."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Final

_REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[2]
_DOCKERFILE: Final = _REPOSITORY_ROOT / "scripts" / "mdm" / "Dockerfile.local-lab"
_DEFAULT_IMAGE: Final = "hol-guard-mdm-local-lab:local"
_COMMAND_TIMEOUT_SECONDS: Final = 300


def _docker_build_command(image: str) -> list[str]:
    return ["docker", "build", "--tag", image, "--file", str(_DOCKERFILE), str(_REPOSITORY_ROOT)]


def _docker_run_command(image: str) -> list[str]:
    source_mount = f"type=bind,src={_REPOSITORY_ROOT},dst=/hol-guard-source,readonly"
    return [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--mount",
        source_mount,
        image,
        "--json",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=_DEFAULT_IMAGE, help="container image tag for the local lab")
    parser.add_argument("--skip-build", action="store_true", help="run an already-built local lab image")
    parser.add_argument("--dry-run", action="store_true", help="print the Docker commands without executing them")
    args = parser.parse_args()

    build_command = _docker_build_command(args.image)
    run_command = _docker_run_command(args.image)
    if args.dry_run:
        print(json.dumps({"build": build_command, "run": run_command}, sort_keys=True))
        return 0

    try:
        if not args.skip_build:
            subprocess.run(build_command, check=True, timeout=_COMMAND_TIMEOUT_SECONDS)
        return subprocess.run(run_command, check=False, timeout=_COMMAND_TIMEOUT_SECONDS).returncode
    except subprocess.TimeoutExpired as error:
        print(
            f"local MDM container command timed out after {_COMMAND_TIMEOUT_SECONDS} seconds: {error.cmd}",
            file=sys.stderr,
        )
        return 124
    except subprocess.CalledProcessError as error:
        print(f"local MDM container command failed with exit code {error.returncode}: {error.cmd}", file=sys.stderr)
        return error.returncode
    except OSError as error:
        print(f"local MDM container command could not start: {error}", file=sys.stderr)
        return 127


if __name__ == "__main__":
    raise SystemExit(main())
