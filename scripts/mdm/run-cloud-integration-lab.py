#!/usr/bin/env python3
"""Build and run the stateful multi-device HOL Guard MDM Cloud Docker lab."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "scripts" / "mdm" / "cloud-lab" / "docker-compose.yml"
DEFAULT_ARTIFACTS = ROOT / "artifacts" / "mdm-cloud-lab"
REPORT_NAME = "mdm-cloud-integration-report.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="preserve containers and state after the run")
    parser.add_argument("--no-build", action="store_true", help="use an already-built lab image")
    parser.add_argument("--project", default="hol-guard-mdm-cloud-lab")
    parser.add_argument("--artifacts", type=Path, default=DEFAULT_ARTIFACTS)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    report = artifacts / REPORT_NAME
    report.unlink(missing_ok=True)
    env = dict(os.environ)
    env["HOL_MDM_LAB_PROJECT"] = args.project
    base = ["docker", "compose", "--project-name", args.project, "--file", str(COMPOSE_FILE)]
    up = [*base, "up", "--abort-on-container-exit", "--exit-code-from", "orchestrator"]
    if not args.no_build:
        up.append("--build")
    copy_report = [*base, "cp", f"orchestrator:/artifacts/{REPORT_NAME}", str(report)]
    down = [*base, "down", "--volumes", "--remove-orphans"]
    if args.dry_run:
        print(
            json.dumps(
                {"up": up, "copyReport": copy_report, "down": down, "artifacts": str(artifacts)},
                sort_keys=True,
            )
        )
        return 0

    status = 1
    try:
        status = subprocess.run(up, cwd=ROOT, env=env, check=False).returncode
        copy_status = subprocess.run(copy_report, cwd=ROOT, env=env, check=False).returncode
        if copy_status != 0 and status == 0:
            status = copy_status
        if not report.exists():
            print("MDM Cloud lab did not produce its bounded report artifact", file=sys.stderr)
            return status or 1
        try:
            payload = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"MDM Cloud lab report is invalid: {error}", file=sys.stderr)
            return 1
        if payload.get("healthy") is not True:
            status = 1
        print(json.dumps(payload, indent=2, sort_keys=True))
        return status
    except OSError as error:
        print(f"Docker Compose could not start: {error}", file=sys.stderr)
        return 127
    finally:
        if not args.keep:
            subprocess.run(down, cwd=ROOT, env=env, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
