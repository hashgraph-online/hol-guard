#!/usr/bin/env python3
"""Build and run the stateful multi-device HOL Guard MDM Cloud Docker lab."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import uuid
from collections.abc import Sequence
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "scripts" / "mdm" / "cloud-lab" / "docker-compose.yml"
REPORT_SCHEMA = ROOT / "docs" / "guard" / "schemas" / "mdm-cloud-lab-report-v1.schema.json"
DEFAULT_ARTIFACTS = ROOT / "artifacts" / "mdm-cloud-lab"
SERVICES = ("cloud", "proxy", "device-a", "device-b", "device-c", "device-d")


def _run(
    command: list[str],
    *,
    env: dict[str, str],
    capture: bool = False,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        check=check,
        text=True,
        capture_output=capture,
    )


def _export_volume_file(
    base: list[str],
    source: str,
    destination: Path,
    *,
    env: dict[str, str],
) -> bool:
    result = _run(
        [
            *base,
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "/bin/cat",
            "orchestrator",
            source,
        ],
        env=env,
        capture=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return False
    destination.write_text(result.stdout, encoding="utf-8")
    return True


def _validate_report(report_path: Path) -> dict[str, object]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    schema = json.loads(REPORT_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(report)
    if report.get("healthy") is not True:
        raise RuntimeError("MDM Cloud lab report is unhealthy")
    steps = report.get("steps")
    if not isinstance(steps, list) or len(steps) < 50:
        raise RuntimeError("MDM Cloud lab report did not cover the full matrix")
    if any(not isinstance(step, dict) or step.get("passed") is not True for step in steps):
        raise RuntimeError("MDM Cloud lab report contains a failed assertion")
    native = report.get("nativeCertification")
    if not isinstance(native, dict) or native.get("outcome") != "not-evaluated":
        raise RuntimeError("MDM Cloud lab overstated native certification")
    return report


def _parse_args(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep",
        action="store_true",
        help="preserve containers and state after the run",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="use an already-built lab image",
    )
    parser.add_argument(
        "--project",
        default=f"hol-guard-mdm-cloud-lab-{uuid.uuid4().hex[:8]}",
    )
    parser.add_argument(
        "--artifacts",
        type=Path,
        default=DEFAULT_ARTIFACTS,
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def _lab_environment(
    args: argparse.Namespace,
) -> tuple[Path, dict[str, str]]:
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    uid = str(getattr(os, "getuid", lambda: 10001)())
    gid = str(getattr(os, "getgid", lambda: 10001)())
    env.setdefault("HOL_MDM_LAB_ADMIN_TOKEN", secrets.token_urlsafe(48))
    env.setdefault("HOL_MDM_LAB_UID", uid)
    env.setdefault("HOL_MDM_LAB_GID", gid)
    env.update(
        {
            "HOL_MDM_LAB_PROJECT": args.project,
            "COMPOSE_PROGRESS": env.get("COMPOSE_PROGRESS", "plain"),
        }
    )
    return artifacts, env


def _compose_commands(
    args: argparse.Namespace,
) -> dict[str, list[str]]:
    base = [
        "docker",
        "compose",
        "--project-name",
        args.project,
        "--file",
        str(COMPOSE_FILE),
    ]
    up = [*base, "up", "-d"]
    if not args.no_build:
        up.append("--build")
    up.extend(["--wait", "--wait-timeout", "180", *SERVICES])
    initial = [
        *base,
        "run",
        "--rm",
        "--no-deps",
        "orchestrator",
        "scripts/mdm/cloud-lab/orchestrator.py",
        "--json",
        "--phase",
        "initial",
        "--output",
        "/artifacts/mdm-cloud-integration-initial.json",
    ]
    resume = [
        *base,
        "run",
        "--rm",
        "--no-deps",
        "orchestrator",
        "scripts/mdm/cloud-lab/orchestrator.py",
        "--json",
        "--phase",
        "restart",
        "--input-report",
        "/artifacts/mdm-cloud-integration-initial.json",
        "--output",
        "/artifacts/mdm-cloud-integration-report.json",
    ]
    return {
        "base": base,
        "up": up,
        "initial": initial,
        "restart": [*base, "restart", *SERVICES],
        "waitAfterRestart": [
            *base,
            "up",
            "-d",
            "--wait",
            "--wait-timeout",
            "180",
            *SERVICES,
        ],
        "resume": resume,
        "down": [*base, "down", "--volumes", "--remove-orphans"],
    }


def _print_dry_run(
    commands: dict[str, list[str]],
    artifacts: Path,
) -> None:
    payload = {key: command for key, command in commands.items() if key != "base"}
    payload["artifacts"] = str(artifacts)
    print(json.dumps(payload, sort_keys=True))


def _run_initial_phase(
    commands: dict[str, list[str]],
    env: dict[str, str],
    initial_path: Path,
) -> int:
    if _run(commands["up"], env=env).returncode != 0:
        return 1
    result = _run(commands["initial"], env=env)
    exported = _export_volume_file(
        commands["base"],
        "/artifacts/mdm-cloud-integration-initial.json",
        initial_path,
        env=env,
    )
    if result.returncode != 0:
        return result.returncode
    if not exported:
        print(
            "MDM Cloud lab did not produce its initial checkpoint artifact",
            file=sys.stderr,
        )
        return 1
    return 0


def _run_restart_phase(
    commands: dict[str, list[str]],
    env: dict[str, str],
    report_path: Path,
) -> int:
    if _run(commands["restart"], env=env).returncode != 0:
        return 1
    if _run(commands["waitAfterRestart"], env=env).returncode != 0:
        return 1
    result = _run(commands["resume"], env=env)
    exported = _export_volume_file(
        commands["base"],
        "/artifacts/mdm-cloud-integration-report.json",
        report_path,
        env=env,
    )
    if not exported:
        print(
            "MDM Cloud lab did not produce its bounded report artifact",
            file=sys.stderr,
        )
        return result.returncode or 1
    return result.returncode


def _finalize_report(
    report_path: Path,
    artifacts: Path,
) -> None:
    report = _validate_report(report_path)
    digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
    checksum_path = artifacts / "mdm-cloud-integration-report.json.sha256"
    checksum_path.write_text(
        f"{digest}  {report_path.name}\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, sort_keys=True))


def _collect_diagnostics(
    commands: dict[str, list[str]],
    env: dict[str, str],
    artifacts: Path,
) -> Path:
    logs_path = artifacts / "compose.log"
    logs = _run(
        [*commands["base"], "logs", "--no-color", "--tail", "1000"],
        env=env,
        capture=True,
    )
    logs_path.write_text(
        (logs.stdout or "") + (logs.stderr or ""),
        encoding="utf-8",
    )
    ps = _run(
        [*commands["base"], "ps", "--all", "--format", "json"],
        env=env,
        capture=True,
    )
    (artifacts / "compose-ps.json").write_text(
        ps.stdout or "[]\n",
        encoding="utf-8",
    )
    return logs_path


def _execute_lab(
    args: argparse.Namespace,
    artifacts: Path,
    env: dict[str, str],
    commands: dict[str, list[str]],
) -> int:
    report_path = artifacts / "mdm-cloud-integration-report.json"
    initial_path = artifacts / "mdm-cloud-integration-initial.json"
    status = 1
    try:
        status = _run_initial_phase(commands, env, initial_path)
        if status != 0:
            return status
        status = _run_restart_phase(commands, env, report_path)
        if status != 0:
            return status
        _finalize_report(report_path, artifacts)
        status = 0
        return 0
    except (OSError, json.JSONDecodeError, RuntimeError) as error:
        print(f"MDM Cloud lab failed: {error}", file=sys.stderr)
        return 1
    finally:
        logs_path = _collect_diagnostics(commands, env, artifacts)
        if not args.keep:
            _run(commands["down"], env=env)
        if status != 0:
            print(f"MDM Cloud lab logs: {logs_path}", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    artifacts, env = _lab_environment(args)
    commands = _compose_commands(args)
    if args.dry_run:
        _print_dry_run(commands, artifacts)
        return 0
    return _execute_lab(args, artifacts, env, commands)


if __name__ == "__main__":
    raise SystemExit(main())
