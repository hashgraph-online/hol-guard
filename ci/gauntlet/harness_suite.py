"""Run the catalog through Claude Code, Codex or Cursor. Never merge-qualifying."""

from __future__ import annotations

import json
import platform
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ci.native_runtime import probe_installed_pi_output as probe

from .case_worker import SubprocessCaseWorker
from .catalog import Scenario, catalog_digest, load_catalog
from .fixtures import create_run_root, digest_file
from .harness_case import run_harness_case
from .harnesses import adapter
from .parallel import Lease, run_scheduled, terminate_as_exit, validate_jobs
from .source_identity import source_identity

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def run_harness_suite(
    *,
    harness: str,
    expected_source_sha: str,
    output: Path,
    model_timeout: float = 300,
    selected_ids: list[str] | None = None,
    executable: str | None = None,
    model: str | None = None,
    work_root: Path | None = None,
    candidate_sha: str | None = None,
    jobs: int = 1,
) -> dict[str, Any]:
    """Run each selected scenario through the harness and write ``summary.json``."""
    if re.fullmatch(r"[0-9a-f]{40}", expected_source_sha) is None:
        raise ValueError("expected source SHA must be a full Git commit")
    jobs = validate_jobs(jobs)
    spec = adapter(harness)
    resolved = spec.executable(executable)
    version = spec.version(resolved)
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    _, identity, capabilities = probe._probe_native_identity()
    if capabilities.build_sha != expected_source_sha:
        raise RuntimeError("installed Guard source SHA does not match the expected build")
    catalog = load_catalog()
    if selected_ids and (set(selected_ids) - {scenario.id for scenario in catalog}):
        raise ValueError("unknown scenario selection")
    selected = tuple(s for s in catalog if not selected_ids or s.id in selected_ids)
    parent = (work_root or output.parent).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    root = create_run_root(parent)
    binding = source_identity(REPO, candidate_sha)
    report: dict[str, Any] = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "schema": "hol.guard-gauntlet.harness-evidence.v1",
        "name": "Guard Gauntlet",
        **binding,
        "harness": harness,
        "harness_version": version,
        "harness_model": model or "harness default",
        "installed_source_sha": capabilities.build_sha,
        "native_binary_sha256": identity.sha256,
        "guard_version": capabilities.runtime_version,
        "platform": platform.system().lower(),
        "catalog_sha256": catalog_digest(),
        "expected_scenarios": [s.id for s in catalog],
        "full_profile": selected == catalog,
        "cases": [],
        "jobs": jobs,
        # Vendor inference bypasses the relay's round transcript and canary backstop.
        "merge_qualified": False,
    }
    completed: dict[str, dict[str, Any]] = {}

    def record(scenario: Scenario, case: dict[str, Any]) -> None:
        completed[scenario.id] = {"id": scenario.id, **case}
        ordered = [completed[s.id] for s in selected if s.id in completed]
        report["cases"] = [
            {
                "id": row["id"],
                **row["assessment"],
                "evidence_sha256": digest_file(output / "cases" / f"{row['id']}.json"),
            }
            for row in ordered
        ]
        print(json.dumps({"scenario": scenario.id, **case["assessment"]}), flush=True)
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")

    if jobs == 1:
        # SIGTERM/SIGHUP must unwind each case so its agent and daemon are reaped.
        with terminate_as_exit():
            for scenario in selected:
                record(
                    scenario,
                    run_harness_case(
                        scenario,
                        harness=harness,
                        root=root,
                        public=output / "cases",
                        executable=resolved,
                        identity=identity,
                        timeout=model_timeout,
                        model=model,
                    ),
                )
    else:
        workdir = root / "workers"
        workdir.mkdir(mode=0o700)

        def spawn(scenario: Scenario, lease: Lease | None = None) -> Any:
            return SubprocessCaseWorker(
                scenario.id,
                {
                    "scenario_id": scenario.id,
                    "harness": harness,
                    "harness_model": model,
                    "root": str(root),
                    "public": str(output / "cases"),
                    "executable": resolved,
                    "timeout": model_timeout,
                    "identity_sha256": identity.sha256,
                    "build_sha": capabilities.build_sha,
                },
                workdir,
                pass_fds=(lease.fd,) if lease is not None and lease.fd is not None else (),
            )

        (output / "cases").mkdir(parents=True, exist_ok=True)
        run_scheduled(
            selected,
            jobs=jobs,
            spawn=spawn,
            on_complete=lambda index, result: record(selected[index], result),
        )
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["outcomes"] = dict(Counter(c["outcome"] for c in report["cases"]))
    report["pass"] = report["full_profile"] and all(c["outcome"] == "pass" for c in report["cases"])
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
