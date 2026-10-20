"""Run approval-retry and Bash-consent lifecycle cases through a real harness CLI.

The core catalog cannot host these cases. Every core scenario joins the ``core`` profile and
so runs on every lane, including the omp runner and the installed acceptance lane, which
would each need the new oracles; adding them also moves ``catalog_sha256`` and
``expected_scenarios`` in every lane's evidence. Beyond that, each existing judge fails an
allow-expectation case that is stopped or that creates an approval row, and ``is_benign``
counts this lane's deliberate review as a benign interruption. The lane therefore carries its
own catalog file, which ``load_catalog`` already accepts, and its own pass rules.

This lane is never merge-qualifying.
"""

from __future__ import annotations

import json
import platform
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ci.native_runtime import probe_installed_pi_output as probe

from .approval_retry import CATALOG as APPROVAL_RETRY_CATALOG
from .approval_rows import connector_classes
from .catalog import catalog_digest, load_catalog
from .fixtures import create_run_root, digest_file
from .harness_case import run_harness_case
from .harnesses import adapter
from .interruptions import report_sections
from .parallel import terminate_as_exit
from .source_identity import source_identity

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def run_approval_retry_suite(
    *,
    catalog_path: Path | None = None,
    harness: str,
    expected_source_sha: str,
    output: Path,
    model_timeout: float = 300,
    selected_ids: list[str] | None = None,
    executable: str | None = None,
    model: str | None = None,
    work_root: Path | None = None,
    candidate_sha: str | None = None,
) -> dict[str, Any]:
    """Run each scenario of an additive harness-only catalog and write ``summary.json``.

    The approve-then-retry catalog is the default; the connector-setup catalog shares
    this lane because it has the same constraints and its own oracles.
    """
    catalog_path = catalog_path or APPROVAL_RETRY_CATALOG
    if re.fullmatch(r"[0-9a-f]{40}", expected_source_sha) is None:
        raise ValueError("expected source SHA must be a full Git commit")
    spec = adapter(harness)
    resolved = spec.executable(executable)
    version = spec.version(resolved)
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    _, identity, capabilities = probe._probe_native_identity()
    if capabilities.build_sha != expected_source_sha:
        raise RuntimeError("installed Guard source SHA does not match the expected build")
    catalog = load_catalog(catalog_path)
    if selected_ids and (set(selected_ids) - {scenario.id for scenario in catalog}):
        raise ValueError("unknown scenario selection")
    selected = tuple(s for s in catalog if not selected_ids or s.id in selected_ids)
    parent = (work_root or output.parent).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    root = create_run_root(parent)
    report: dict[str, Any] = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "schema": "hol.guard-gauntlet.harness-evidence.v1",
        "name": "Guard Gauntlet "
        + ("approve-then-retry" if catalog_path == APPROVAL_RETRY_CATALOG else catalog_path.stem),
        **source_identity(REPO, candidate_sha),
        "harness": harness,
        "harness_version": version,
        "harness_model": spec.model(model) or "harness default",
        "installed_source_sha": capabilities.build_sha,
        "native_binary_sha256": identity.sha256,
        "guard_version": capabilities.runtime_version,
        "platform": platform.system().lower(),
        "catalog_sha256": catalog_digest(catalog_path),
        "expected_scenarios": [s.id for s in catalog],
        "full_profile": selected == catalog,
        "cases": [],
        "jobs": 1,
        "merge_qualified": False,
    }
    completed: dict[str, dict[str, Any]] = {}

    def record(scenario_id: str, case: dict[str, Any]) -> None:
        completed[scenario_id] = {"id": scenario_id, **case}
        report["cases"] = [
            {
                "id": row["id"],
                **row["assessment"],
                "approval_grants": len((row.get("approval_grants") or {}).get("granted") or []),
                "connector_classes": connector_classes(row.get("approval_rows")),
                "evidence_sha256": digest_file(output / "cases" / f"{row['id']}.json"),
            }
            for row in (completed[s.id] for s in selected if s.id in completed)
        ]
        print(json.dumps({"scenario": scenario_id, **case["assessment"]}), flush=True)
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")

    # SIGTERM/SIGHUP must unwind each case so its agent and daemon are reaped.
    with terminate_as_exit():
        for scenario in selected:
            record(
                scenario.id,
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
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["outcomes"] = dict(Counter(c["outcome"] for c in report["cases"]))
    # Reported for visibility only: the lane reviews ordinary commands deliberately, so a
    # benign interruption here is the scenario working, not a defect.
    report.update(report_sections(report["cases"], harness))
    report["pass"] = report["full_profile"] and all(c["outcome"] == "pass" for c in report["cases"])
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
