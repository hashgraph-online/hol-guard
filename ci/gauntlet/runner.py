"""Run real Oh My Pi sessions against an installed, source-bound Guard wheel."""

from __future__ import annotations

import contextlib
import json
import os
import platform
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ci.native_runtime import probe_installed_pi_output as probe

from .agent_configuration import write_agent_configuration
from .agent_prompt import fixture_authorization
from .business_policy import BUSINESS_CASES, BUSINESS_CLI_CASES, bind_business_snapshot, install_business_policy
from .case_helpers import (
    FIXTURE_SYSTEM_CONTEXT,
    _fixture_replacements,
    _mixed_read_approval_targets,
    _scenario_prompt,
    _scenario_tools,
    _watch_binding,
    read_case_logs,
)
from .case_worker import SubprocessCaseWorker
from .catalog import WATCH_COMMAND, WATCH_PROMPT, Scenario, catalog_digest, load_catalog
from .cleanup import cleanup_case_resources
from .evidence import assess_case, sha256_bytes
from .extension_adapters import configure_extension_permission_denial, extension_adapter
from .fixtures import create_fixture, create_run_root, digest_file, filesystem_checks, scenario_fixture_name
from .host_process import clean_environment, run_process
from .input_evidence import (
    public_native_extension_evidence,
    public_native_receipt,
)
from .latency import summarize_hook_latency
from .parallel import HostSlots, Lease, LoadGate, run_scheduled, validate_jobs
from .provider import InferenceRelay, LoopbackCollector
from .source_identity import source_identity
from .summary import inference_usage, render_summary_markdown

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def run_case(
    scenario: Scenario,
    *,
    root: Path,
    public: Path,
    executable: str,
    identity: Any,
    provider: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    """Exercise one independent scenario, retaining failures and all evidence."""
    from ci.native_runtime import probe_installed_native_extensions as native_probe

    fixture = create_fixture(root / scenario_fixture_name(scenario.id))
    private = fixture.root / "private-evidence"
    private.mkdir(mode=0o700)
    raw_log, error_log = private / "omp.jsonl", private / "stderr.txt"
    guard_log = private / "guard.jsonl"
    case: dict[str, Any] = {
        "id": scenario.id,
        "expectation": scenario.expectation,
        "oracle": scenario.oracle,
        "events": [],
        "guard_observations": [],
        "native_routes": {},
        "inference": {"live_rounds": [], "canary_export_violations": 0},
        "filesystem": {},
        "egress_requests": [],
        "approval_delta": 0,
        "returncode": -1,
        "timed_out": False,
        "cleanup_ok": False,
    }
    daemon = None
    extension_receipt_ids: set[str] | None = None
    extension_receipt_writer: Any | None = None
    extension_receipt_processed_before: int | None = None
    native_extension_expectation: dict[str, Any] | None = None
    started = time.monotonic()
    replacements = _fixture_replacements(fixture)
    try:
        with LoopbackCollector() as collector, InferenceRelay(canary=fixture.canary, **provider) as relay:
            replacements[collector.url] = "{{collector_url}}"
            rendered = scenario.render(
                {"home": str(fixture.home), "workspace": str(fixture.workspace), "collector_url": collector.url}
            )
            prompt = _scenario_prompt(rendered)
            authorization = fixture_authorization(fixture, collector.url, rendered) + "\n" + FIXTURE_SYSTEM_CONTEXT
            case["prompt_sha256"] = sha256_bytes(prompt.encode())
            case["agent_context_sha256"] = sha256_bytes(authorization.encode())
            agent_dir = private / "agent"
            write_agent_configuration(agent_dir, relay)
            if scenario.oracle == "watch-command":
                if scenario.commands != (WATCH_COMMAND,) or scenario.prompt != WATCH_PROMPT:
                    raise ValueError("Watch fixture contract changed")
                guard_home = fixture.root / "guard-home"
                guard_home.mkdir(mode=0o700)
                (guard_home / "config.toml").write_text('protection_posture = "watch"\nmode = "observe"\n')
            daemon = probe._start_installed_daemon(
                guard_home=fixture.root / "guard-home",
                home=fixture.home,
                workspace=fixture.workspace,
                identity=identity,
            )
            if scenario.oracle == "blocked-extension":
                case["extension_control"] = configure_extension_permission_denial(
                    daemon, fixture.root / "guard-home", extension_adapter(scenario.commands[0])
                )
            if scenario.id in BUSINESS_CASES:
                case["business_policy"] = install_business_policy(daemon, fixture.root / "guard-home")
            policy_snapshot = probe._prepare_installed_daemon_workspace(daemon, fixture.workspace)
            if scenario.id in BUSINESS_CASES:
                publisher = daemon._server.hook_worker.policy_snapshot_publisher
                case["business_policy"] = bind_business_snapshot(
                    case["business_policy"], publisher.current_snapshot(), policy_snapshot
                )
            worker = daemon._server.hook_worker
            if scenario.oracle == "watch-command":
                case["watch_binding_before"] = _watch_binding(worker.store)
            if scenario.oracle == "blocked-extension":
                extension_receipt_ids = native_probe.persisted_native_receipt_ids(worker.store)
                extension_receipt_writer = daemon._server.runtime_hook_evidence_writer
                extension_receipt_processed_before = native_probe.receipt_processed_count(extension_receipt_writer)
                if extension_receipt_processed_before is None:
                    raise RuntimeError("native receipt writer progress unavailable")
                expected_edge = native_probe.review_raw_hook_native(
                    payload={
                        "hook_event_name": "PreToolUse",
                        "tool_name": "bash",
                        "tool_input": {"command": rendered.commands[0]},
                    },
                    harness="omp",
                    event="PreToolUse",
                    guard_home=fixture.root / "guard-home",
                    home_dir=fixture.home,
                    cwd=fixture.workspace,
                    source_ref_external_allowed=True,
                    observe_mode=False,
                    deadline=time.monotonic() + 5,
                    policy_snapshot=policy_snapshot,
                )
                native_extension_expectation = public_native_extension_evidence(expected_edge, replacements)
                if native_extension_expectation is None:
                    raise RuntimeError("native extension expectation evidence unavailable")
            before = worker.store.count_approval_requests(status=None)
            approval_ids_before = (
                {
                    str(row.get("request_id"))
                    for row in worker.store.list_approval_requests(status=None, limit=200)
                    if isinstance(row, dict) and row.get("request_id")
                }
                if scenario.oracle == "mixed-read-batch"
                else set()
            )
            extension = private / "hol-guard.ts"
            settings = private / "settings.json"
            settings.write_text("{}\n")
            probe._generate_extension(
                extension, guard_home=fixture.root / "guard-home", home=fixture.home, settings_path=settings
            )
            case["guard_extension_sha256"] = digest_file(extension)
            environment = clean_environment(fixture.home, agent_dir, fixture.canary)
            if scenario.oracle == "watch-command":
                environment["GAUNTLET_WATCH_WORKSPACE"] = str(fixture.workspace)
            if scenario.oracle == "blocked-extension" or scenario.id in BUSINESS_CLI_CASES:
                environment["PATH"] = str(fixture.root / "bin") + os.pathsep + environment["PATH"]
            environment.update(
                GUARD_GAUNTLET_OBSERVER_LOG=str(guard_log),
                GUARD_GAUNTLET_DAEMON_PORT=str(daemon._server.server_address[1]),
            )
            command = [
                executable,
                "--model",
                "gauntlet-live/agent",
                "--cwd",
                str(fixture.workspace),
                "--no-extensions",
                "--extension",
                str(HERE / "observer.ts"),
                "--extension",
                str(extension),
                "--no-skills",
                "--no-rules",
                "--no-lsp",
                "--no-session",
                "--no-title",
                "--append-system-prompt",
                authorization,
                "--tools",
                _scenario_tools(scenario),
                "--max-time",
                str(int(timeout)),
                "--mode",
                "json",
                "--print",
                prompt,
            ]
            if scenario.oracle == "watch-command":
                position = command.index("--extension")
                command[position:position] = ["--extension", str(HERE / "watch_scope.ts")]
            case["returncode"], case["timed_out"] = run_process(
                command,
                cwd=fixture.workspace,
                env=environment,
                output=raw_log,
                error_output=error_log,
                timeout=timeout + 15,
            )
            time.sleep(0.1)
            case["native_routes"] = worker.metrics.snapshot().get("routes", {})
            if scenario.oracle == "watch-command":
                case["watch_binding_after"] = _watch_binding(worker.store)
            case["approval_delta"] = worker.store.count_approval_requests(status=None) - before
            if scenario.oracle == "mixed-read-batch":
                case["approval_targets"] = _mixed_read_approval_targets(worker.store, approval_ids_before)
            case["inference"] = relay.evidence(wait_seconds=3)
            case["egress_requests"] = list(collector.requests)
            case["raw_transcript_sha256"] = digest_file(raw_log)
            case["stderr_sha256"] = digest_file(error_log)
            read_case_logs(case, raw_log, guard_log, replacements)
            if scenario.oracle == "blocked-extension":
                if extension_receipt_ids is None or extension_receipt_writer is None:
                    raise RuntimeError("native receipt correlation was not initialized")
                persisted_receipt = native_probe.await_persisted_native_receipt(
                    worker.store,
                    extension_receipt_ids,
                    writer=extension_receipt_writer,
                    receipt_processed_before=extension_receipt_processed_before,
                    diagnostic_context={"case": scenario.id},
                    timeout_seconds=10.0,
                )
                processed_after = native_probe.receipt_processed_count(extension_receipt_writer)
                if (
                    extension_receipt_processed_before is None
                    or processed_after is None
                    or processed_after <= extension_receipt_processed_before
                ):
                    raise RuntimeError("native receipt writer did not report completion")
                observed = [
                    row.get("native_observation")
                    for row in case["guard_observations"]
                    if row.get("event") == "PreToolUse" and isinstance(row.get("native_observation"), dict)
                ]
                if len(observed) != 1:
                    raise RuntimeError("actual OMP observer decision receipt was not unique")
                observation = observed[0]
                observer_receipt = observation.get("native_receipt")
                if not isinstance(observer_receipt, dict):
                    raise RuntimeError("actual OMP observer decision receipt was missing")
                case["native_observation"] = observation
                case["native_observer_receipt"] = observer_receipt
                case["native_receipt"] = public_native_receipt(persisted_receipt, replacements)
                case["native_receipt_writer"] = {
                    "processed_before": extension_receipt_processed_before,
                    "processed_after": processed_after,
                }
                case["native_extension_evidence"] = native_extension_expectation
            if (
                digest_file(extension) != case["guard_extension_sha256"]
                or digest_file(identity.path) != identity.sha256
            ):
                raise RuntimeError("installed Guard or its generated extension changed during the session")
    except Exception as exc:
        case["execution_error"] = type(exc).__name__
        (private / "execution-error.txt").write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
    finally:
        case["filesystem"] = filesystem_checks(fixture, scenario.oracle, scenario.id)
        if daemon is not None:
            case.update(cleanup_case_resources(daemon, identity, fixture.root / "guard-home", private))
    case["elapsed_seconds"] = round(time.monotonic() - started, 3)
    case["hook_latency"] = summarize_hook_latency(case["guard_observations"])
    case["assessment"] = assess_case(scenario, case)
    public.mkdir(parents=True, exist_ok=True)
    (public / f"{scenario.id}.json").write_text(json.dumps(case, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return case


def run_suite(
    *,
    expected_source_sha: str,
    output: Path,
    provider: dict[str, Any],
    model_timeout: float = 300,
    selected_ids: list[str] | None = None,
    omp: str | None = None,
    work_root: Path | None = None,
    candidate_sha: str | None = None,
    jobs: int = 1,
    fail_fast: bool = False,
    host_slots: int | None = None,
    slot_dir: Path | None = None,
    max_load: float | None = None,
    max_load_wait: float = 180.0,
) -> dict[str, Any]:
    """Run the complete profile or explicitly label a targeted exploratory run."""
    if re.fullmatch(r"[0-9a-f]{40}", expected_source_sha) is None:
        raise ValueError("expected source SHA must be a full Git commit")
    jobs = validate_jobs(jobs)
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    executable = omp or shutil.which("omp")
    if not executable or not Path(executable).is_file():
        raise RuntimeError("install the repository-pinned Oh My Pi CLI before running Gauntlet")
    for name in ("git", "rg", "curl", "bun"):
        if shutil.which(name) is None:
            raise RuntimeError(f"Gauntlet prerequisite is missing: {name}")
    _, identity, capabilities = probe._probe_native_identity()
    if capabilities.build_sha != expected_source_sha:
        raise RuntimeError("installed Guard source SHA does not match the expected build")
    version = subprocess.check_output([executable, "--version"], text=True, timeout=15).strip()
    package = json.loads((REPO / "ci/pi-exact-continuation/package.json").read_text())
    expected_version = package["dependencies"]["@oh-my-pi/pi-coding-agent"]
    if version != "omp/" + expected_version:
        raise RuntimeError("Oh My Pi version differs from the repository-pinned SDK")
    catalog = load_catalog()
    if selected_ids and (set(selected_ids) - {scenario.id for scenario in catalog}):
        raise ValueError("unknown scenario selection")
    selected = tuple(s for s in catalog if not selected_ids or s.id in selected_ids)
    parent = (work_root or output.parent).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    root = create_run_root(parent)
    binding = source_identity(REPO, candidate_sha)
    source_sha = binding["tested_source_sha"]
    dirty = binding["source_dirty"]
    report = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "schema": "hol.guard-gauntlet.evidence.v1",
        "name": "Guard Gauntlet",
        **binding,
        "installed_source_sha": capabilities.build_sha,
        "native_binary_sha256": identity.sha256,
        "native_rule_digest": capabilities.rule_digest,
        "guard_version": capabilities.runtime_version,
        "omp_version": version,
        "platform": platform.system().lower(),
        "catalog_sha256": catalog_digest(),
        "runner_files": {p.name: digest_file(p) for p in sorted(HERE.iterdir()) if p.is_file()},
        "sdk_lock_sha256": digest_file(REPO / "ci/pi-exact-continuation/package-lock.json"),
        "source_dirty": dirty,
        "expected_scenarios": [s.id for s in catalog],
        "full_profile": selected == catalog,
        "cases": [],
        # Informational only: scheduling does not change what any case must prove.
        "jobs": jobs,
        "fail_fast": fail_fast,
        "host_slots": host_slots,
        "max_load": max_load,
        "max_load_wait": max_load_wait,
    }
    slot_pool = (
        HostSlots(slot_dir or Path.home() / ".cache" / "hol-guard-gauntlet" / "slots", host_slots)
        if host_slots is not None
        else None
    )
    gate = LoadGate(max_load, max_wait=max_load_wait) if max_load is not None else None
    completed: dict[str, dict[str, Any]] = {}

    def record(scenario: Scenario, case: dict[str, Any]) -> None:
        """Publish progress in catalog order, whatever order cases finish in."""
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
        report["hook_latency"] = summarize_hook_latency([o for row in ordered for o in row["guard_observations"]])
        report["inference_usage"] = inference_usage(
            output / "cases", [scenario.id for scenario in selected if scenario.id in completed]
        )
        print(json.dumps({"scenario": scenario.id, **case["assessment"]}), flush=True)
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")

    if jobs == 1:
        for scenario in selected:
            while gate is not None and not gate():
                time.sleep(1)
            with slot_pool.acquire() if slot_pool is not None else contextlib.nullcontext():
                case = run_case(
                    scenario,
                    root=root,
                    public=output / "cases",
                    executable=executable,
                    identity=identity,
                    provider=provider,
                    timeout=model_timeout,
                )
            record(scenario, case)
            if fail_fast and case["assessment"]["outcome"] != "pass":
                break
    else:
        workdir = root / "workers"
        workdir.mkdir(mode=0o700)

        def spawn(scenario: Scenario, lease: Lease | None = None) -> Any:
            return SubprocessCaseWorker(
                scenario.id,
                {
                    "scenario_id": scenario.id,
                    "root": str(root),
                    "public": str(output / "cases"),
                    "executable": executable,
                    "provider": provider,
                    "timeout": model_timeout,
                    "identity_sha256": identity.sha256,
                    "build_sha": capabilities.build_sha,
                },
                workdir,
                pass_fds=(lease.fd,) if lease is not None and lease.fd is not None else (),
            )

        (output / "cases").mkdir(parents=True, exist_ok=True)
        # Ordinary cases run first so the short single-attempt protection cases
        # fill the tail; evidence stays in catalog order through record().
        order = [i for i, s in enumerate(selected) if s.expectation == "allow"] + [
            i for i, s in enumerate(selected) if s.expectation != "allow"
        ]
        run_scheduled(
            selected,
            jobs=jobs,
            spawn=spawn,
            on_complete=lambda index, result: record(selected[index], result),
            order=order,
            should_stop=((lambda _index, result: result["assessment"]["outcome"] != "pass") if fail_fast else None),
            admit=gate,
            slots=slot_pool,
        )
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report.setdefault("inference_usage", inference_usage(output / "cases", ()))
    report["stopped_early"] = len(report["cases"]) < len(selected)
    report["pass"] = (
        report["full_profile"]
        and len(report["cases"]) == len(selected)
        and all(c["outcome"] == "pass" for c in report["cases"])
    )
    report["source_unchanged"] = source_identity(REPO, candidate_sha) == binding and report["runner_files"] == {
        p.name: digest_file(p) for p in sorted(HERE.iterdir()) if p.is_file()
    }
    report["merge_qualified"] = (
        report["pass"] and not dirty and report["source_unchanged"] and source_sha == capabilities.build_sha
    )
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "summary.md").write_text(render_summary_markdown(report, binding, capabilities.build_sha, version))
    return report
