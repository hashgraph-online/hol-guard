"""Run and assess the additive real-agent contained Bun/Vitest profile."""

from __future__ import annotations

import json
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ci.native_runtime import probe_installed_pi_output as probe
from ci.native_runtime.probe_workflow_matrix import _workflow_prompt, contained_vitest_cases

from .catalog import catalog_digest
from .contained_judge import (
    _CONTAINED_PROFILE,
    _contained_project_checks,
    _contained_project_snapshot,
    _contained_snapshot_digest,
    assess_contained_execution,
)
from .evidence import public_events, read_events
from .fixtures import create_fixture, digest_file
from .input_evidence import fixture_path_aliases, public_observations, redact_value
from .provider import InferenceRelay, LoopbackCollector
from .runner import (
    HERE,
    REPO,
    _agent_configuration,
    clean_environment,
    run_process,
)
from .source_files import digest_runner_files
from .source_identity import source_identity

_CONTAINED_CROSS_PROJECT_CASES = frozenset({"bun-cross-project", "bun-cross-project-equals"})


def _contained_case_batches(cases: list[Any], project: Path, workspace: Path) -> tuple[tuple[list[Any], Path], ...]:
    """Partition by the reviewed case identity so caller and target cannot drift apart."""
    local = [case for case in cases if case.name not in _CONTAINED_CROSS_PROJECT_CASES]
    cross_project = [case for case in cases if case.name in _CONTAINED_CROSS_PROJECT_CASES]
    return tuple(batch for batch in ((local, project), (cross_project, workspace)) if batch[0])


def _source_snapshots_match(
    initial_binding: dict[str, Any],
    current_binding: dict[str, Any],
    initial_runner_files: dict[str, str],
    current_runner_files: dict[str, str],
) -> bool:
    """Require source ancestry and every runner byte to remain stable during the run."""
    return initial_binding == current_binding and initial_runner_files == current_runner_files


def _guard_wrapper_command(extension: Path) -> str:
    """Read the absolute wrapper selected by the generated installed extension."""
    source = extension.read_text(encoding="utf-8")
    match = re.search(r'^const GUARD_CLI_WRAPPER_COMMAND = ("(?:\\.|[^"\\])*");$', source, re.MULTILINE)
    if match is None:
        raise RuntimeError("generated Guard extension omitted its CLI wrapper binding")
    wrapper = json.loads(match.group(1))
    if (
        not isinstance(wrapper, str)
        or not Path(wrapper).is_absolute()
        or not Path(wrapper).is_file()
        or not os.access(wrapper, os.X_OK)
    ):
        raise RuntimeError("generated Guard extension did not select an executable absolute CLI wrapper")
    return wrapper


class _ContainedRequestCapture:
    """Capture only owned adapter request files while the real sink is active."""

    def __init__(self, root: Path) -> None:
        self.records: dict[str, bytes] = {}
        self._root = root.resolve(strict=True)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="gauntlet-contained-request-capture", daemon=True)

    def __enter__(self) -> _ContainedRequestCapture:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._scan_once()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._scan_once()
            self._stop.wait(0.001)

    def _scan_once(self) -> None:
        for path in self._root.glob("hol-guard-contained-test-*/request.json"):
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    metadata = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.getuid()
                        or (metadata.st_mode & 0o777) != 0o600
                        or metadata.st_size > 1_048_576
                    ):
                        continue
                    self.records[str(path)] = os.read(descriptor, 1_048_577)
                finally:
                    os.close(descriptor)
            except (OSError, ValueError):
                continue


def run_contained_profile(
    *,
    expected_source_sha: str,
    output: Path,
    provider: dict[str, Any],
    test_project: Path,
    model_timeout: float = 300,
    omp: str | None = None,
    work_root: Path | None = None,
    candidate_sha: str | None = None,
) -> dict[str, Any]:
    """Run the additive real-agent Bun/Vitest profile against one explicit fixture project."""
    if re.fullmatch(r"[0-9a-f]{40}", expected_source_sha) is None:
        raise ValueError("expected source SHA must be a full Git commit")
    project = test_project.resolve(strict=True)
    cases = contained_vitest_cases(project)
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    executable = omp or shutil.which("omp")
    if not executable or not Path(executable).is_file():
        raise RuntimeError("install the repository-pinned Oh My Pi CLI before running the contained profile")
    if platform.system() != "Darwin":
        raise RuntimeError("the contained Bun/Vitest sink is only generated on macOS")
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
    binding = source_identity(REPO, candidate_sha)
    initial_runner_files = digest_runner_files(HERE)
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat()
    parent = (work_root or output.parent).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="guard-gauntlet-contained-", dir=parent)).resolve()
    fixture = create_fixture(root / "fixture")
    private = fixture.root / "private-evidence"
    private.mkdir(mode=0o700)
    request_tmp = fixture.root / "request-tmp"
    request_tmp.mkdir(mode=0o700)
    raw_logs = [private / "omp-0.jsonl", private / "omp-1.jsonl"]
    error_logs = [private / "stderr-0.txt", private / "stderr-1.txt"]
    guard_log = private / "guard.jsonl"
    before_snapshot = _contained_project_snapshot(project)
    replacements = fixture_path_aliases(
        {
            fixture.canary: "<synthetic-canary-redacted>",
            str(fixture.workspace): "{{workspace}}",
            str(fixture.home): "{{home}}",
            str(fixture.root): "{{fixture}}",
            str(request_tmp): "/guard-gauntlet-contained-request-tmp",
            str(project): "{{contained_project}}",
        }
    )
    for value, placeholder in tuple(replacements.items()):
        if value != fixture.canary:
            replacements[shlex.quote(value)] = placeholder
    events: list[dict[str, Any]] = []
    raw_events: list[dict[str, Any]] = []
    guard_observations: list[dict[str, Any]] = []
    inference: dict[str, Any] = {"live_rounds": [], "canary_export_violations": 0}
    egress_requests: list[dict[str, Any]] = []
    native_routes: dict[str, Any] = {}
    returncode = -1
    timed_out = False
    approval_delta = 0
    cleanup_ok = False
    execution_error: str | None = None
    daemon = None
    guard_home = fixture.root / "guard-home"
    wrapper_command: str | None = None
    wrapper_sha256: str | None = None
    request_records: dict[str, bytes] = {}
    caller_workspaces = [
        fixture.workspace if case.name in _CONTAINED_CROSS_PROJECT_CASES else project for case in cases
    ]
    target_workspaces: list[Path | None] = [
        project if case.name in _CONTAINED_CROSS_PROJECT_CASES else None for case in cases
    ]
    try:
        with LoopbackCollector() as collector, InferenceRelay(canary=fixture.canary, **provider) as relay:
            agent_dir = private / "agent"
            _agent_configuration(agent_dir, relay)
            daemon = probe._start_installed_daemon(
                guard_home=guard_home,
                home=fixture.home,
                workspace=project,
                identity=identity,
            )
            probe._prepare_installed_daemon_workspace(daemon, project)
            probe._prepare_installed_daemon_workspace(daemon, fixture.workspace)
            worker = daemon._server.hook_worker
            before_approvals = worker.store.count_approval_requests(status=None)
            extension = private / "hol-guard.ts"
            settings = private / "settings.json"
            settings.write_text("{}\n")
            probe._generate_extension(extension, guard_home=guard_home, home=fixture.home, settings_path=settings)
            extension_sha256 = digest_file(extension)
            wrapper_command = _guard_wrapper_command(extension)
            wrapper_sha256 = digest_file(Path(wrapper_command))
            environment = clean_environment(fixture.home, agent_dir, fixture.canary)
            environment.update(
                GUARD_GAUNTLET_OBSERVER_LOG=str(guard_log),
                GUARD_GAUNTLET_DAEMON_PORT=str(daemon._server.server_address[1]),
                TMPDIR=str(request_tmp),
            )
            returncodes: list[int] = []
            timeouts: list[bool] = []
            batches = _contained_case_batches(cases, project, fixture.workspace)
            with _ContainedRequestCapture(request_tmp) as capture:
                for index, (batch, cwd) in enumerate(batches):
                    command = [
                        executable,
                        "--model",
                        "gauntlet-live/agent",
                        "--cwd",
                        str(cwd),
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
                        "--tools",
                        "bash",
                        "--max-time",
                        str(int(model_timeout)),
                        "--mode",
                        "json",
                        "--print",
                        _workflow_prompt(batch),
                    ]
                    status, timed = run_process(
                        command,
                        cwd=cwd,
                        env=environment,
                        output=raw_logs[index],
                        error_output=error_logs[index],
                        timeout=model_timeout + 15,
                    )
                    returncodes.append(status)
                    timeouts.append(timed)
                    raw_events.extend(read_events(raw_logs[index]))
                request_records = capture.records
            returncode = next((status for status in returncodes if status != 0), 0)
            timed_out = any(timeouts)
            time.sleep(0.1)
            native_routes = worker.metrics.snapshot().get("routes", {})
            approval_delta = worker.store.count_approval_requests(status=None) - before_approvals
            inference = relay.evidence()
            egress_requests = list(collector.requests)
            events = public_events(raw_events, replacements)
            if guard_log.exists():
                rows = [json.loads(line) for line in guard_log.read_text().splitlines() if line.strip()]
                guard_observations = public_observations(rows, replacements)
            if (
                digest_file(extension) != extension_sha256
                or digest_file(identity.path) != identity.sha256
                or wrapper_command is None
                or wrapper_sha256 != digest_file(Path(wrapper_command))
            ):
                raise RuntimeError("installed Guard or its generated extension changed during the session")
    except Exception as exc:
        execution_error = type(exc).__name__
        (private / "execution-error.txt").write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
    finally:
        if daemon is not None:
            try:
                probe._cleanup_installed_daemon(daemon)
                probe._cleanup_native(identity, fixture.root / "guard-home")
                cleanup_ok = True
            except Exception as exc:
                execution_error = execution_error or type(exc).__name__
    filesystem, after_snapshot = _contained_project_checks(project, before_snapshot)
    public_commands = [redact_value(case.command, replacements) for case in cases]
    public_callers = [redact_value(str(path), replacements) for path in caller_workspaces]
    public_targets = [redact_value(str(path), replacements) if path is not None else None for path in target_workspaces]
    public_request_records = {redact_value(path, replacements): value for path, value in request_records.items()}
    assessment = assess_contained_execution(
        cases,
        raw_events=raw_events,
        events=events,
        guard_observations=guard_observations,
        native_routes=native_routes,
        inference=inference,
        filesystem=filesystem,
        returncode=returncode,
        timed_out=timed_out,
        cleanup_ok=cleanup_ok,
        approval_delta=approval_delta,
        egress_requests=egress_requests,
        expected_commands=public_commands,
        caller_workspaces=public_callers,
        target_workspaces=public_targets,
        expected_wrapper=redact_value(wrapper_command or "", replacements),
        expected_guard_home=redact_value(str(guard_home), replacements),
        expected_home=redact_value(str(fixture.home), replacements),
        request_records=public_request_records,
        request_workspaces=[str(path) for path in caller_workspaces],
        execution_error=execution_error,
    )
    current_binding = source_identity(REPO, candidate_sha)
    current_runner_files = digest_runner_files(HERE)
    source_unchanged = _source_snapshots_match(
        binding,
        current_binding,
        initial_runner_files,
        current_runner_files,
    )
    report: dict[str, Any] = {
        "started_at": started_at,
        "schema": "hol.guard-gauntlet.contained-bun-vitest.evidence.v1",
        "name": "Guard Gauntlet contained Bun/Vitest extended profile",
        "profile": _CONTAINED_PROFILE,
        "qualification": "extended-profile-only",
        "core20_qualified": False,
        **binding,
        "installed_source_sha": capabilities.build_sha,
        "native_binary_sha256": identity.sha256,
        "native_rule_digest": capabilities.rule_digest,
        "guard_version": capabilities.runtime_version,
        "omp_version": version,
        "guard_cli_wrapper_sha256": wrapper_sha256,
        "platform": platform.system().lower(),
        "core_catalog_sha256": catalog_digest(),
        "runner_files": initial_runner_files,
        "sdk_lock_sha256": digest_file(REPO / "ci/pi-exact-continuation/package-lock.json"),
        "source_dirty": binding["source_dirty"],
        "source_unchanged": source_unchanged,
        "contained_test_project": "{{contained_project}}",
        "contained_caller_workspaces": public_callers,
        "contained_target_workspaces": public_targets,
        "expected_cases": [case.name for case in cases],
        "full_profile": True,
        "cases": [],
        "actual_tool_calls": assessment["actual_tool_calls"],
        "profile_protocol_errors": assessment["protocol_errors"],
        "filesystem": filesystem,
        "project_snapshot_sha256": {
            "before": _contained_snapshot_digest(before_snapshot),
            "after": _contained_snapshot_digest(after_snapshot) if after_snapshot else None,
        },
        "events": events,
        "guard_observations": guard_observations,
        "inference": inference,
        "returncode": returncode,
        "timed_out": timed_out,
        "cleanup_ok": cleanup_ok,
        "approval_delta": approval_delta,
        "egress_requests": egress_requests,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }
    public = output / "cases"
    public.mkdir(parents=True, exist_ok=True)
    report["cases"] = []
    for index, (case, result) in enumerate(zip(cases, assessment["cases"], strict=True)):
        request_proofs = assessment.get("request_proofs", [])
        case_evidence = {
            "id": case.name,
            "profile": _CONTAINED_PROFILE,
            "command": redact_value(case.command, replacements),
            "assessment": result,
            "filesystem": filesystem,
            "project_snapshot_sha256": report["project_snapshot_sha256"],
            "events": events,
            "guard_observations": guard_observations,
            "inference": inference,
            "native_routes": native_routes,
            "caller_workspace": public_callers[index],
            "target_workspace": public_targets[index],
            "tool_call_count": result["tool_calls"],
            "request_proof": request_proofs[index] if index < len(request_proofs) else None,
        }
        case_path = public / f"{case.name}.json"
        case_path.write_text(json.dumps(case_evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        report["cases"].append({**result, "evidence_sha256": digest_file(case_path)})
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["pass"] = assessment["profile_pass"] and source_unchanged
    if not source_unchanged:
        report["profile_failure_reason"] = "source-or-runner-files-changed-during-run"
    report["merge_qualified"] = False
    profile_evidence = output / "contained-profile.json"
    profile_evidence.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (output / "summary.md").write_text(
        "\n".join(
            [
                "# Guard Gauntlet contained Bun/Vitest extended profile",
                "",
                "This additive profile is not a core20 qualification.",
                f"Profile pass: {report['pass']}",
                f"Merge-qualified: {report['merge_qualified']}",
                *(
                    [f"Profile failure reason: {report['profile_failure_reason']}"]
                    if "profile_failure_reason" in report
                    else []
                ),
                "",
                "| Case | Outcome | Actual tools |",
                "| --- | --- | ---: |",
                *[
                    f"| {case['id']} | {case['outcome']} | {case['tool_calls']} |"
                    for case in report["cases"]
                ],
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return report
