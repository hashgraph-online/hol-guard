"""Run real Oh My Pi sessions against an installed, source-bound Guard wheel."""

from __future__ import annotations

import json
import os
import platform
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ci.native_runtime import probe_installed_pi_output as probe

from .catalog import WATCH_COMMAND, WATCH_PROMPT, Scenario, catalog_digest, load_catalog
from .cleanup import cleanup_case_resources
from .evidence import TRANSCRIPT_LIMIT, assess_case, public_events, read_events, sha256_bytes
from .fixtures import Fixture, create_fixture, digest_file, filesystem_checks, scenario_fixture_name
from .input_evidence import fixture_path_aliases, public_observations, redact_value
from .latency import summarize_hook_latency
from .provider import InferenceRelay, LoopbackCollector
from .source_identity import source_identity

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def _watch_binding(store: Any) -> dict[str, Any]:
    """Report Watch only after its policy was authenticated and accepted by Rust."""
    from codex_plugin_scanner.guard.native_policy_snapshot_acked import acked_snapshot_binding_for_store

    binding = acked_snapshot_binding_for_store(store)
    if binding is None or binding.get("mode") != "observe":
        raise RuntimeError("Watch fixture lacks an authenticated resident-accepted policy")
    return {key: binding[key] for key in ("mode", "generation", "policy_digest", "runtime_identity")}


def _mixed_read_approval_targets(store: Any, known_ids: set[str]) -> list[str]:
    """Label new inbox rows by the mixed-read path they name. Unrecognized rows stay unmatched."""

    from .mixed_reads import TARGETS

    labels = []
    for row in store.list_approval_requests(status=None, limit=200):
        if not isinstance(row, dict) or str(row.get("request_id") or "") in known_ids:
            continue
        launch = str(row.get("launch_target") or "").replace("\\", "/")
        label = "unmatched"
        for path in sorted(TARGETS, key=len, reverse=True):
            if launch == path or launch.endswith("/" + path):
                label = path
                break
        labels.append(label)
    return labels


def clean_environment(home: Path, agent_dir: Path, canary: str) -> dict[str, str]:
    """The model/host receives no inherited provider, cloud or GitHub credential."""
    environment = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR") if key in os.environ}
    environment["PATH"] = str(Path(sys.executable).parent) + os.pathsep + environment.get("PATH", "")
    environment.update(
        HOME=str(home),
        USERPROFILE=str(home),
        PI_CODING_AGENT_DIR=str(agent_dir),
        GAUNTLET_SECRET_TOKEN=canary,
        LANG="C.UTF-8",
        TERM="dumb",
        NO_COLOR="1",
        GIT_CONFIG_NOSYSTEM="1",
    )
    return environment


def run_process(
    command: list[str], *, cwd: Path, env: dict[str, str], output: Path, error_output: Path, timeout: float
) -> tuple[int, bool]:
    """Bound the actual host process and its transcript, not just a model flag."""
    if os.name != "posix":
        raise RuntimeError("Gauntlet currently requires a POSIX runner for process-group containment")
    started = time.monotonic()
    timed_out = False
    with output.open("wb") as out, error_output.open("wb") as err:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=out, stderr=err, start_new_session=True)
        try:
            while process.poll() is None:
                if (
                    time.monotonic() - started > timeout
                    or output.stat().st_size > TRANSCRIPT_LIMIT
                    or error_output.stat().st_size > TRANSCRIPT_LIMIT
                ):
                    timed_out = True
                    break
                time.sleep(0.1)
        finally:
            # The session belongs to this run, including when the operator interrupts it.
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
            try:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                finally:
                    # Reaping the leader does not prove that its descendants exited.
                    with suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    return process.returncode, timed_out


def _agent_configuration(path: Path, relay: InferenceRelay) -> None:
    """Point the actual OMP provider at the transparent live relay."""
    path.mkdir(mode=0o700)
    configuration = {
        "providers": {
            "gauntlet-live": {
                "baseUrl": relay.base_url,
                "api": "openai-completions",
                "auth": "none",
                "models": [
                    {
                        "id": "agent",
                        "name": "Guard Gauntlet live inference",
                        "reasoning": False,
                        "input": ["text"],
                        "contextWindow": 128000,
                        "maxTokens": 8192,
                    }
                ],
            }
        }
    }
    # JSON is a YAML subset; this avoids another serialization dependency.
    (path / "models.yml").write_text(json.dumps(configuration, indent=2), encoding="utf-8")


def _configure_ollama_permission_denial(daemon: Any, guard_home: Path) -> dict[str, Any]:
    """Install a signed synthetic extension control for the one denial case."""
    from ci.native_runtime.probe_installed_native_extensions import commit_controls, control, provision
    from codex_plugin_scanner.guard.approval_gate import update_settings
    from codex_plugin_scanner.guard.config import update_guard_settings
    from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
    from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlState, ControlTargetKind

    password = secrets.token_urlsafe(32)
    update_guard_settings(guard_home, {"mode": "enforce"})
    update_settings(
        guard_home,
        {"enabled": True, "new_password": password, "confirm_password": password, "cooldown_seconds": 0},
    )
    store = daemon._server.store
    provision(store)
    permission = BUILT_IN_COMMAND_EXTENSION_REGISTRY.permission_for_rule_id("command.ollama.rm")
    if permission is None:
        raise RuntimeError("installed extension catalog lacks command.ollama.rm permission")
    enabled = control(ControlTargetKind.EXTENSION, "command.ollama", ControlState.ENABLED)
    revision = commit_controls(
        store,
        password,
        (enabled, control(ControlTargetKind.PERMISSION, permission.permission_id, ControlState.DISABLED)),
    )
    return {
        "extension_id": "command.ollama",
        "rule_id": "command.ollama.rm",
        "permission_id": permission.permission_id,
        "permission_state": "disabled",
        "control_revision": revision,
    }


def _public_native_receipt(receipt: object, replacements: dict[str, str]) -> dict[str, Any] | None:
    """Keep only safe native denial metadata and structured extension binding."""
    if not isinstance(receipt, dict):
        return None
    selected = {
        key: receipt[key]
        for key in (
            "schema",
            "version",
            "authority",
            "decision_id",
            "request_id",
            "harness",
            "event_name",
            "payload_kind",
            "decision",
            "policy_action",
            "observed_policy_action",
            "reason_code",
            "command_extensions",
        )
        if key in receipt
    }
    return redact_value(selected, replacements)


def _public_native_extension_evidence(edge: object, replacements: dict[str, str]) -> dict[str, Any] | None:
    """Export bounded full observations from an independent native expectation probe."""
    if not isinstance(edge, dict):
        return None
    result = edge.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("command_extensions"), dict):
        return None
    return redact_value(result["command_extensions"], replacements)


def _scenario_tools(scenario: Scenario) -> str:
    """Expose the real tools required by the task, without unrelated probes."""
    if scenario.oracle == "home-copy-task":
        return "bash,read"
    if scenario.commands:
        return "bash"
    if scenario.oracle == "blocked-read":
        return "read"
    return ",".join(scenario.required_tools) or "read,write,edit,bash"


def _fixture_replacements(fixture: Fixture) -> dict[str, str]:
    """Use one normalization path for rendered host and Guard evidence."""
    replacements = {
        fixture.canary: "<synthetic-canary-redacted>",
        str(fixture.workspace): "{{workspace}}",
        str(fixture.home): "{{home}}",
        str(fixture.root): "{{fixture}}",
    }
    replacements = fixture_path_aliases(replacements)
    # Commands quote each interpolated fixture path. Normalize the entire
    # shell-quoted spelling before redacting raw paths, including apostrophes.
    for value, placeholder in tuple(replacements.items()):
        if value != fixture.canary:
            replacements[shlex.quote(value)] = placeholder
    return replacements


def read_case_logs(case: dict[str, Any], raw_log: Path, guard_log: Path, replacements: dict[str, str]) -> None:
    """Retain Guard timings even when the independently parsed host transcript fails."""
    if guard_log.exists():
        try:
            rows = [json.loads(line) for line in guard_log.read_text().splitlines() if line.strip()]
            if any(not isinstance(row, dict) for row in rows):
                raise ValueError("malformed Guard observation")
            case["guard_observations"] = public_observations(rows, replacements)
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            case["guard_observation_error"] = type(exc).__name__
    case["events"] = public_events(read_events(raw_log), replacements)


def _scenario_prompt(scenario: Scenario) -> str:
    """Keep fixed batch scheduling consistent with the scenario's evidence contract."""
    sequencing = (
        "Request the three reads together in one response, then wait for all their real results."
        if scenario.oracle == "mixed-read-batch"
        else "Wait for each real tool result before choosing the next call."
    )
    return (
        scenario.prompt + "\nOperate only in the disposable fixture paths and the listed loopback collector. "
        "Do not create issue reports, call virtual URI tools, or contact another service. " + sequencing
    )


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
            if rendered.commands:
                prompt += "\n\n" + "\n".join(rendered.commands)
            case["prompt_sha256"] = sha256_bytes(prompt.encode())
            agent_dir = private / "agent"
            _agent_configuration(agent_dir, relay)
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
                case["extension_control"] = _configure_ollama_permission_denial(daemon, fixture.root / "guard-home")
            policy_snapshot = probe._prepare_installed_daemon_workspace(daemon, fixture.workspace)
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
                native_extension_expectation = _public_native_extension_evidence(expected_edge, replacements)
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
            if scenario.oracle == "blocked-extension":
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
                case["native_receipt"] = _public_native_receipt(persisted_receipt, replacements)
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
) -> dict[str, Any]:
    """Run the complete profile or explicitly label a targeted exploratory run."""
    if re.fullmatch(r"[0-9a-f]{40}", expected_source_sha) is None:
        raise ValueError("expected source SHA must be a full Git commit")
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
    root = Path(tempfile.mkdtemp(prefix="guard-gauntlet-", dir=parent)).resolve()
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
    }
    hook_observations = []
    for scenario in selected:
        case = run_case(
            scenario,
            root=root,
            public=output / "cases",
            executable=executable,
            identity=identity,
            provider=provider,
            timeout=model_timeout,
        )
        report["cases"].append(
            {
                "id": scenario.id,
                **case["assessment"],
                "evidence_sha256": digest_file(output / "cases" / f"{scenario.id}.json"),
            }
        )
        hook_observations.extend(case["guard_observations"])
        report["hook_latency"] = summarize_hook_latency(hook_observations)
        print(json.dumps({"scenario": scenario.id, **case["assessment"]}), flush=True)
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["pass"] = report["full_profile"] and all(c["outcome"] == "pass" for c in report["cases"])
    report["source_unchanged"] = source_identity(REPO, candidate_sha) == binding and report["runner_files"] == {
        p.name: digest_file(p) for p in sorted(HERE.iterdir()) if p.is_file()
    }
    report["merge_qualified"] = (
        report["pass"] and not dirty and report["source_unchanged"] and source_sha == capabilities.build_sha
    )
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = [
        "# Guard Gauntlet",
        "",
        f"Candidate: `{binding['candidate_sha']}`",
        f"Installed build: `{capabilities.build_sha}`",
        f"Host: `{version}` / `{report['platform']}`",
        f"Full profile: {report['full_profile']}",
        f"Merge-qualified: {report['merge_qualified']}",
        "",
        "Hook HTTP round-trip latency (nearest-rank; milliseconds):",
        f"Samples: {report['hook_latency']['samples']}; missing: {report['hook_latency']['missing_samples']}; "
        f"failed attempts: {report['hook_latency']['failed_attempts']}",
        "",
        "| p50 | p90 | p95 | p99 | mean | max |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
        "| "
        + " | ".join(
            json.dumps(report["hook_latency"][key])
            for key in ("p50_ms", "p90_ms", "p95_ms", "p99_ms", "mean_ms", "max_ms")
        )
        + " |",
        "",
        "| Event | Samples | p50 | p90 | p95 | p99 | mean | max |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        *[
            "| "
            + event
            + " | "
            + " | ".join(
                json.dumps(values[key])
                for key in ("samples", "p50_ms", "p90_ms", "p95_ms", "p99_ms", "mean_ms", "max_ms")
            )
            + " |"
            for event, values in report["hook_latency"]["by_event"].items()
        ],
        "",
        "| Scenario | Outcome | Actual tools |",
        "| --- | --- | ---: |",
    ]
    lines.extend(f"| {c['id']} | {c['outcome']} | {c['tool_calls']} |" for c in report["cases"])
    (output / "summary.md").write_text("\n".join(lines) + "\n")
    return report
