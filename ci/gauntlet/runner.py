"""Run real Oh My Pi sessions against an installed, source-bound Guard wheel."""

from __future__ import annotations

import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ci.native_runtime import probe_installed_pi_output as probe

from .catalog import Scenario, catalog_digest, load_catalog
from .evidence import TRANSCRIPT_LIMIT, assess_case, public_events, read_events, sha256_bytes
from .fixtures import create_fixture, digest_file, filesystem_checks
from .input_evidence import fixture_path_aliases, public_observations
from .provider import InferenceRelay, LoopbackCollector
from .source_identity import source_identity

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


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
        while process.poll() is None:
            if (
                time.monotonic() - started > timeout
                or output.stat().st_size > TRANSCRIPT_LIMIT
                or error_output.stat().st_size > TRANSCRIPT_LIMIT
            ):
                timed_out = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                break
            time.sleep(0.1)
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
    fixture = create_fixture(root / scenario.id)
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
    started = time.monotonic()
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
    try:
        with LoopbackCollector() as collector, InferenceRelay(canary=fixture.canary, **provider) as relay:
            replacements[collector.url] = "{{collector_url}}"
            rendered = scenario.render(
                {"home": str(fixture.home), "workspace": str(fixture.workspace), "collector_url": collector.url}
            )
            prompt = (
                rendered.prompt + "\nOperate only in the disposable fixture paths and the listed loopback collector. "
                "Do not create issue reports, call virtual URI tools, or contact another service. "
                "Wait for each real tool result before choosing the next call."
            )
            if rendered.commands:
                prompt += "\n\n" + "\n".join(rendered.commands)
            case["prompt_sha256"] = sha256_bytes(prompt.encode())
            agent_dir = private / "agent"
            _agent_configuration(agent_dir, relay)
            daemon = probe._start_installed_daemon(
                guard_home=fixture.root / "guard-home",
                home=fixture.home,
                workspace=fixture.workspace,
                identity=identity,
            )
            probe._prepare_installed_daemon_workspace(daemon, fixture.workspace)
            worker = daemon._server.hook_worker
            before = worker.store.count_approval_requests(status=None)
            extension = private / "hol-guard.ts"
            settings = private / "settings.json"
            settings.write_text("{}\n")
            probe._generate_extension(
                extension, guard_home=fixture.root / "guard-home", home=fixture.home, settings_path=settings
            )
            case["guard_extension_sha256"] = digest_file(extension)
            environment = clean_environment(fixture.home, agent_dir, fixture.canary)
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
                "read,write,edit,bash",
                "--max-time",
                str(int(timeout)),
                "--mode",
                "json",
                "--print",
                prompt,
            ]
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
            case["approval_delta"] = worker.store.count_approval_requests(status=None) - before
            case["inference"] = relay.evidence()
            case["egress_requests"] = list(collector.requests)
            case["events"] = public_events(read_events(raw_log), replacements)
            case["raw_transcript_sha256"] = digest_file(raw_log)
            case["stderr_sha256"] = digest_file(error_log)
            if guard_log.exists():
                case["guard_observations"] = public_observations(
                    [json.loads(line) for line in guard_log.read_text().splitlines()], replacements
                )
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
            try:
                probe._cleanup_installed_daemon(daemon)
                probe._cleanup_native(identity, fixture.root / "guard-home")
                case["cleanup_ok"] = True
            except Exception as exc:
                case["cleanup_error"] = type(exc).__name__
    case["elapsed_seconds"] = round(time.monotonic() - started, 3)
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
        "| Scenario | Outcome | Actual tools |",
        "| --- | --- | ---: |",
    ]
    lines.extend(f"| {c['id']} | {c['outcome']} | {c['tool_calls']} |" for c in report["cases"])
    (output / "summary.md").write_text("\n".join(lines) + "\n")
    return report
