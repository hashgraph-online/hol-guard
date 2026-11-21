"""Run full developer tasks against real GitHub from inside a locked-down container.

The host orchestrator (this module) is trusted. It starts a gateway container that holds the
only real GitHub token and enforces the default-deny policy, then an agent container on an
internal Docker network whose only reachable peer is that gateway. Per task it seeds any
repository the task needs as a private run-owned repository, judges the physical outcome from
what GitHub holds, and always retires every run-owned repository so names are free next run.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .catalog import Scenario
from .evidence import reconcile
from .full_task_docker_inputs import (
    DOCKER_DIR,
    GuardSource,
    ensure_image,
    write_repo_inputs,
)
from .full_task_host_github import GitHubError, HostGitHub, acquire_token
from .full_task_remote_checks import CANARY_CHECK, remote_checks
from .full_task_runner import assess_case, finish_report
from .full_tasks import REMOTE_TASKS, load_full_tasks
from .source_identity import source_identity

AGENT_LIMITS = ["--cpus", "2", "--memory", "6g", "--pids-limit", "2048"]
GATEWAY_LIMITS = ["--cpus", "0.5", "--memory", "256m", "--pids-limit", "256"]
HARDENING = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
# What Guard's Linux workspace containment needs to run inside the agent container.
# The seccomp profile is Docker's default plus the namespace and mount calls
# bubblewrap makes in an unprivileged user namespace. Mounting a fresh /proc there
# requires an unmasked /proc, and the overlay's upper layer cannot sit on the
# container's own overlay root, so /tmp is a tmpfs. Capabilities stay dropped, so
# the agent still cannot mount anything in the container's own namespaces.
AGENT_CONTAINMENT = [
    "--security-opt",
    f"seccomp={DOCKER_DIR / 'agent-seccomp.json'}",
    "--security-opt",
    "systempaths=unconfined",
    "--tmpfs",
    "/tmp:rw,exec,size=2g,mode=1777",
]
# Example target for the foreign-repository probe: any repository outside the run's own set.
FOREIGN_PROBE = "octocat/Hello-World"
MAX_LOAD = 12.0
RELAY_HOSTS = ("github.com", "api.github.com", "registry.npmjs.org", "relay.gauntlet.test")


def wait_for_quiet_host(limit: float = MAX_LOAD, patience: float = 1800) -> None:
    """One heavy container at a time, and none while the machine is already busy."""
    deadline = time.monotonic() + patience
    while os.getloadavg()[0] > limit:
        if time.monotonic() > deadline:
            raise RuntimeError(f"host load stayed above {limit} for {patience:.0f}s")
        time.sleep(30)


def docker(*args: str, check: bool = True, env: dict[str, str] | None = None, timeout: float = 120) -> str:
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, env=env)
    if check and result.returncode != 0:
        raise RuntimeError(f"docker {args[0]} failed: {result.stderr.strip()[-300:]}")
    return result.stdout.strip()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines() if path.is_file() else []:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def summarize_gateway(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts by verdict plus every denial's shape. Bodies and credentials are never in the rows."""
    denials = Counter(
        (row["host"], row["method"], row["reason"], row.get("graphql_op")) for row in rows if row["decision"] == "deny"
    )
    return {
        "requests": len(rows),
        "allowed": sum(row["decision"] == "allow" for row in rows),
        "denied": sum(row["decision"] == "deny" for row in rows),
        "denials": [
            {"host": h, "method": m, "reason": r, "graphql_op": g, "count": n}
            for (h, m, r, g), n in denials.most_common()
        ],
        "canary_hits": sum(bool(row.get("canary_hits")) for row in rows),
    }


class TaskRun:
    """Resources of one task: a network, a gateway, an agent and the repositories they may touch."""

    def __init__(
        self,
        *,
        task: Scenario,
        github: HostGitHub,
        inputs: Path,
        image: str,
        guard: GuardSource,
        output: Path,
        provider: dict[str, Any],
        mode: str,
        timeout: float,
    ) -> None:
        self.task, self.github, self.inputs, self.image, self.guard = task, github, inputs, image, guard
        self.provider, self.mode, self.timeout = provider, mode, timeout
        self.run_id = secrets.token_hex(4)
        self.names = {kind: f"ft-{self.run_id}-{kind}" for kind in ("net", "gateway", "agent")}
        self.dir = output / "tasks" / task.id
        self.canary = "GAUNTLET_SYNTHETIC_" + secrets.token_hex(24)
        self.seeded: dict[str, str] = {}
        self.cleanup: list[dict[str, Any]] = []
        self.started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def seed(self) -> str | None:
        if self.task.id != "contributing-pull-request":
            return None
        name = f"guard-ft-{self.run_id}-{self.task.id}"
        self.seeded[name] = self.github.create_private_repo(name, "Temporary Gauntlet fixture; safe to delete")
        return name

    def start_network(self) -> str:
        docker("network", "create", "--internal", self.names["net"])
        relay_port = urlsplit(self.provider["base_url"]).port
        seeds = [f"--seed={name}={node}" for name, node in self.seeded.items()]
        (self.dir / "gateway").mkdir(parents=True)
        env = self.github.child_environment("GATEWAY_GITHUB_TOKEN")
        env["GATEWAY_RELAY_TOKEN"] = self.provider["api_key"]
        env["GATEWAY_CANARIES"] = json.dumps({self.task.id: self.canary})
        docker(
            "create",
            "--name",
            self.names["gateway"],
            "--platform",
            self.guard.platform,
            "--network",
            self.names["net"],
            "--init",
            *GATEWAY_LIMITS,
            *HARDENING,
            "--sysctl",
            "net.ipv4.ip_unprivileged_port_start=0",
            "--tmpfs",
            "/run/gateway:rw,size=8m,mode=700,uid=10001",
            "-v",
            f"{self.inputs}:/inputs:ro",
            "-v",
            f"{self.dir / 'gateway'}:/evidence",
            "-e",
            "GATEWAY_GITHUB_TOKEN",
            "-e",
            "GATEWAY_RELAY_TOKEN",
            "-e",
            "GATEWAY_CANARIES",
            "-e",
            "PYTHONPATH=/inputs/gateway",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            self.image,
            "python",
            "-m",
            "ftgw.full_task_gateway",
            "--owner",
            self.github.owner,
            "--relay-port",
            str(relay_port),
            "--evidence",
            "/evidence",
            *seeds,
            env=env,
        )
        docker("network", "connect", "bridge", self.names["gateway"])
        docker("start", self.names["gateway"])
        template = '{{{{(index .NetworkSettings.Networks "{}").IPAddress}}}}'.format(self.names["net"])
        for _ in range(60):
            ip = docker("inspect", "-f", template, self.names["gateway"])
            if ip and self._gateway_healthy():
                return ip
            time.sleep(1)
        raise RuntimeError("gateway did not become healthy")

    def _gateway_healthy(self) -> bool:
        probe = "import urllib.request as u; u.urlopen('http://127.0.0.1:8079/health', timeout=2).read()"
        result = subprocess.run(
            ["docker", "exec", self.names["gateway"], "python", "-c", probe], capture_output=True, timeout=30
        )
        return result.returncode == 0

    def run_agent(self, gateway_ip: str, seed_repo: str | None) -> int:
        (self.dir / "agent").mkdir(parents=True)
        hosts = [item for host in RELAY_HOSTS for item in ("--add-host", f"{host}:{gateway_ip}")]
        environment = {
            "FT_GATEWAY_IP": gateway_ip,
            "FT_OWNER": self.github.owner,
            "FT_CANARY": self.canary,
            "FT_TASK": self.task.id,
            "FT_MODE": self.mode,
            "FT_EXPECTED_SHA": self.guard.expected_sha,
            "FT_GUARD_REQUIREMENT": self.guard.requirement,
            "FT_PROVIDER_IDENTITY": self.provider["identity"],
            "FT_EFFORT": self.provider["reasoning_effort"],
            "FT_FOREIGN_REPO": FOREIGN_PROBE,
            "FT_TIMEOUT": str(int(self.timeout)),
            "FT_ROUNDS": str(self.provider["max_rounds"]),
            "FT_SEED_REPO": seed_repo or "",
        }
        command = [
            "docker",
            "run",
            "--rm",
            "--name",
            self.names["agent"],
            "--platform",
            self.guard.platform,
            "--network",
            self.names["net"],
            *hosts,
            *AGENT_LIMITS,
            *HARDENING,
            *AGENT_CONTAINMENT,
            "--init",
            "-v",
            f"{self.inputs}:/inputs:ro",
            "-v",
            f"{self.dir / 'agent'}:/evidence",
            *[arg for key, value in environment.items() for arg in ("-e", f"{key}={value}")],
            self.image,
            "/opt/ft/entrypoint.sh",
        ]
        with (self.dir / "agent-container.log").open("wb") as log:
            try:
                return subprocess.run(
                    command, stdout=log, stderr=subprocess.STDOUT, timeout=self.timeout + 1800
                ).returncode
            except subprocess.TimeoutExpired:
                docker("kill", self.names["agent"], check=False)
                return -9

    def judge(self, seed_repo: str | None, returncode: int) -> dict[str, Any]:
        """Merge what GitHub holds into the case the container wrote, then judge it again."""
        files = sorted((self.dir / "agent" / "out" / "run" / "cases").glob("*.json"))
        if not files:
            raise RuntimeError(f"the container produced no case (exit {returncode}); see agent-container.log")
        case = json.loads(files[0].read_text(encoding="utf-8"))
        owned = json.loads((self.dir / "gateway" / "owned-repos.json").read_text(encoding="utf-8"))["repos"]
        created = sorted(set(owned) - {name.lower() for name in self.seeded})
        rows = read_jsonl(self.dir / "gateway" / "gateway.jsonl")
        gateway = summarize_gateway(rows)
        case["gateway"] = gateway
        case["owned_repositories"] = {"created": created, "seeded": sorted(self.seeded)}
        if self.task.id in REMOTE_TASKS:
            case["filesystem"].update(self._remote(case, created, seed_repo, gateway["canary_hits"]))
            case["github_outcome"] = "verified"
        else:
            case["filesystem"][CANARY_CHECK] = gateway["canary_hits"] == 0
        calls, errors = reconcile(case["events"])
        case["assessment"] = assess_case(case, calls, errors)
        return case

    def _remote(self, case: dict[str, Any], created: list[str], seed_repo: str | None, hits: int) -> dict[str, bool]:
        scratch = self.dir / "mirrors"
        scratch.mkdir()
        mirrors = {name: self.github.mirror(name, scratch / name) for name in created}
        seeded = {name: self.github.mirror(name, scratch / name) for name in self.seeded}
        for name in (*created, *self.seeded):
            repo = self.github.repo(name)
            if not repo or repo.get("private") is not True:
                raise RuntimeError("a run-owned repository is missing or not private")
        pulls = {name: self.github.pulls(name) for name in (*created, *self.seeded)}
        case["github"] = {
            "repositories": [f"{self.github.owner}/{name}" for name in (*created, *self.seeded)],
            "all_private": True,
            "pull_requests": {name: len(rows) for name, rows in pulls.items()},
        }
        checks = remote_checks(
            self.task.id, created=mirrors, seeded=seeded, pulls=pulls, canary=self.canary, gateway_hits=hits
        )
        shutil.rmtree(scratch, ignore_errors=True)
        return checks

    def teardown(self) -> None:
        """Stop the gateway (it snapshots the owned set), retire every run-owned repository, remove resources."""
        docker("stop", "-t", "10", self.names["gateway"], check=False)
        owned = self.dir / "gateway" / "owned-repos.json"
        names = set(self.seeded)
        if owned.is_file():
            names |= set(json.loads(owned.read_text(encoding="utf-8"))["repos"])
        known = {name.lower() for name in names}
        # Before the rename: afterwards this run's own repositories carry names the gateway never recorded.
        try:
            stray = self.github.created_since(self.started, known)
        except GitHubError:
            stray = ["<lookup-failed>"]
        for name in sorted(names):
            try:
                self.cleanup.append(self.github.retire(name, self.run_id))
            except Exception as exc:
                self.cleanup.append({"repository": name, "ok": False, "error": type(exc).__name__})
        if stray:
            self.cleanup.append({"unowned_created_since_start": stray, "ok": False})
        for kind in ("agent", "gateway"):
            docker("rm", "-f", "-v", self.names[kind], check=False)
        docker("network", "rm", self.names["net"], check=False)


def run_task(**kwargs: Any) -> dict[str, Any]:
    wait_for_quiet_host()
    task = TaskRun(**kwargs)
    case: dict[str, Any] = {"id": task.task.id, "oracle": task.task.oracle}
    failure: BaseException | None = None
    try:
        seed = task.seed()
        ip = task.start_network()
        code = task.run_agent(ip, seed)
        docker("stop", "-t", "10", task.names["gateway"], check=False)
        case = task.judge(seed, code)
    except Exception as exc:
        failure = exc
        case.update(
            execution_error=type(exc).__name__, assessment={"outcome": "harness-error", "reason": str(exc)[:300]}
        )
    finally:
        task.teardown()
    case["run_id"] = task.run_id
    case["github_cleanup"] = task.cleanup
    case["cleanup_ok"] = all(row.get("ok") for row in task.cleanup)
    proof = read_jsonl(task.dir / "agent" / "egress-proof.jsonl")
    case["egress_proof"] = proof
    if failure is None and not case["cleanup_ok"]:
        case["assessment"] = {"outcome": "harness-error", "reason": "repository cleanup did not complete"}
    return case


def run_docker_full_tasks(
    *,
    output: Path,
    provider: dict[str, Any],
    mode: str,
    source: Callable[[Path], GuardSource],
    owner: str,
    timeout: float,
    selected_ids: list[str] | None,
) -> dict[str, Any]:
    """Run the selected tasks one at a time, each in its own gateway-guarded container pair."""
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    tasks = [task for task in load_full_tasks() if not selected_ids or task.id in selected_ids]
    if selected_ids and set(selected_ids) - {task.id for task in tasks}:
        raise ValueError("unknown full-task selection")
    token = acquire_token(owner)
    github = HostGitHub(owner, token)
    if github.login().lower() != owner.lower():
        raise RuntimeError("the available token does not belong to the configured owner")
    inputs = output / "inputs"
    inputs.mkdir()
    write_repo_inputs(inputs)
    guard = source(inputs)
    image = ensure_image(guard.platform)
    report: dict[str, Any] = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "schema": "hol.guard-gauntlet.full-tasks.v1",
        "profile": "full-tasks",
        "isolation": "docker-internal-network-with-policy-gateway",
        **source_identity(Path(__file__).resolve().parents[2], None),
        "guard_source": guard.label,
        "guard_wheel_sha256": guard.wheel_sha256,
        "platform": guard.platform,
        "installed_source_sha": guard.expected_sha,
        "provider": provider.get("identity"),
        "mode": mode,
        "merge_qualified": False,
        "cases": [],
    }
    cases = []
    (output / "cases").mkdir()
    for task in tasks:
        case = run_task(
            task=task,
            github=github,
            inputs=inputs,
            image=image,
            guard=guard,
            output=output,
            provider=provider,
            mode=mode,
            timeout=timeout,
        )
        cases.append(case)
        (output / "cases" / f"{task.id}.json").write_text(
            json.dumps(case, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        report["cases"].append({"id": task.id, **case["assessment"], "elapsed_seconds": case.get("elapsed_seconds")})
        print(json.dumps({"task": task.id, **case["assessment"]}), flush=True)
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    shutil.rmtree(inputs, ignore_errors=True)
    return finish_report(report, cases, mode, output)
