"""Actual frozen CLI/MCP with a separately qualified CIGAR interpreter."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import get_default_environment, stdio_client

from codex_plugin_scanner.guard.native_context_assistance import workspace
from codex_plugin_scanner.guard.native_resident_client import close_native_resident_clients, close_native_residents
from scripts.cigar_benchmark_processes import ProcessSampler
from tests.context_frozen_daemon import FrozenDaemon
from tests.context_persistence_installed_support import call
from tests.test_context_useful_docs_installed import DOCUMENTS, QUESTIONS, normalized, verify_citations


@pytest.mark.integration
@pytest.mark.installed
@pytest.mark.parametrize("repetition", [1, 2, 3])
@pytest.mark.skipif(
    sys.platform != "darwin"
    or not os.environ.get("GUARD_CIGAR_TEST_FROZEN_ROOT")
    or not os.environ.get("GUARD_CIGAR_TEST_SELECTION")
    or not os.environ.get("GUARD_CIGAR_TEST_APPROVAL"),
    reason="requires the exact local frozen bundle and independently approved CIGAR candidate",
)
def test_frozen_cli_and_mcp_with_running_host_use_python_314_and_persist_opt_out(
    tmp_path: Path, monkeypatch, repetition: int
) -> None:
    frozen = Path(os.environ["GUARD_CIGAR_TEST_FROZEN_ROOT"]).resolve(strict=True)
    executable = frozen / "hol-guard"
    native = Path(
        os.environ.get(
            "GUARD_CIGAR_TEST_FROZEN_NATIVE_OPERATOR",
            str(frozen / "_internal/codex_plugin_scanner/_native/hol-guard-runtime"),
        )
    ).resolve(strict=True)
    root = tmp_path.resolve()
    guard, project, profile, temporary = (root / name for name in ("guard", "project", "profile", "tmp"))
    for directory in (guard, project, profile, temporary):
        directory.mkdir(mode=0o700)
    environment = {
        "HOME": str(profile),
        "TMPDIR": str(temporary),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
        "LANG": "en_US.UTF-8",
    }
    repo = Path(__file__).resolve().parents[1]
    texts = {name: (repo / "docs/guard/cigar-integration" / name).read_text() for name in DOCUMENTS}
    for name, text in texts.items():
        (project / name).write_text(text)
    selection = json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text())
    approval = json.loads(Path(os.environ["GUARD_CIGAR_TEST_APPROVAL"]).read_text())
    report = {
        "schema": "guard-cigar-frozen-context-installed.v1",
        "fixed_fresh_profile_repetition": repetition,
        "completed": False,
        "frozen_application_environment_keys": sorted(environment),
        "application_native_mode": "auto; no native/test/SDK path override",
        "operator_transport": (
            "installed thin Python IPC explicitly selects verified native bytes from the frozen artifact"
        ),
        "frozen_entry_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "bundled_native_sha256": hashlib.sha256(native.read_bytes()).hexdigest(),
        "sources": {name: hashlib.sha256(text.encode()).hexdigest() for name, text in texts.items()},
        "answers": [],
        "external_model_calls": 0,
        "persistent_frozen_daemon_requested": os.environ.get("GUARD_CIGAR_TEST_FROZEN_HOST", "daemon") == "daemon",
    }

    def cli(action: str) -> dict:
        result = subprocess.run(
            [str(executable), "context", action, "--guard-home", str(guard), "--json"],
            cwd=project,
            env=environment,
            capture_output=True,
            text=True,
            timeout=45,
        )
        for line in result.stderr.splitlines():
            if line.startswith("GUARD_CIGAR_NATIVE_DIAGNOSTIC="):
                diagnostic = json.loads(line.split("=", 1)[1])
                fields = {"schema", "status_calls", "resident_failure_code"}
                if diagnostic["schema"] == "guard-cigar-native-transport-observation.v2":
                    fields.add("request_calls")
                else:
                    assert diagnostic["schema"] == "guard-cigar-native-transport-observation.v1"
                assert set(diagnostic) == fields
                report.setdefault("native_transport_observations", []).append({"action": action, "data": diagnostic})
        assert result.returncode == 0, f"frozen context {action} failed: {result.stdout} {result.stderr}"
        return json.loads(result.stdout)

    def operator(command: str, request: dict) -> dict:
        result = subprocess.run(
            [str(native), command, "--stdin"],
            input=json.dumps(request),
            cwd=project,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, "bundled native operator request failed"
        value = json.loads(result.stdout)
        assert value["ok"]
        return value

    async def exercise(scope: str) -> None:
        effective_environment = {**get_default_environment(), **environment}
        assert not any(
            key.startswith("HOL_GUARD_") or key in {"PYTHONPATH", "PYTHONHOME"} for key in effective_environment
        )
        report["frozen_mcp_effective_environment_keys"] = sorted(effective_environment)
        parameters = StdioServerParameters(
            command=str(executable),
            args=["mcp", "serve", "--stdio", "--guard-home", str(guard)],
            env=environment,
            cwd=str(project),
        )
        with (root / "frozen-mcp.stderr.log").open("x") as errors:
            async with stdio_client(parameters, errlog=errors) as (read, write), ClientSession(read, write) as client:
                initialized = await client.initialize()
                assert initialized.capabilities.tools.listChanged
                pending = await call(client, "get_context_status")
                assert pending["data"]["phase"] == "pending"
                workspace(
                    "workspace_grant",
                    guard_home=guard,
                    payload={
                        "action": "authorize_agent",
                        "session_id": pending["data"]["session_id"],
                        "scope_id": scope,
                    },
                )
                assert (await call(client, "get_context_status"))["data"]["phase"] == "authorized"
                names = {tool.name for tool in (await client.list_tools()).tools}
                optional = {"get_context_status", "get_guard_context", "explain_guard_context", "explain_guard_action"}
                base = names - optional
                assert len(base) >= 6 and {"get_guard_context", "explain_guard_context"} <= names
                for question in QUESTIONS:
                    response = await call(client, "get_guard_context", {"query": question["query"]})
                    assert response["ok"] and response["data_role"]
                    result = response["data"]["result"]
                    assert result["current"] and result["brief"]["data_role"]
                    brief = result["brief"]
                    coverage = {fact: normalized(fact) in normalized(brief["rendered"]) for fact in question["facts"]}
                    report["answers"].append(
                        {
                            "id": question["id"],
                            "coverage": coverage,
                            "brief": brief,
                            "citations": verify_citations(brief, texts),
                        }
                    )
                    assert all(coverage.values())
                    explanation = await call(client, "explain_guard_context", {"snapshot_id": brief["snapshot_id"]})
                    assert explanation["ok"] and explanation["data"]["result"]["current"]
                off = cli("off")
                assert not off["requested_enabled"] and not off["effective_enabled"]
                assert {tool.name for tool in (await client.list_tools()).tools} == base
                refused = await call(client, "get_guard_context", {"query": QUESTIONS[0]["query"]})
                assert not refused["ok"] and refused["error"]["code"] == "native_context_assistance_disabled"
                report.update(base_tools_remain_available=True, cached_context_refused=True, persisted_opt_out=True)

    with ProcessSampler(Path(selection["python"])) as sampler:
        _, baseline = sampler.sample_with_identities()
        daemon = None
        try:
            if report["persistent_frozen_daemon_requested"]:
                daemon = FrozenDaemon(executable, root, guard, project, environment)
                daemon.wait_ready()
                report["persistent_frozen_daemon_ready"] = True
            before = cli("status")
            assert before["availability"] == "off" and before["runtime"] is None
            observed_off = sampler.sample()
            assert not any(observed_off["counts"].get(kind, 0) for kind in ("sdk_worker", "python_bridge"))
            report["off_has_no_observed_optional_worker"] = True
            enrolled = operator(
                "context-assistance-enroll-local",
                {
                    "schema": "guard-cigar-enroll-local.v1",
                    "guard_home": str(guard),
                    "runtime_id": "frozen-candidate",
                    "local_candidate_approved": True,
                    "source_revision": "b47380e5a5cbeaaad5a61cab3372e9e67368732f",
                    "selection": selection,
                    "approval": approval,
                },
            )
            assert not enrolled["installation"]["activation_granted"]
            operator(
                "guard-config-update",
                {
                    "schema": "guard-config-update.v1",
                    "guard_home": str(guard),
                    "kind": "settings",
                    "value_text": json.dumps(
                        {
                            "context_assistance": {
                                "enabled": True,
                                "runtime_id": "frozen-candidate",
                                "features": {"agent_context": True},
                                "sources": {"workspace_documents": True, "source_set_id": "frozen-selected-documents"},
                            }
                        }
                    ),
                },
            )
            choices = cli("runtimes")["installation_options"]
            assert choices[0]["runtime_id"] == "frozen-candidate" and selection["site_packages"] not in json.dumps(
                choices
            )
            report["activation_accepted"] = cli("start")
            deadline = time.monotonic() + 90
            while True:
                state = cli("status")
                report["activation_status"] = state
                if state["job"] is None:
                    assert state["effective_enabled"] and state["runtime"]["compile_verified"], (
                        state["availability"],
                        state["diagnostic"],
                    )
                    assert state["runtime"]["interpreter"]["version"][:2] == [3, 14]
                    assert state["runtime"]["worker_fingerprint"] == approval["worker_sha256"]
                    report["selected_interpreter"] = state["runtime"]["interpreter"]
                    break
                assert time.monotonic() < deadline, "frozen runtime verification timed out"
            # Only operator IPC in this pytest process uses explicit selection.
            # Both frozen application routes retain the minimal environment above.
            monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
            monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(native))
            scope = workspace(
                "workspace_grant",
                guard_home=guard,
                payload={
                    "action": "grant",
                    "workspace": str(project),
                    "app": "codex",
                    "sources": list(DOCUMENTS),
                },
            )["result"]["scope_id"]
            asyncio.run(exercise(scope))
            after = cli("status")
            assert not after["requested_enabled"] and not after["effective_enabled"] and after["runtime"] is None
            assert len({answer["brief"]["graph_revision"] for answer in report["answers"]}) == 1
            report["completed"] = True
        finally:
            try:
                try:
                    try:
                        cli("off")
                    finally:
                        try:
                            monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
                            monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(native))
                            resident_closed = close_native_residents(guard)
                            clients_closed = close_native_resident_clients(
                                guard, deadline_monotonic=time.monotonic() + 10
                            )
                            report.update(resident_closed=resident_closed, clients_closed=clients_closed)
                        finally:
                            if daemon is not None:
                                try:
                                    daemon.stop()
                                finally:
                                    report["frozen_daemon_exit"] = daemon.exit_metadata()
                finally:
                    # A failed Stop must retain observations before assertions.
                    deadline = time.monotonic() + 5
                    _, remaining = sampler.sample_with_identities()
                    while remaining.keys() - baseline.keys() and time.monotonic() < deadline:
                        time.sleep(0.05)
                        _, remaining = sampler.sample_with_identities()
                    report["new_processes_remaining"] = len(remaining.keys() - baseline.keys())
                    report["resources"] = sampler.summary()
                assert resident_closed and clients_closed
                assert report["new_processes_remaining"] == 0 and report["resources"]["sampling_errors"] == 0
                assert report["resources"]["maximum_counts"].get("sdk_worker", 0) >= 1
                assert report["resources"]["maximum_counts"].get("python_bridge", 0) >= 1
                if daemon is not None:
                    assert not daemon.fallback_used
                    assert report["frozen_daemon_exit"]["graceful_zero_exit"], report["frozen_daemon_exit"]
            finally:
                with (root / "frozen-context-report.json").open("x") as output:
                    json.dump(report, output, indent=2)
                    output.write("\n")
