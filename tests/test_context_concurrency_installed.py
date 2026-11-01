"""Real independent MCP clients, bounded overload and shared-source currentness.

Functional contention evidence, not a latency or memory benchmark. All setup,
sources and authority live in disposable test-owned profiles.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections import Counter
from contextlib import AsyncExitStack, ExitStack
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_context_assistance import ContextAssistanceError, workspace
from codex_plugin_scanner.guard.native_resident_client import close_native_resident_clients
from scripts.cigar_benchmark_processes import ProcessSampler
from tests.context_persistence_installed_support import Host, agent, call, operator, stop_resident

_BUSY = {"native_context_assistance_busy", "native_context_assistance_context_busy"}
_CAPACITY = "native_context_assistance_context_resource_limit"


@pytest.mark.integration
@pytest.mark.installed
@pytest.mark.skipif(
    os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") != "1"
    or not os.environ.get("GUARD_CIGAR_TEST_SELECTION")
    or not os.environ.get("GUARD_CIGAR_TEST_APPROVAL"),
    reason="requires the explicitly approved installed CIGAR candidate and independent MCP processes",
)
def test_five_shared_clients_source_churn_and_twelve_attempts_obey_native_limits(
    native_hook_force, tmp_path, *, source_update_rounds: int = 1, source_update_interval: int = 0
):
    assert (source_update_rounds, source_update_interval) in {(1, 0), (12, 15)}
    root = tmp_path.resolve()
    guard, project = root / "guard", root / "workspace"
    for directory in (guard, project, root / "profile"):
        directory.mkdir(mode=0o700)
    (root / "fixture-owned").write_text("guard-cigar-restart-fixture.v1\n")
    document = project / "README.md"
    first_text = "SHARED_REVISION_ONE: release requires a reviewed deployment checklist."
    second_text = "SHARED_REVISION_TWO: release requires an independently verified rollback checklist."
    document.write_text(first_text + "\n")
    metrics = {"schema": "guard-cigar-mcp-concurrency.v1", "read_busy_refusals": Counter(), "phases": [], "waves": []}
    metrics["source_update_rounds"] = source_update_rounds
    metrics["source_update_interval_seconds"] = source_update_interval
    metrics["source_updates"] = []
    metrics["completed"] = False
    sampler = None

    def host(action, **fields):
        kind = "workspace_grant" if action in {"grant", "authorize_agent", "admit_proposal"} else "workspace_access"
        if action in {"list", "list_agents", "compile"}:
            kind = "workspace"
        return workspace(kind, guard_home=guard, payload={"action": action, **fields})["result"]

    async def read(client, name, arguments=None):
        # Retry only an explicit bounded read refusal, never an unknown SDK
        # outcome, begin, pairing, proposal or source mutation.
        for attempt in range(8):
            result = await call(client, name, arguments)
            if result.get("ok") or result.get("error", {}).get("code") not in _BUSY:
                return result
            metrics["read_busy_refusals"][result["error"]["code"]] += 1
            await asyncio.sleep((attempt + 1) * 0.025)
        raise AssertionError("an independent context reader starved after bounded busy refusals")

    async def compile_all(clients, expected, forbidden):
        replies = [None] * len(clients)
        pending = list(range(len(clients)))
        for wave in range(6):
            started = time.monotonic()
            values = await asyncio.gather(
                *(call(clients[index], "get_guard_context", {"query": "release checklist"}) for index in pending),
                return_exceptions=True,
            )
            refused = []
            errors = []
            unexpected = []
            for index, value in zip(pending, values, strict=True):
                if isinstance(value, BaseException):
                    errors.append(type(value).__name__)
                elif value["ok"]:
                    replies[index] = value
                else:
                    code = value["error"]["code"]
                    if code in _BUSY:
                        metrics["read_busy_refusals"][code] += 1
                        refused.append(index)
                    else:
                        unexpected.append(code)
            metrics["waves"].append(
                {
                    "wave": wave + 1,
                    "attempted": len(pending),
                    "busy": len(refused),
                    "seconds": round(time.monotonic() - started, 3),
                    "errors": errors,
                    "unexpected_codes": unexpected,
                }
            )
            assert not errors, "a concurrent SDK read failed before a classified outcome"
            assert not unexpected, f"a concurrent read returned unexpected outcomes: {unexpected}"
            pending = refused
            if not pending:
                break
            await asyncio.sleep((wave + 1) * 0.05)
        assert not pending, "some readers never progressed across six completed waves"
        for reply in replies:
            assert reply is not None
            assert reply["ok"], reply.get("error")
            value = reply["data"]["result"]
            assert value["current"] and value["brief"]["data_role"]
            assert value["brief"]["citations"]
            assert expected in value["brief"]["rendered"] and forbidden not in value["brief"]["rendered"]
        return replies

    async def pair(client, scope):
        pending = await read(client, "get_context_status")
        assert pending["ok"] and pending["data"]["phase"] == "pending", pending.get("error")
        assert "credential" not in json.dumps(pending)
        session = pending["data"]["session_id"]
        host("authorize_agent", scope_id=scope, session_id=session)
        state = await read(client, "get_context_status")
        assert state["ok"] and state["data"]["phase"] == "authorized"
        assert state["data"]["harness_route_qualification"] == "not_established"
        return session

    async def scenario():
        nonlocal second_text
        daemon = Host(root, 1)
        try:
            enrolled = operator(
                native_hook_force,
                "context-assistance-enroll-local",
                {
                    "schema": "guard-cigar-enroll-local.v1",
                    "guard_home": str(guard),
                    "runtime_id": "concurrent-candidate",
                    "local_candidate_approved": True,
                    "source_revision": "b47380e5a5cbeaaad5a61cab3372e9e67368732f",
                    "selection": json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text()),
                    "approval": json.loads(Path(os.environ["GUARD_CIGAR_TEST_APPROVAL"]).read_text()),
                },
            )
            assert enrolled["ok"] and not enrolled["installation"]["activation_granted"]
            updated = operator(
                native_hook_force,
                "guard-config-update",
                {
                    "schema": "guard-config-update.v1",
                    "guard_home": str(guard),
                    "kind": "settings",
                    "value_text": json.dumps(
                        {
                            "context_assistance": {
                                "enabled": True,
                                "runtime_id": "concurrent-candidate",
                                "features": {"agent_context": True, "shared_agents": True, "execution_context": True},
                                "sources": {
                                    "workspace_documents": True,
                                    "sanitized_receipt_facts": False,
                                    "source_set_id": "concurrency-synthetic-source",
                                },
                                "storage": {"mode": "sqlite", "retention_hours": 1},
                            }
                        }
                    ),
                },
            )
            assert updated["ok"]
            state = await daemon.activate()
            assert state["execution_ready"] and state["runtime"]["execution_handoff_verified"]
            scope = host(
                "grant",
                workspace=str(project),
                app="codex",
                sources=["README.md"],
                shared_notes={"read": True, "propose": True},
            )["scope_id"]
            # Include the operator's actual SDK view in the finite global
            # client budget before testing independently paired connections.
            assert host("compile", scope_id=scope, query="release checklist")["current"]
            async with AsyncExitStack() as clients_stack:
                clients, sessions = [], []
                for _ in range(5):
                    client = await clients_stack.enter_async_context(agent(guard))
                    sessions.append(await pair(client, scope))
                    clients.append(client)
                one = await read(clients[0], "get_guard_context", {"query": "release checklist"})
                assert one["ok"] and first_text in one["data"]["result"]["brief"]["rendered"]
                foreign = await read(
                    clients[1],
                    "explain_guard_context",
                    {
                        "snapshot_id": one["data"]["result"]["brief"]["snapshot_id"],
                    },
                )
                assert (
                    not foreign["ok"] and foreign["error"]["code"] == "native_context_assistance_context_scope_denied"
                )
                old = await compile_all(clients, first_text, second_text)
                metrics["phases"].append(
                    {
                        "clients": 5,
                        "current_contexts": len(old),
                        "distinct_graph_revisions": len({r["data"]["result"]["brief"]["graph_revision"] for r in old}),
                    }
                )
                previous, previous_text = old, first_text
                churn_started = time.monotonic()
                for revision in range(source_update_rounds):
                    mark = sampler.checkpoint() if sampler is not None else None
                    await asyncio.sleep(source_update_interval)
                    second_text = (
                        "SHARED_REVISION_TWO: release requires an independently verified rollback checklist."
                        if revision == 0
                        else f"SHARED_REVISION_{revision + 2:03}: release requires reviewed rollback check {revision}."
                    )
                    document.write_text(second_text + "\n")
                    for client, selection in zip(clients, previous, strict=True):
                        stale = await read(
                            client,
                            "explain_guard_context",
                            {"snapshot_id": selection["data"]["result"]["brief"]["snapshot_id"]},
                        )
                        assert not stale["ok"] and stale["error"]["code"] == "native_context_assistance_context_stale"
                    host("refresh", scope_id=scope)
                    fresh = await compile_all(clients, second_text, previous_text)
                    revisions = {reply["data"]["result"]["brief"]["graph_revision"] for reply in fresh}
                    assert len(revisions) == 1
                    assert all(
                        a["data"]["result"]["brief"]["graph_revision"] != b["data"]["result"]["brief"]["graph_revision"]
                        for a, b in zip(previous, fresh, strict=True)
                    )
                    update = {"round": revision + 1, "current_clients": len(fresh), "distinct_graph_revisions": 1}
                    if sampler is not None:
                        sampler.sample()
                        update["observed_tree_memory"] = sampler.summary(mark)
                    metrics["source_updates"].append(update)
                    previous, previous_text = fresh, second_text
                metrics["source_update_seconds"] = round(time.monotonic() - churn_started, 3)
                assert metrics["source_update_seconds"] >= source_update_rounds * source_update_interval
                for client, previous in zip(clients, old, strict=True):
                    stale = await read(
                        client,
                        "explain_guard_context",
                        {
                            "snapshot_id": previous["data"]["result"]["brief"]["snapshot_id"],
                        },
                    )
                    assert not stale["ok"], "refresh cannot revive an old selection"
                capacity_refusals = 0
                refused_clients = []
                for _ in range(7):
                    client = await clients_stack.enter_async_context(agent(guard))
                    pending = await read(client, "get_context_status")
                    if not pending["ok"]:
                        assert pending["error"]["code"] == _CAPACITY, pending["error"]
                        capacity_refusals += 1
                        refused_clients.append(client)
                        continue
                    session = pending["data"]["session_id"]
                    try:
                        host("authorize_agent", scope_id=scope, session_id=session)
                    except ContextAssistanceError as error:
                        assert error.code == _CAPACITY
                        capacity_refusals += 1
                        refused_clients.append(client)
                    else:
                        clients.append(client)
                        sessions.append(session)
                # Eight SDK client slots include this private execution lane
                # and the operator view, leaving six paired agent clients.
                assert len(clients) == 6 and capacity_refusals == 6
                active = host("list_agents")["agent_sessions"]
                assert len(active) == 6 and all(row["phase"] == "authorized" for row in active)
                assert "credential" not in json.dumps(active)
                for client in refused_clients:
                    denied = await read(client, "get_guard_context", {"query": "release checklist"})
                    assert not denied["ok"], "capacity refusal cannot leave usable source authority"
                await compile_all(clients, second_text, first_text)
                assert host("compile", scope_id=scope, query="rollback checklist")["current"]
                metrics["phases"].append(
                    {
                        "attempted_connections": 12,
                        "authorized": len(clients),
                        "capacity_refusals": capacity_refusals,
                        "native_sessions_after_refusals": len(active),
                    }
                )
                victim, victim_id = clients.pop(0), sessions.pop(0)
                host("revoke_agent", session_id=victim_id)
                refused = await read(victim, "get_guard_context", {"query": "release"})
                assert not refused["ok"], "cached tools cannot cross individual revocation"
                replacement = await clients_stack.enter_async_context(agent(guard))
                replacement_id = await pair(replacement, scope)
                assert replacement_id != victim_id
                clients.append(replacement)
                sessions.append(replacement_id)
                await compile_all(clients, second_text, first_text)
                host("revoke", scope_id=scope)
                for client in clients:
                    assert not (await read(client, "get_guard_context", {"query": "release"}))["ok"]
                code, off = daemon.request("/stop", {})
                assert code == 200 and not off["effective_enabled"]
                assert not off["requested_enabled"]
                metrics["revoke_reuse_and_global_stop"] = True
                metrics["raw_content_or_credentials_written"] = False
        finally:
            try:
                daemon.stop()
            finally:
                stop_resident(native_hook_force, guard)
                # Check our own teardown before pytest's later fixture hook.
                # Keep clients/reapers alive until Rust acknowledges Stop.
                assert close_native_resident_clients(guard, deadline_monotonic=time.monotonic() + 10)

    started = time.monotonic()
    try:
        with ExitStack() as resources:
            selected = Path(json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text())["python"])
            sampler = resources.enter_context(ProcessSampler(selected))
            baseline, baseline_identities = sampler.sample_with_identities()
            metrics["observed_processes_before_fixture"] = baseline
            metrics["process_containment_boundary"] = "no new live descendant identities; baseline remains in all RSS"
            assert not any(
                baseline["counts"].get(kind, 0) for kind in ("sdk_worker", "python_bridge", "selected_python")
            )
            try:
                asyncio.run(asyncio.wait_for(scenario(), timeout=240 + source_update_rounds * source_update_interval))
            finally:
                if sampler is not None:
                    metrics["all_observed_processes"] = sampler.summary()
            if sampler is not None:
                deadline = time.monotonic() + 5
                final, identities = sampler.sample_with_identities()
                while identities.keys() - baseline_identities.keys() and time.monotonic() < deadline:
                    time.sleep(0.1)
                    final, identities = sampler.sample_with_identities()
                metrics["observed_processes_at_end"] = final
                metrics["new_process_counts_at_end"] = dict(
                    Counter(kind for identity, kind in identities.items() if identity not in baseline_identities)
                )
                metrics["all_observed_processes"] = sampler.summary()
                assert not metrics["new_process_counts_at_end"]
                assert sampler.errors == 0
            metrics["completed"] = True
    finally:
        metrics["seconds"] = round(time.monotonic() - started, 3)
        with (root / "concurrency-metrics.json").open("x") as output:
            json.dump(metrics, output, indent=2)
            output.write("\n")
