"""Fixed answer coverage and citation checks over actual public Guard documents."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_context_assistance import control, workspace
from codex_plugin_scanner.guard.native_resident_client import close_native_resident_clients, close_native_residents
from scripts.cigar_benchmark_processes import ProcessSampler
from tests.context_persistence_installed_support import agent, call, operator

REPO = Path(__file__).resolve().parents[1]
DOCUMENTS = ("runtime-controls.md", "agent-access.md")
QUESTIONS = (
    {
        "id": "separate-runtime",
        "query": "Runtime requirement: can Guard use a separate verified final CPython 3.14 environment, "
        "and do Python 3.15, prereleases, PyPy, debug or free-threaded builds qualify?",
        "facts": (
            "a separate verified Python 3.14 environment is valid",
            "Python 3.13, 3.15, prereleases, PyPy, debug and free-threaded builds do not qualify",
            "approved CIGAR 0.14.1 package and matching bundled worker",
        ),
    },
    {
        "id": "agent-authority",
        "query": "Connect an app: how does get_context_status pairing authorize an MCP process, "
        "can a dashboard grant authorize an agent, and does human_paired_mcp_process attest the app executable?",
        "facts": (
            "A dashboard grant cannot authorize an agent",
            "human_paired_mcp_process",
            "harness_route_qualification: not_established",
            "not a claim that Guard has attested that app's executable",
        ),
    },
    {
        "id": "safe-opt-out",
        "query": "End-user controls: what does Turn off now do to optional work and Guard approvals, "
        "and does opening Home or reading context status start or probe a runtime?",
        "facts": (
            "persists opt-out without clearing Guard approvals",
            "Opening Home reads status only; it does not start or probe a runtime",
            "no CIGAR probe, import or installation",
        ),
    },
)


def normalized(text: str) -> str:
    return " ".join(text.replace("`", "").replace("*", "").casefold().split())


def verify_citations(brief: dict, texts: dict[str, str]) -> list[dict]:
    sources = {"source:" + hashlib.sha256(name.encode()).hexdigest(): name for name in texts}
    verified = []
    for excerpt in brief["excerpts"]:
        for citation in excerpt["citations"]:
            name = sources.get(citation["source"])
            if name is None:  # Mandatory native scope facts are separate from selected documents.
                continue
            start, end = citation["start_line"], citation["end_line"]
            assert type(start) is int and type(end) is int and 1 <= start <= end
            actual = "".join(texts[name].splitlines(keepends=True)[start - 1 : end])
            assert actual == excerpt["text"], "selected citation must reproduce the actual document lines"
            verified.append({"document": name, "start_line": start, "end_line": end})
    assert verified, "the answer must cite an explicitly selected project document"
    return verified


@pytest.mark.integration
@pytest.mark.installed
@pytest.mark.skipif(
    sys.platform != "darwin"
    or os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") != "1"
    or not os.environ.get("GUARD_CIGAR_TEST_SELECTION")
    or not os.environ.get("GUARD_CIGAR_TEST_APPROVAL"),
    reason="requires the exact installed macOS Guard and approved CIGAR 0.14.1 candidate",
)
def test_actual_mcp_retrieval_covers_fixed_project_questions_with_verified_lines(
    native_hook_force: Path, tmp_path: Path
) -> None:
    root = tmp_path.resolve()
    guard, project = root / "guard", root / "project"
    guard.mkdir(mode=0o700)
    project.mkdir(mode=0o700)
    texts = {name: (REPO / "docs/guard/cigar-integration" / name).read_text() for name in DOCUMENTS}
    for name, text in texts.items():
        (project / name).write_text(text)
    canary = "UNGRANTED_USEFULNESS_CANARY"
    (project / "unselected.md").write_text(
        canary + ": fabricated unsupported-runtime and unrestricted-access advice.\n"
    )
    selection = json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text())
    report = {
        "schema": "guard-cigar-useful-project-docs-installed.v1",
        "completed": False,
        "sources": {
            name: {"sha256": hashlib.sha256(text.encode()).hexdigest(), "bytes": len(text.encode())}
            for name, text in texts.items()
        },
        "rubric": QUESTIONS,
        "answers": [],
        "model_calls": 0,
        "limitation": "Fixed source-fact coverage, not measured human/model accuracy, latency savings or model tokens.",
    }

    async def retrieve(scope: str) -> None:
        async with agent(guard) as client:
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
            for question in QUESTIONS:
                result = await call(client, "get_guard_context", {"query": question["query"]})
                assert result["ok"] and result["data_role"]
                prepared = result["data"]["result"]
                assert prepared["current"] and prepared["brief"]["data_role"]
                brief = prepared["brief"]
                coverage = {fact: normalized(fact) in normalized(brief["rendered"]) for fact in question["facts"]}
                answer = {
                    "id": question["id"],
                    "fact_coverage": coverage,
                    "brief": brief,
                    "rendered_bytes": len(brief["rendered"].encode()),
                    "selected_citations": verify_citations(brief, texts),
                }
                report["answers"].append(answer)
                assert canary not in brief["rendered"]
                assert all(coverage.values()), "the predeclared answer facts must all be available in context"
                explanation = await call(client, "explain_guard_context", {"snapshot_id": brief["snapshot_id"]})
                assert explanation["ok"] and explanation["data"]["result"]["current"]
            control("stop", guard_home=guard)
            refused = await call(client, "get_guard_context", {"query": QUESTIONS[0]["query"]})
            assert not refused["ok"] and refused["error"]["code"] == "native_context_assistance_disabled"
            report["cached_call_refused_after_stop"] = True

    with ProcessSampler(Path(selection["python"])) as sampler:
        _, baseline = sampler.sample_with_identities()
        try:
            assert control("status", guard_home=guard)["effective_enabled"] is False
            enrolled = operator(
                native_hook_force,
                "context-assistance-enroll-local",
                {
                    "schema": "guard-cigar-enroll-local.v1",
                    "guard_home": str(guard),
                    "runtime_id": "useful-docs-candidate",
                    "local_candidate_approved": True,
                    "source_revision": "b47380e5a5cbeaaad5a61cab3372e9e67368732f",
                    "selection": selection,
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
                                "runtime_id": "useful-docs-candidate",
                                "features": {"agent_context": True, "shared_agents": False, "execution_context": False},
                                "sources": {"workspace_documents": True, "source_set_id": "public-project-documents"},
                            }
                        }
                    ),
                },
            )
            assert updated["ok"]
            control("activate", guard_home=guard)
            deadline = time.monotonic() + 90
            while True:
                state = control("status", guard_home=guard)
                if state["job"] is None:
                    assert state["effective_enabled"] and state["runtime"]["compile_verified"]
                    break
                assert time.monotonic() < deadline, "actual selected runtime verification timed out"
                time.sleep(0.05)
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
            asyncio.run(retrieve(scope))
            revisions = {answer["brief"]["graph_revision"] for answer in report["answers"]}
            assert len(report["answers"]) == 3 and len(revisions) == 1
            report.update(completed=True, unchanged_graph_revision_reused=True, ungranted_document_excluded=True)
        finally:
            try:
                control("stop", guard_home=guard)
                assert close_native_residents(guard)
                assert close_native_resident_clients(guard, deadline_monotonic=time.monotonic() + 10)
                deadline = time.monotonic() + 5
                _, remaining = sampler.sample_with_identities()
                while remaining.keys() - baseline.keys() and time.monotonic() < deadline:
                    time.sleep(0.05)
                    _, remaining = sampler.sample_with_identities()
                report["new_processes_remaining"] = len(remaining.keys() - baseline.keys())
                report["resources"] = sampler.summary()
                assert report["new_processes_remaining"] == 0 and report["resources"]["sampling_errors"] == 0
                assert report["resources"]["maximum_counts"].get("sdk_worker", 0) >= 1
                assert report["resources"]["maximum_counts"].get("python_bridge", 0) >= 1
            finally:
                with (root / "useful-docs-report.json").open("x") as output:
                    json.dump(report, output, indent=2)
                    output.write("\n")
