from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.project_identity import is_portable_project_identity
from codex_plugin_scanner.guard.store import GuardStore
from tests.portable_identity_vector_cases import FIXTURE_PATH, SCHEMA, build_fixture, materialize

_NOW = "2026-10-14T12:00:00+00:00"


def _fixture() -> dict[str, object]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _case(case_id: str) -> dict[str, object]:
    cases = _fixture()["cases"]
    assert isinstance(cases, list)
    return next(case for case in cases if case["id"] == case_id)


def test_checked_in_vectors_match_the_python_resolver(tmp_path: Path) -> None:
    base = tmp_path.resolve()

    assert build_fixture(lambda case_id: base / case_id) == _fixture()


def test_vectors_cover_identities_absences_and_the_config_corpus() -> None:
    fixture = _fixture()
    cases = fixture["cases"]
    assert isinstance(cases, list)
    identities = [case["identity"] for case in cases]
    corpus = [case for case in cases if str(case["id"]).startswith("corpus_")]

    assert fixture["schema"] == SCHEMA
    assert len({case["id"] for case in cases}) == len(cases)
    assert len(corpus) == 60
    assert any(identity is None for identity in identities)
    assert all(identity is None or is_portable_project_identity(identity) for identity in identities)
    assert {case["identity"] is None for case in corpus} == {True, False}


@pytest.mark.parametrize("case_id", ["remote_https_github", "layout_git_two_levels_up"])
def test_the_saver_writes_the_vector_identity(tmp_path: Path, case_id: str) -> None:
    case = _case(case_id)
    workspace = materialize(case, (tmp_path / "tree").resolve())
    store = GuardStore(tmp_path / "guard-home")
    store.upsert_guard_session(
        session_id="session-vector",
        harness="codex",
        surface="cli",
        status="active",
        client_name="codex",
        client_title=None,
        client_version="test",
        workspace=str(workspace),
        capabilities=[],
        now=_NOW,
    )
    store.upsert_guard_operation(
        operation_id="operation-vector",
        session_id="session-vector",
        harness="codex",
        operation_type="tool_action",
        status="pending",
        approval_request_ids=["request-vector"],
        resume_token=None,
        metadata={"workspace_path": str(workspace)},
        now=_NOW,
    )

    operation = store.get_guard_operation_for_approval_request("request-vector")

    assert operation is not None
    metadata = operation["metadata"]
    assert isinstance(metadata, dict)
    assert case["identity"] is not None
    assert metadata["project_id"] == case["identity"]
