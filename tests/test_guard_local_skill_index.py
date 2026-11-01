from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.runtime import local_skill_index
from codex_plugin_scanner.guard.runtime.local_skill_index import (
    LocalSkillRecord,
    approved_skill_roots,
    index_local_skills,
    inspect_indexed_skill,
    public_skill_page,
)
from codex_plugin_scanner.guard.store import GuardStore

_METADATA: dict[str, object] = {
    "name": "report",
    "description": "Prepare a report.",
    "compatibility": None,
    "requested_tools": None,
    "metadata_digest": "a" * 64,
    "requirements_complete": False,
    "instruction_content_loaded": False,
    "dependencies": [],
}
_IDENTITY: dict[str, object] = {
    "status": "complete",
    "manifest_digest": "sha256:" + "b" * 64,
    "entry_count": 2,
    "total_bytes": 40,
    "reason": None,
}


def _skill(root: Path, name: str = "report", *, frontmatter: str = "", body: str = "PRIVATE INSTRUCTIONS") -> Path:
    directory = root / name
    directory.mkdir(parents=True)
    document = directory / "SKILL.md"
    document.write_text(f"---\nname: {name}\ndescription: Prepare a report.\n{frontmatter}---\n{body}\n")
    return document


def test_metadata_only_index_keeps_duplicate_origins_and_never_executes(tmp_path: Path):
    home = tmp_path / "home"
    roots = approved_skill_roots(home)
    chosen = dict(list(roots.items())[1:3])
    for root in chosen.values():
        document = _skill(root, frontmatter="allowed-tools: '*'\n")
        script = document.parent / "scripts" / "run.py"
        script.parent.mkdir()
        script.write_text(f"open({str(tmp_path / 'executed')!r}, 'w').close()")
    records, issues = index_local_skills(chosen, home=home, cancel=threading.Event())
    assert not issues
    assert len(records) == 2
    page = public_skill_page(records, offset=0, search="report")
    assert page["permissions_granted"] is False
    assert all(skill["duplicate_name"] and skill["permission_state"] == "not-granted" for skill in page["skills"])
    assert len({skill["uri"] for skill in page["skills"]}) == 2
    assert "PRIVATE INSTRUCTIONS" not in str(page)
    assert not (tmp_path / "executed").exists()
    assert all(record.metadata["requirements_complete"] is False for record in records.values())


def test_symlink_roots_and_documents_are_explicit_gaps(tmp_path: Path):
    home = tmp_path / "home"
    root = home / ".agents" / "skills"
    outside = tmp_path / "outside"
    document = _skill(outside)
    root.parent.mkdir(parents=True)
    root.symlink_to(outside, target_is_directory=True)
    records, issues = index_local_skills({"root": root}, home=home, cancel=threading.Event())
    assert not records
    assert issues == [{"root_id": "root", "reason": "linked-root-not-indexed"}]
    safe = home / ".codex" / "skills"
    skill = safe / "report"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").symlink_to(document)
    records, issues = index_local_skills({"safe": safe}, home=home, cancel=threading.Event())
    assert not records
    assert issues == [{"root_id": "safe", "reason": "linked-skill-not-indexed"}]


@pytest.mark.parametrize(
    "header,reason",
    [
        ("name: replaced\n", "metadata-invalid-frontmatter"),
        ("compatibility: !!python/object/apply:os.system ['echo unsafe']\n", "metadata-invalid-frontmatter"),
        ("description: duplicate\n", "metadata-invalid-frontmatter"),
        ("compatibility: " + "x" * 501 + "\n", "metadata-invalid-compatibility"),
        ("# " + "x" * 20_000 + "\n", "metadata-frontmatter-limit"),
    ],
)
def test_malformed_or_over_limit_metadata_is_an_issue(tmp_path: Path, header: str, reason: str):
    root = tmp_path / "skills"
    _skill(root, frontmatter=header)
    records, issues = index_local_skills({"root": root}, home=tmp_path, cancel=threading.Event())
    assert not records
    assert issues == [{"root_id": "root", "reason": reason}]


def test_an_unavailable_runtime_reports_every_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(local_skill_index, "_skill_index_answer", lambda *_args, **_kwargs: None)
    roots = {"a": tmp_path / "a", "b": tmp_path / "b"}
    records, issues = index_local_skills(roots, home=tmp_path, cancel=threading.Event())
    assert not records
    assert issues == [
        {"root_id": "a", "reason": "skill-index-unavailable"},
        {"root_id": "b", "reason": "skill-index-unavailable"},
    ]


@pytest.mark.parametrize("relative", ["/etc/passwd", "../outside/SKILL.md", "a//SKILL.md", "./SKILL.md"])
def test_runtime_records_outside_their_root_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str):
    record = {"root_id": "root", "document_hex": relative.encode().hex(), "metadata": _METADATA}
    monkeypatch.setattr(
        local_skill_index, "_skill_index_answer", lambda *_args, **_kwargs: {"records": [record], "issues": []}
    )
    records, issues = index_local_skills({"root": tmp_path}, home=tmp_path, cancel=threading.Event())
    assert not records
    assert issues == [{"root_id": "root", "reason": "metadata-unreadable"}]


def test_a_cancelled_scan_stops_before_its_next_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cancel = threading.Event()
    requested: list[object] = []

    def fake_answer(request: dict[str, object], **_kwargs: object) -> dict[str, object]:
        requested.append(request["roots"])
        cancel.set()
        return {"records": [], "issues": []}

    monkeypatch.setattr(local_skill_index, "_skill_index_answer", fake_answer)
    roots = {"a": tmp_path / "a", "b": tmp_path / "b"}
    assert index_local_skills(roots, home=tmp_path, cancel=cancel) == ({}, [])
    assert requested == [[{"root_id": "a", "root_hex": str(tmp_path / "a").encode().hex()}]]


@pytest.mark.parametrize(
    "record",
    [
        {"root_id": ["root"], "document_hex": b"a/SKILL.md".hex(), "metadata": _METADATA},
        {"root_id": "root", "document_hex": b"a/SKILL.md".hex(), "metadata": {**_METADATA, "name": 7}},
        {"root_id": "root", "document_hex": b"a/SKILL.md".hex(), "metadata": {**_METADATA, "description": None}},
        {"root_id": "root", "document_hex": b"a/SKILL.md".hex(), "metadata": {**_METADATA, "metadata_digest": "x"}},
        {"root_id": "root", "document_hex": b"a/SKILL.md".hex(), "metadata": {**_METADATA, "uri": "file:///etc"}},
        {"root_id": "root", "document_hex": b"a/SKILL.md".hex(), "metadata": {"name": "report"}},
    ],
)
def test_malformed_runtime_records_are_issues(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, record: object):
    issue = {"root_id": [], "reason": "metadata-unreadable"}
    monkeypatch.setattr(
        local_skill_index, "_skill_index_answer", lambda *_args, **_kwargs: {"records": [record], "issues": [issue]}
    )
    records, issues = index_local_skills({"root": tmp_path}, home=tmp_path, cancel=threading.Event())
    assert not records
    assert issues == [{"root_id": "root", "reason": "metadata-unreadable"}]


@pytest.mark.parametrize(
    "change",
    [
        {"status": "granted"},
        {"status": 1},
        {"manifest_digest": 7},
        {"manifest_digest": "b" * 64},
        {"entry_count": -1},
        {"entry_count": True},
        {"total_bytes": "40"},
        {"reason": ["changed"]},
    ],
)
def test_malformed_identity_answers_are_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: dict[str, object]
):
    record = LocalSkillRecord("id", "root", tmp_path / "a" / "SKILL.md", tmp_path, _METADATA)
    monkeypatch.setattr(local_skill_index, "_skill_index_answer", lambda *_a, **_k: {"identity": _IDENTITY})
    assert inspect_indexed_skill(record, home=tmp_path)["manifest_digest"] == _IDENTITY["manifest_digest"]
    monkeypatch.setattr(
        local_skill_index, "_skill_index_answer", lambda *_a, **_k: {"identity": {**_IDENTITY, **change}}
    )
    with pytest.raises(OSError, match="skill-inspection-unavailable"):
        inspect_indexed_skill(record, home=tmp_path)


def test_lazy_directory_identity_changes_with_supporting_file_without_grants(tmp_path: Path):
    home = tmp_path / "home"
    root = home / ".agents" / "skills"
    document = _skill(root)
    supporting = document.parent / "reference.md"
    supporting.write_text("first reference")
    records, issues = index_local_skills({"root": root}, home=home, cancel=threading.Event())
    assert not issues
    record = next(iter(records.values()))
    first = inspect_indexed_skill(record, home=home)
    supporting.write_text("changed reference")
    second = inspect_indexed_skill(record, home=home)
    assert first["status"] == second["status"] == "complete"
    assert first["manifest_digest"] != second["manifest_digest"]
    assert first["permissions_granted"] is False
    assert second["runtime_checks_required"] is True
    document.write_text(document.read_text().replace("Prepare a report.", "Changed requirements."))
    with pytest.raises(ValueError, match="skill-metadata-changed"):
        inspect_indexed_skill(record, home=home)


def test_skill_api_requires_exact_root_selection_and_pages_consistently(tmp_path: Path, monkeypatch):
    home = tmp_path / "operator-home"
    root = home / ".agents" / "skills"
    for index in range(55):
        _skill(root, name=f"report-{index}")
    monkeypatch.setattr(Path, "home", lambda: home)
    store = GuardStore(tmp_path / "guard-home")
    api = LocalCliApiService(store=store)
    try:
        assert api.skills({})["known_count"] == 0
        roots = api.skills({"operation": "roots"})["roots"]
        root_id = next(row["root_id"] for row in roots if row["path"] == str(root))
        for selected in (None, [], ["/etc"], [root_id, root_id], [{"path": str(root)}]):
            with pytest.raises(LocalCliApiError):
                api.skills({"operation": "scan", "confirm_metadata_read": True, "approved_root_ids": selected})
        with pytest.raises(LocalCliApiError):
            api.skills({"operation": "scan", "approved_root_ids": [root_id]})
        assert api.skills({})["known_count"] == 0
        job = api.skills({"operation": "scan", "confirm_metadata_read": True, "approved_root_ids": [root_id]})
        deadline = time.monotonic() + 3
        while api.refresh_job({"job_id": job["job_id"]})["state"] == "running" and time.monotonic() < deadline:
            time.sleep(0.01)
        assert api.refresh_job({"job_id": job["job_id"]})["state"] == "complete"
        first = api.skills({})
        assert first["complete"] is True
        assert len(first["skills"]) == 50
        assert first["next_offset"] == 50
        assert len(api.skills({"offset": 50, "revision": first["revision"]})["skills"]) == 5
        with pytest.raises(LocalCliApiError, match="Skill metadata changed"):
            api.skills({"offset": 50, "revision": 0})
        assert store.read_local_cli_revision() == 0
        assert "PRIVATE INSTRUCTIONS" not in str(first)
        skill_id = first["skills"][0]["skill_id"]
        with pytest.raises(LocalCliApiError, match="Confirm inspecting"):
            api.skills({"operation": "preflight", "skill_id": skill_id})
        job = api.skills({"operation": "preflight", "skill_id": skill_id, "confirm_directory_read": True})
        deadline = time.monotonic() + 3
        while api.refresh_job({"job_id": job["job_id"]})["state"] == "running" and time.monotonic() < deadline:
            time.sleep(0.01)
        assert api.refresh_job({"job_id": job["job_id"]})["state"] == "complete"
        preflight = api.skills({"operation": "preflight-result", "skill_id": skill_id})
        assert preflight["permissions_granted"] is False
        assert preflight["inspection"]["status"] == "complete"
        assert preflight["dependency_status"] == "absent"
        assert store.read_local_cli_revision() == 0
        record = api._skill_records[skill_id]
        (record.document.parent / "new-guide.md").write_text("A changed supporting file")
        with pytest.raises(LocalCliApiError, match="Skill files changed"):
            api.skills({"operation": "preflight-result", "skill_id": skill_id})
        api._skill_preflights[skill_id] = (time.monotonic() - 31, preflight)
        with pytest.raises(LocalCliApiError, match="Prepare this workflow again"):
            api.skills({"operation": "preflight-result", "skill_id": skill_id})
    finally:
        assert api.close_discovery()
