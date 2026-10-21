from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.runtime.local_skill_index import (
    approved_skill_roots,
    index_local_skills,
    inspect_indexed_skill,
    public_skill_page,
    read_skill_metadata,
)
from codex_plugin_scanner.guard.store import GuardStore


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
def test_malformed_or_over_limit_metadata_is_not_loaded(tmp_path: Path, header: str, reason: str):
    root = tmp_path / "skills"
    document = _skill(root, frontmatter=header)
    with pytest.raises(ValueError, match=reason):
        read_skill_metadata(document, root=root)


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
