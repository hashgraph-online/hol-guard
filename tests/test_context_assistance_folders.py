from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import context_assistance_folders as folders
from codex_plugin_scanner.guard.daemon import context_assistance_http as http


def _tree(root: Path) -> Path:
    project = root / "my-app"
    (project / ".git").mkdir(parents=True)
    (project / "docs").mkdir()
    (project / "node_modules").mkdir()
    (project / "README.md").write_text("# My app\n")
    (project / "AGENTS.md").write_text("Rules\n")
    (project / "docs" / "design.md").write_text("Design\n")
    (project / ".env").write_text("KEY=1\n")
    (project / "logo.png").write_bytes(b"\x89PNG")
    (project / "big.md").write_text("x" * (folders.MAX_FILE_BYTES + 1))
    (project / "server_token.txt").write_text("t\n")
    (project / "tokenizer.py").write_text("print(1)\n")
    (root / "notes").mkdir()
    (root / ".hidden").mkdir()
    (root / ".ssh").mkdir()
    (root / "prod-secrets").mkdir()
    return project


def test_folders_lists_only_subfolders_and_marks_projects(tmp_path: Path) -> None:
    _tree(tmp_path)
    result = folders.browse({"path": str(tmp_path)})
    assert result["schema"] == "guard-context-folders.v1"
    assert result["path"] == str(tmp_path.resolve())
    names = {entry["name"]: entry["project"] for entry in result["entries"]}
    assert names == {"my-app": True, "notes": False}
    shown = folders.browse({"path": str(tmp_path), "hidden": True})
    assert {entry["name"] for entry in shown["entries"]} == {".hidden", "my-app", "notes"}
    assert result["places"][0]["kind"] == "home"
    assert result["roots"]


def test_folders_returns_canonical_path_through_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    result = folders.browse({"path": str(link)})
    assert result["path"] == str(real.resolve())
    assert "link" not in {entry["name"] for entry in folders.browse({"path": str(tmp_path)})["entries"]}


@pytest.mark.parametrize(
    ("payload", "code", "status"),
    [
        ({"path": "relative/dir"}, "folder_not_absolute", 400),
        ({"path": 7}, "folder_input_invalid", 400),
        ({"mode": "other"}, "folder_input_invalid", 400),
        ({"mode": "files"}, "folder_input_invalid", 400),
    ],
)
def test_folders_rejects_invalid_input(payload: dict[str, object], code: str, status: int) -> None:
    with pytest.raises(folders.FolderError) as caught:
        folders.browse(payload)
    assert (caught.value.code, caught.value.status) == (code, status)


def test_folders_reports_missing_and_file_paths(tmp_path: Path) -> None:
    with pytest.raises(folders.FolderError) as missing:
        folders.browse({"path": str(tmp_path / "nope")})
    assert missing.value.status == 404
    target = tmp_path / "file.txt"
    target.write_text("x")
    with pytest.raises(folders.FolderError) as not_dir:
        folders.browse({"path": str(target)})
    assert not_dir.value.code == "folder_not_directory"


def test_files_lists_readable_files_and_suggests_project_notes(tmp_path: Path) -> None:
    project = _tree(tmp_path)
    result = folders.browse({"mode": "files", "workspace": str(project)})
    assert result["workspace"] == str(project.resolve())
    assert [entry["relative"] for entry in result["entries"]] == ["docs"]
    files = {row["relative"]: (row["available"], row["reason"]) for row in result["files"]}
    assert files == {
        "AGENTS.md": (True, None),
        "big.md": (False, "too_large"),
        "logo.png": (False, "not_text"),
        "README.md": (True, None),
        "tokenizer.py": (True, None),
    }
    assert [row["relative"] for row in result["suggested"]] == ["README.md", "AGENTS.md", "docs/design.md"]
    nested = folders.browse({"mode": "files", "workspace": str(project), "path": "docs"})
    assert [row["relative"] for row in nested["files"]] == ["docs/design.md"]
    assert nested["suggested"] == []


@pytest.mark.parametrize("path", ["../outside", "docs/../..", "C:\\x", "/abs"])
def test_files_stays_inside_the_workspace(tmp_path: Path, path: str) -> None:
    project = _tree(tmp_path)
    with pytest.raises(folders.FolderError):
        folders.browse({"mode": "files", "workspace": str(project), "path": path if path != "/abs" else "a/../b"})


class _Handler:
    def __init__(self) -> None:
        self.calls: list[tuple[dict[str, object], int]] = []

    def _write_json(self, data: dict[str, object], status: int = 200, extra_headers: object = None) -> None:
        assert extra_headers == {"Cache-Control": "no-store"}
        self.calls.append((data, status))


def test_http_route_frames_listing_and_refusals(tmp_path: Path) -> None:
    assert http.WRITE_PATHS["/v1/context-assistance/folders"] == "folders"
    handler = _Handler()
    http.respond(handler, "folders", {"path": str(tmp_path)})
    assert handler.calls[-1][1] == 200
    http.respond(handler, "folders", {"path": os.path.join(str(tmp_path), "missing")})
    assert handler.calls[-1] == ({"error": "folder_unavailable", "code": "folder_not_found"}, 404)
