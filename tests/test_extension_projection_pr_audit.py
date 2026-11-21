"""Keep retirement audits complete when PRs rename files or change mid-read."""

import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "projection_pr_audit", Path(__file__).resolve().parents[1] / "scripts/audit_extension_projection_prs.py"
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


@pytest.mark.parametrize("failure", [None, "missing-page", "head-moved"])
def test_paginated_rename_origins_and_source_identity(monkeypatch, failure):
    def github(*args):
        if args[0] == "pr":
            return [{"number": 1, "headRefOid": "a" * 40, "changedFiles": 2, "files": []}]
        if "/files?" in args[1]:
            pages = [[{"filename": "docs/new-location.md", "previous_filename": "docs/guard/extensions/README.md"}]]
            if failure != "missing-page":
                pages.append([{"filename": "unrelated.txt"}])
            return pages
        return {"state": "open", "head": {"sha": ("b" if failure == "head-moved" else "a") * 40}, "changed_files": 2}

    monkeypatch.setattr(audit, "github", github)
    if failure:
        with pytest.raises(ValueError, match=r"incomplete|changed during"):
            audit.audit()
    else:
        result = audit.audit()
        assert result["complete"]
        assert result["affected_prs"] == [
            {"number": 1, "head_sha": "a" * 40, "paths": ["docs/guard/extensions/README.md"]}
        ]
