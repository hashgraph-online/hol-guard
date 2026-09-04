from __future__ import annotations

import os
import subprocess
from pathlib import Path

from scripts.ci.generate_release_notes import (
    Change,
    enrich_with_pull_requests,
    extract_summary_bullets,
    load_changes,
    parse_subject,
    render_notes,
    select_previous_tag,
    version_sort_key,
)

REPO = "hashgraph-online/hol-guard"


def _change(**kwargs) -> Change:
    defaults = {
        "sha": "a" * 40,
        "subject": "feat(guard): do a thing (#1)",
        "author": "Michael Kantor",
        "type": "feat",
        "scope": "guard",
        "description": "do a thing",
        "pr_number": 1,
    }
    defaults.update(kwargs)
    return Change(**defaults)


def test_parse_subject_extracts_type_scope_breaking_and_pr() -> None:
    parsed = parse_subject("feat(extensions)!: add Laravel Artisan command safety extension (#2761)")
    assert parsed == {
        "type": "feat",
        "scope": "extensions",
        "breaking": True,
        "description": "add Laravel Artisan command safety extension",
        "pr": 2761,
    }


def test_parse_subject_handles_scopeless_and_non_conventional_subjects() -> None:
    assert parse_subject("fix: repair the doctor install probe (#9)") == {
        "type": "fix",
        "scope": None,
        "breaking": False,
        "description": "repair the doctor install probe",
        "pr": 9,
    }
    assert parse_subject("Merge pull request #5 from guard/release") is None
    assert parse_subject("some release bookkeeping") is None


def test_version_sort_key_orders_preleases_below_stable() -> None:
    assert version_sort_key("3.0.10") > version_sort_key("3.0.9")
    assert version_sort_key("3.0.0") > version_sort_key("3.0.0a290")
    assert version_sort_key("3.0.0a290") > version_sort_key("3.0.0a289")
    assert version_sort_key("not-a-version") is None


def test_select_previous_tag_picks_closest_same_channel_tag() -> None:
    tags = ["v3.0.7", "v3.0.68", "v3.0.69", "v3.0.70", "alpha/v3.0.0a290"]
    assert select_previous_tag(tags, "3.0.70", "stable") == "v3.0.69"
    assert select_previous_tag(tags, "3.0.68", "stable") == "v3.0.7"
    assert select_previous_tag(["v3.0.69", "alpha/v3.0.0a290"], "3.0.70", "stable") == "v3.0.69"
    assert select_previous_tag(["alpha/v3.0.0a289", "alpha/v3.0.0a290"], "3.0.0a290", "alpha") == "alpha/v3.0.0a289"
    assert select_previous_tag(["v2.2.128"], "3.0.0", "stable") == "v2.2.128"
    assert select_previous_tag(["v3.0.1"], "3.0.1", "stable") is None


def test_extract_summary_bullets_reads_summary_section_with_limits() -> None:
    body = (
        "## Summary\n"
        "- Adds a Laravel Artisan command safety extension\n"
        "- Covers direct and interpreter-wrapped launch forms\n"
        "- Declares safe counterparts for dry-run flags\n"
        "- Fourth bullet beyond the limit\n"
        "\n"
        "## Testing\n"
        "-pytest\n"
    )
    assert extract_summary_bullets(body, limit=3) == [
        "Adds a Laravel Artisan command safety extension",
        "Covers direct and interpreter-wrapped launch forms",
        "Declares safe counterparts for dry-run flags",
    ]
    assert extract_summary_bullets(None) == []
    assert extract_summary_bullets("## Testing\n- nothing") == []


def test_extract_summary_bullets_truncates_at_word_boundary() -> None:
    bullet = "word " * 80
    bullets = extract_summary_bullets(f"## Summary\n- {bullet}")
    assert len(bullets) == 1
    assert bullets[0].endswith("…")
    assert len(bullets[0]) <= 220


def test_render_notes_groups_sections_and_links_everything() -> None:
    changes = [
        _change(
            subject="feat(extensions): add Laravel Artisan command safety extension (#2761)",
            description="add Laravel Artisan command safety extension",
            scope="extensions",
            pr_number=2761,
            pr_title="feat(extensions): add Laravel Artisan command safety extension",
            pr_author="kantorcodes",
            summary_bullets=["Reviews destructive Artisan operations"],
        ),
        _change(
            sha="b" * 40,
            subject="ci(sonar): import sharded pytest coverage (#2759)",
            author="github-actions[bot]",
            type="ci",
            scope="sonar",
            description="import sharded pytest coverage",
            pr_number=2759,
            pr_title="ci(sonar): import sharded pytest coverage",
        ),
        _change(
            sha="c" * 40,
            subject="refactor(guard)!: share duplicated helpers (#2760)",
            type="refactor",
            scope="guard",
            breaking=True,
            description="share duplicated helpers",
            pr_number=2760,
            pr_title="refactor(guard)!: share duplicated helpers",
        ),
        _change(
            sha="d" * 40,
            subject="build(wheels): pin the native toolchain",
            type="build",
            scope="wheels",
            description="pin the native toolchain",
            pr_number=None,
        ),
    ]
    notes = render_notes(
        changes,
        version="3.0.68",
        channel="stable",
        repo=REPO,
        tag="v3.0.68",
        previous_tag="v3.0.67",
        source_sha="a" * 40,
    )
    assert "Guard 3.0.68 is a stable release cut from [`aaaaaaa`]" in notes
    assert "**4 commits • 3 merged pull requests • 2 contributors** since [Guard 3.0.67]" in notes
    assert "## Features" in notes and "## Fixes" not in notes
    assert "## CI & automation" in notes and "## Refactoring" in notes
    assert "Pin the native toolchain" in notes
    assert "[#2761](https://github.com/hashgraph-online/hol-guard/pull/2761)" in notes
    assert "  - Reviews destructive Artisan operations" in notes
    assert "**(breaking)**" in notes
    assert 'uv tool install "hol-guard[cisco]==3.0.68"' in notes
    assert "[v3.0.67...v3.0.68](https://github.com/hashgraph-online/hol-guard/compare/v3.0.67...v3.0.68)" in notes
    assert "Thanks @kantorcodes, Michael Kantor!" in notes
    assert "@Michael Kantor" not in notes


def test_render_notes_alpha_channel_and_empty_history() -> None:
    alpha = render_notes(
        [_change()],
        version="3.0.0a290",
        channel="alpha",
        repo=REPO,
        tag="alpha/v3.0.0a290",
        previous_tag="alpha/v3.0.0a289",
        source_sha="a" * 40,
    )
    assert "opt-in prerelease" in alpha
    assert "since [Guard 3.0.0a289]" in alpha

    empty = render_notes(
        [],
        version="3.0.71",
        channel="stable",
        repo=REPO,
        tag="v3.0.71",
        previous_tag="v3.0.70",
        source_sha="d" * 40,
    )
    assert "no user-facing changes" in empty
    assert 'uv tool install "hol-guard[cisco]==3.0.71"' in empty


def _git(repo: Path, *args: str) -> None:
    env = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "PATH": os.environ["PATH"]}
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


def test_load_changes_parses_commit_range(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--initial-branch=main")
    _git(repo, "config", "user.email", "guard@example.test")
    _git(repo, "config", "user.name", "Guard Tests")
    (repo / "file.txt").write_text("one", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "feat(guard): first feature (#1)")
    _git(repo, "tag", "v3.0.1")
    (repo / "file.txt").write_text("two", encoding="utf-8")
    _git(repo, "commit", "-am", "fix(doctor): repair install probe (#2)")
    (repo / "file.txt").write_text("three", encoding="utf-8")
    _git(repo, "commit", "-am", "Merge pull request #2 from guard/fix")

    changes = load_changes("HEAD", "v3.0.1", cwd=repo)
    subjects = [change.subject for change in changes]
    assert "fix(doctor): repair install probe (#2)" in subjects
    fix = next(change for change in changes if change.type == "fix")
    assert fix.scope == "doctor" and fix.pr_number == 2

    merge = next(change for change in changes if change.subject.startswith("Merge pull request"))
    assert merge.pr_number == 2


def test_enrich_with_pull_requests_uses_pr_metadata(monkeypatch) -> None:
    changes = [
        _change(
            subject="Merge pull request #5 from guard/feature",
            type="internal",
            scope=None,
            description="Merge pull request #5 from guard/feature",
            pr_number=5,
        )
    ]
    monkeypatch.setattr(
        "scripts.ci.generate_release_notes.fetch_pull_request",
        lambda repo, number: {
            "title": "feat(cli): add pattern search (#5)",
            "author": "kantorcodes",
            "body": "## Summary\n- Search command patterns from the terminal",
        },
    )
    enrich_with_pull_requests(changes, REPO)
    change = changes[0]
    assert change.type == "feat" and change.scope == "cli"
    assert change.pr_number == 5 and change.pr_author == "kantorcodes"
    assert change.summary_bullets == ["Search command patterns from the terminal"]
