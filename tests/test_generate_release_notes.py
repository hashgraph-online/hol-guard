from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from scripts.ci.generate_release_notes import (
    Change,
    PreviousRelease,
    enrich_with_pull_requests,
    extract_summary_bullets,
    human_contributors,
    load_changes,
    main,
    parse_subject,
    render_notes,
    resolve_previous_release,
    select_previous_tag,
    split_pr_suffix,
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


def test_render_notes_condenses_histories_too_large_to_list() -> None:
    changes = [
        _change(
            sha=f"{i:040x}",
            subject=f"fix(guard): repair thing {i} (#{i + 1})",
            type="fix" if i % 2 else "feat",
            scope="guard",
            description=f"repair thing {i}",
            pr_number=i + 1,
        )
        for i in range(200)
    ]
    notes = render_notes(
        changes,
        version="2.1.0a1",
        channel="alpha",
        repo=REPO,
        tag="alpha/v2.1.0a1",
        previous_tag=None,
        source_sha="e" * 40,
    )
    assert "first release on this channel" in notes
    assert "## Changes by category" in notes
    assert "- **Features**: 100" in notes and "- **Fixes**: 100" in notes
    assert "full commit history" in notes
    assert "repair thing 5" not in notes
    assert len(notes) < 10000


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
            "author_id": 6068672,
            "body": "## Summary\n- Search command patterns from the terminal",
        },
    )
    enrich_with_pull_requests(changes, REPO)
    change = changes[0]
    assert change.type == "feat" and change.scope == "cli"
    assert change.pr_number == 5 and change.pr_author == "kantorcodes"
    assert change.pr_author_id == 6068672
    assert change.summary_bullets == ["Search command patterns from the terminal"]


def test_split_pr_suffix_recognizes_nonconventional_squash_subjects() -> None:
    assert split_pr_suffix("Add LDAP authentication (#42)") == ("Add LDAP authentication", 42)
    assert split_pr_suffix("Fix thing (#4) (#12)") == ("Fix thing (#4)", 12)
    assert split_pr_suffix("Merge pull request #5 from guard/fix") == (
        "Merge pull request #5 from guard/fix",
        None,
    )
    assert split_pr_suffix("bookkeeping without a suffix") == ("bookkeeping without a suffix", None)


def test_load_changes_recognizes_nonconventional_squash_subject(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--initial-branch=main")
    _git(repo, "config", "user.email", "guard@example.test")
    _git(repo, "config", "user.name", "Guard Tests")
    (repo / "file.txt").write_text("one", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "feat(guard): baseline (#1)")
    _git(repo, "tag", "v3.0.1")
    (repo / "file.txt").write_text("two", encoding="utf-8")
    _git(repo, "commit", "-am", "Add LDAP authentication (#42)")

    changes = load_changes("HEAD", "v3.0.1", cwd=repo)
    change = changes[0]
    assert change.subject == "Add LDAP authentication (#42)"
    assert change.pr_number == 42
    assert change.type == "internal" and change.scope is None
    assert change.description == "Add LDAP authentication"


def test_enrich_with_pull_requests_credits_nonconventional_pr_titles(monkeypatch) -> None:
    changes = [_change(subject="Add LDAP authentication (#42)", type="internal", scope=None, pr_number=42)]
    monkeypatch.setattr(
        "scripts.ci.generate_release_notes.fetch_pull_request",
        lambda repo, number: {
            "title": "Add LDAP authentication",
            "author": "kantorcodes",
            "author_id": 6068672,
            "body": "## Summary\n- Adds LDAP login support",
        },
    )
    enrich_with_pull_requests(changes, REPO)
    change = changes[0]
    assert change.pr_author == "kantorcodes" and change.pr_author_id == 6068672
    assert change.description == "Add LDAP authentication"
    assert change.summary_bullets == ["Adds LDAP login support"]
    notes = render_notes(
        [change],
        version="3.0.71",
        channel="stable",
        repo=REPO,
        tag="v3.0.71",
        previous_tag="v3.0.70",
        source_sha="a" * 40,
        previous_release=PreviousRelease(status="published", tag="v3.0.70"),
    )
    assert "[#42](https://github.com/hashgraph-online/hol-guard/pull/42)" in notes
    assert "Add LDAP authentication ([#42]" in notes
    assert "Thanks @kantorcodes!" in notes
    assert "(#42)" not in notes.replace("[#42]", "")


def test_human_contributors_dedups_numeric_ids_and_fallback_names() -> None:
    changes = [
        # Same numeric account renamed between PRs: one credit, not two.
        _change(sha="a" * 40, pr_number=100, pr_author="old-login", pr_author_id=6068672),
        _change(sha="b" * 40, pr_number=150, pr_author="new-login", pr_author_id=6068672),
        # Different numeric account: still a distinct credit.
        _change(sha="c" * 40, pr_number=160, pr_author="collaborator", pr_author_id=301892678),
        # Same Git display name twice without PR metadata: one fallback credit.
        _change(sha="d" * 40, pr_number=None, pr_author=None, author="Michael Kantor"),
        _change(sha="e" * 40, pr_number=None, pr_author=None, author="Michael Kantor"),
        # A display name matching a login string is never merged into it.
        _change(sha="f" * 40, pr_number=None, pr_author=None, author="collaborator"),
        # Bots stay excluded in both branches.
        _change(sha="1" * 40, pr_number=170, pr_author="ci-bot[bot]", pr_author_id=999),
        _change(sha="2" * 40, pr_number=None, pr_author=None, author="github-actions[bot]"),
    ]
    assert human_contributors(changes) == [
        ("old-login", True),
        ("collaborator", True),
        ("Michael Kantor", False),
        ("collaborator", False),
    ]


def test_render_notes_stable_channel_links_published_predecessor() -> None:
    notes = render_notes(
        [_change()],
        version="3.0.70",
        channel="stable",
        repo=REPO,
        tag="v3.0.70",
        previous_tag="v3.0.69",
        source_sha="a" * 40,
        previous_release=PreviousRelease(status="published", tag="v3.0.69"),
    )
    assert "stable release" in notes
    assert "since [Guard 3.0.69](https://github.com/hashgraph-online/hol-guard/releases/tag/v3.0.69)" in notes
    assert (
        "**Full changelog**: [v3.0.69...v3.0.70]"
        "(https://github.com/hashgraph-online/hol-guard/compare/v3.0.69...v3.0.70)" in notes
    )
    assert "Source comparison" not in notes


def test_render_notes_alpha_channel_links_published_predecessor() -> None:
    notes = render_notes(
        [_change()],
        version="3.0.0a290",
        channel="alpha",
        repo=REPO,
        tag="alpha/v3.0.0a290",
        previous_tag="alpha/v3.0.0a289",
        source_sha="a" * 40,
        previous_release=PreviousRelease(status="published", tag="alpha/v3.0.0a289"),
    )
    assert "opt-in prerelease" in notes
    assert (
        "since [Guard 3.0.0a289]"
        "(https://github.com/hashgraph-online/hol-guard/releases/tag/alpha/v3.0.0a289)" in notes
    )
    assert "**Full changelog**: [alpha/v3.0.0a289...alpha/v3.0.0a290]" in notes


def test_render_notes_tag_only_predecessor_never_links_a_release() -> None:
    notes = render_notes(
        [_change()],
        version="3.0.192",
        channel="stable",
        repo=REPO,
        tag="v3.0.192",
        previous_tag="v3.0.191",
        source_sha="a" * 40,
        previous_release=PreviousRelease(status="unpublished"),
    )
    release_url = "https://github.com/hashgraph-online/hol-guard/releases/tag/v3.0.191"
    assert release_url not in notes
    assert "[Guard 3.0.191]" not in notes
    assert "since tag `v3.0.191` (previous tag has no published release)." in notes
    assert (
        "**Source comparison**: [v3.0.191...v3.0.192]"
        "(https://github.com/hashgraph-online/hol-guard/compare/v3.0.191...v3.0.192)" in notes
    )
    assert "not a release-to-release changelog" in notes
    assert "**Full changelog**" not in notes


def test_render_notes_lookup_failure_degrades_to_labelled_comparison() -> None:
    notes = render_notes(
        [_change()],
        version="3.0.192",
        channel="stable",
        repo=REPO,
        tag="v3.0.192",
        previous_tag="v3.0.191",
        source_sha="a" * 40,
        previous_release=PreviousRelease(status="unavailable"),
    )
    release_url = "https://github.com/hashgraph-online/hol-guard/releases/tag/v3.0.191"
    assert release_url not in notes
    assert "since tag `v3.0.191` (published release lookup unavailable)." in notes
    assert "**Source comparison**: [v3.0.191...v3.0.192]" in notes
    assert "lookup was unavailable" in notes
    assert "**Full changelog**" not in notes


def test_resolve_previous_release_published_unpublished_unavailable(monkeypatch) -> None:
    class Ok:
        returncode = 0
        stdout = json.dumps({"tag_name": "v3.0.191", "draft": False})
        stderr = ""

    monkeypatch.setattr(
        "scripts.ci.generate_release_notes.subprocess.run", lambda *a, **k: Ok()
    )
    resolved = resolve_previous_release(REPO, "v3.0.191")
    assert resolved.status == "published"
    assert resolved.url == "https://github.com/hashgraph-online/hol-guard/releases/tag/v3.0.191"

    class NotFound:
        returncode = 1
        stdout = ""
        stderr = "gh: Not Found (HTTP 404)"

    monkeypatch.setattr(
        "scripts.ci.generate_release_notes.subprocess.run", lambda *a, **k: NotFound()
    )
    assert resolve_previous_release(REPO, "v3.0.191").status == "unpublished"

    class ServerError:
        returncode = 1
        stdout = ""
        stderr = "gh: Server Error (HTTP 500)"

    monkeypatch.setattr(
        "scripts.ci.generate_release_notes.subprocess.run", lambda *a, **k: ServerError()
    )
    assert resolve_previous_release(REPO, "v3.0.191").status == "unavailable"

    class Draft:
        returncode = 0
        stdout = json.dumps({"tag_name": "v3.0.191", "draft": True})
        stderr = ""

    monkeypatch.setattr(
        "scripts.ci.generate_release_notes.subprocess.run", lambda *a, **k: Draft()
    )
    assert resolve_previous_release(REPO, "v3.0.191").status == "unpublished"

    def explode(*a, **k):
        raise subprocess.TimeoutExpired(cmd="gh", timeout=30)

    monkeypatch.setattr("scripts.ci.generate_release_notes.subprocess.run", explode)
    assert resolve_previous_release(REPO, "v3.0.191").status == "unavailable"


def test_main_degrades_to_labelled_comparison_when_release_lookup_fails(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--initial-branch=main")
    _git(repo, "config", "user.email", "guard@example.test")
    _git(repo, "config", "user.name", "Guard Tests")
    (repo / "file.txt").write_text("one", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "feat(guard): first feature (#1)")
    _git(repo, "tag", "v3.0.191")
    (repo / "file.txt").write_text("two", encoding="utf-8")
    _git(repo, "commit", "-am", "feat(guard): second feature (#2)")
    _git(repo, "tag", "v3.0.192")

    monkeypatch.chdir(repo)
    monkeypatch.setattr(
        "scripts.ci.generate_release_notes.resolve_previous_release",
        lambda repo, tag: PreviousRelease(status="unavailable"),
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "generate_release_notes.py",
            "--version",
            "3.0.192",
            "--channel",
            "stable",
            "--repo",
            REPO,
            "--skip-pr-metadata",
        ],
    )

    assert main() == 0
    notes = capsys.readouterr().out
    release_url = "https://github.com/hashgraph-online/hol-guard/releases/tag/v3.0.191"
    assert release_url not in notes
    assert "since tag `v3.0.191` (published release lookup unavailable)." in notes
    assert "**Source comparison**: [v3.0.191...v3.0.192]" in notes
    assert "uv tool install \"hol-guard[cisco]==3.0.192\"" in notes


def test_main_links_no_release_when_tag_exists_without_release_object(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """v3.0.191 case: the tag exists but has no public release object.

    The releases API succeeds and only v3.0.190 (older, published) comes back,
    so the immediate predecessor tag must never be linked to a release URL -
    the notes degrade to the explicitly labelled source comparison instead.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--initial-branch=main")
    _git(repo, "config", "user.email", "guard@example.test")
    _git(repo, "config", "user.name", "Guard Tests")
    (repo / "file.txt").write_text("one", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "feat(guard): first feature (#1)")
    _git(repo, "tag", "v3.0.190")
    (repo / "file.txt").write_text("two", encoding="utf-8")
    _git(repo, "commit", "-am", "feat(guard): second feature (#2)")
    _git(repo, "tag", "v3.0.191")
    (repo / "file.txt").write_text("three", encoding="utf-8")
    _git(repo, "commit", "-am", "feat(guard): third feature (#3)")
    _git(repo, "tag", "v3.0.192")

    monkeypatch.chdir(repo)
    monkeypatch.setattr(
        "scripts.ci.generate_release_notes.resolve_previous_release",
        lambda repo, tag: PreviousRelease(status="unpublished"),
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "generate_release_notes.py",
            "--version",
            "3.0.192",
            "--channel",
            "stable",
            "--repo",
            REPO,
            "--skip-pr-metadata",
        ],
    )

    assert main() == 0
    notes = capsys.readouterr().out
    for release_url in (
        "https://github.com/hashgraph-online/hol-guard/releases/tag/v3.0.191",
        "https://github.com/hashgraph-online/hol-guard/releases/tag/v3.0.190",
    ):
        assert release_url not in notes
    assert "since tag `v3.0.191` (previous tag has no published release)." in notes
    assert "**Source comparison**: [v3.0.191...v3.0.192]" in notes
    assert "**Full changelog**" not in notes

