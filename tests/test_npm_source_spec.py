"""Canonical npm Git/source specification tests."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime.npm_source_spec import parse_npm_source_spec
from codex_plugin_scanner.guard.runtime.package_intent import (
    build_package_request_artifact,
    parse_package_intent,
)
from codex_plugin_scanner.guard.runtime.package_intent_common import js_target

COMMIT = "0123456789abcdef0123456789abcdef01234567"
REPOSITORY = "git:github.com/hashgraph-online/hol-guard"


@pytest.mark.parametrize(
    "source",
    [
        f"github:Hashgraph-Online/hol-guard.git#{COMMIT}",
        f"git+https://GITHUB.com:443/Hashgraph-Online/hol-guard.git#{COMMIT}",
        f"git+ssh://git@github.com:22/hashgraph-online/hol-guard.git#{COMMIT}",
        f"git://github.com:9418/hashgraph-online/hol-guard.git#{COMMIT}",
        f"ssh://git@github.com/hashgraph-online/hol-guard.git#{COMMIT}",
        f"git@github.com:hashgraph-online/hol-guard.git#{COMMIT}",
        f"hashgraph-online/hol-guard#{COMMIT}",
        f"https://github.com/hashgraph-online/hol-guard.git#{COMMIT}",
        f"https://github.com/hashgraph-online/%68ol-guard.git#{COMMIT}",
    ],
)
def test_equivalent_github_source_forms_share_canonical_identity(source: str) -> None:
    parsed = parse_npm_source_spec(source)

    assert parsed is not None
    assert parsed.valid
    assert parsed.source_kind == "git"
    assert parsed.canonical_repository == REPOSITORY
    assert parsed.revision == COMMIT
    assert parsed.revision_kind == "immutable_commit"
    assert parsed.identity == f"{REPOSITORY}#commit:{COMMIT}"


@pytest.mark.parametrize(
    ("fragment", "expected_kind"),
    [
        (None, "missing"),
        ("main", "mutable_ref"),
        ("v2.1.0", "mutable_ref"),
        ("semver:^2.1.0", "mutable_ref"),
        ("pull/1748/head", "mutable_ref"),
        (COMMIT.upper(), "immutable_commit"),
    ],
)
def test_git_revision_state_is_classified_conservatively(fragment: str | None, expected_kind: str) -> None:
    suffix = f"#{fragment}" if fragment is not None else ""

    parsed = parse_npm_source_spec(f"github:hashgraph-online/hol-guard{suffix}")

    assert parsed is not None
    assert parsed.revision_kind == expected_kind
    if expected_kind == "immutable_commit":
        assert parsed.revision == COMMIT


@pytest.mark.parametrize(
    ("source", "repository", "revision"),
    [
        (
            "https://github.com/Hashgraph-Online/hol-guard/archive/refs/heads/main.tar.gz?token=secret",
            REPOSITORY,
            "refs/heads/main",
        ),
        (
            "https://gitlab.com/Group/Subgroup/Repo/-/archive/release/repo-release.tar.gz",
            "git:gitlab.com/group/subgroup/repo",
            "release",
        ),
        (
            "https://bitbucket.org/Owner/Repo/get/main.zip",
            "git:bitbucket.org/owner/repo",
            "main",
        ),
    ],
)
def test_hosted_git_archive_urls_remain_repository_sources(
    source: str,
    repository: str,
    revision: str,
) -> None:
    parsed = parse_npm_source_spec(source)

    assert parsed is not None
    assert parsed.is_git
    assert parsed.canonical_repository == repository
    assert parsed.revision == revision
    assert parsed.revision_kind == "mutable_ref"


def test_idna_and_nondefault_ports_are_canonicalized_without_collapsing_distinct_hosts() -> None:
    idna_source = parse_npm_source_spec("git+https://BÜCHER.example/Owner/Repo.git#main")
    nondefault_port = parse_npm_source_spec("git+https://github.com:8443/Owner/Repo.git#main")
    default_port = parse_npm_source_spec("github:owner/repo#main")

    assert idna_source is not None
    assert idna_source.canonical_repository == "git:xn--bcher-kva.example/Owner/Repo"
    assert nondefault_port is not None
    assert default_port is not None
    assert nondefault_port.canonical_repository == "git:github.com:8443/owner/repo"
    assert nondefault_port.identity != default_port.identity


def test_custom_git_hosts_support_root_level_repositories() -> None:
    parsed = parse_npm_source_spec("git+https://example.com/Guard.GIT#main")

    assert parsed is not None
    assert parsed.canonical_repository == "git:example.com/Guard"
    assert parsed.revision_kind == "mutable_ref"


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        ("https://user:password@github.com/owner/repo.git#main", "npm_source_ambiguous_userinfo"),
        ("ssh://deploy@github.com/owner/repo.git#main", "npm_source_ambiguous_userinfo"),
        ("deploy@github.com:owner/repo.git#main", "npm_source_ambiguous_userinfo"),
        ("https://github.com/owner%2Frepo/project.git", "npm_source_path_invalid"),
        ("git+https://github.com:bad/owner/repo.git", "npm_source_malformed_port"),
        ("git+https://github.com:70000/owner/repo.git", "npm_source_malformed_port"),
        ("git+file:///tmp/owner/repo.git", "npm_source_protocol_unsupported"),
        ("file://server/share/owner/repo", "npm_source_local_url_invalid"),
        ("ftp://github.com/owner/repo.git", "npm_source_protocol_unsupported"),
        ("git+https://github.com/../owner/repo.git", "npm_source_path_invalid"),
    ],
)
def test_ambiguous_or_malformed_sources_fail_with_stable_reasons(source: str, reason: str) -> None:
    parsed = parse_npm_source_spec(source)

    assert parsed is not None
    assert not parsed.valid
    assert parsed.source_kind == "invalid"
    assert parsed.reason == reason
    assert parsed.redacted == "<invalid-source>"
    assert "password" not in parsed.identity


def test_query_credentials_are_redacted_without_changing_git_identity() -> None:
    plain = parse_npm_source_spec("https://github.com/owner/repo.git#main")
    secret = parse_npm_source_spec("https://github.com/owner/repo.git?token=VERY_SECRET#main")

    assert plain is not None and secret is not None
    assert secret.identity == plain.identity
    assert "VERY_SECRET" not in secret.redacted
    assert secret.redacted == "git:github.com/owner/repo#<mutable-ref>"


def test_named_and_aliased_sources_reuse_the_canonical_parser() -> None:
    named = js_target(f"guard@github:Hashgraph-Online/hol-guard.git#{COMMIT}")
    aliased = js_target(f"guard-alias@npm:github:hashgraph-online/hol-guard#{COMMIT}")

    assert named.package_name == "guard"
    assert aliased.package_name == "hol-guard"
    assert aliased.alias == "guard-alias"
    assert named.source_identity == aliased.source_identity == f"{REPOSITORY}#commit:{COMMIT}"
    assert named.requested_specifier is None
    assert aliased.requested_specifier is None


def test_registry_aliases_do_not_become_ambiguous_scp_sources() -> None:
    target = js_target("guard-safe@npm:minimist@1.2.8")

    assert target.alias == "guard-safe"
    assert target.package_name == "minimist"
    assert target.requested_specifier == "1.2.8"
    assert target.source_kind is None
    assert target.source_invalid_reason is None


def test_git_approval_fingerprint_uses_canonical_repository_and_exact_commit() -> None:
    first = _artifact_for_source(f"github:Hashgraph-Online/hol-guard.git#{COMMIT}")
    equivalent = _artifact_for_source(
        f"git+https://GITHUB.com:443/hashgraph-online/hol-guard.git?token=ROTATING_SECRET#{COMMIT}"
    )
    different_commit = _artifact_for_source(
        "git+https://github.com/hashgraph-online/hol-guard.git#ffffffffffffffffffffffffffffffffffffffff"
    )

    assert first.artifact_id == equivalent.artifact_id
    assert different_commit.artifact_id != first.artifact_id
    assert "ROTATING_SECRET" not in equivalent.artifact_id


def _artifact_for_source(source: str) -> GuardArtifact:
    intent = parse_package_intent(f"npm install {source}")
    assert intent is not None
    return build_package_request_artifact(
        "codex",
        intent,
        config_path="codex.json",
        source_scope="project",
    )
