"""Token grants stay explicit and local to the jobs that consume them."""

from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

from scripts.check_privileged_workflows import validate_privileged_workflows

ROOT = Path(__file__).resolve().parents[1]
PINNED_ACTION = "actions/checkout@0123456789abcdef0123456789abcdef01234567"


def _write_workflow(root: Path, header: str, job_permissions: str = "") -> Path:
    """Create a workflow whose root and job permission declarations vary independently."""

    path = root / ".github/workflows/fixture.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"{header}\njobs:\n  test:\n{job_permissions}    steps:\n      - uses: {PINNED_ACTION}\n",
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    "header",
    ["", "permissions:", "permissions: null", "permissions: []", "permissions: read-all", "permissions: write-all"],
)
def test_workflow_requires_explicit_named_permissions(tmp_path: Path, header: str) -> None:
    """Repository defaults and wildcard declarations cannot silently grant token capabilities."""

    _write_workflow(tmp_path, header, "    permissions: {}\n")
    violations = validate_privileged_workflows(tmp_path)
    assert [item.code for item in violations] == ["permission-map-required"]
    assert violations[0].job == "<workflow>"


@pytest.mark.parametrize(
    "scope",
    [
        "contents",
        "packages",
        "actions",
        "security-events",
        "id-token",
        "attestations",
        "artifact-metadata",
        "pull-requests",
        "issues",
    ],
)
def test_workflow_write_grants_are_rejected_even_with_read_only_job(tmp_path: Path, scope: str) -> None:
    """A safe existing job does not make write-capable defaults safe for future jobs."""

    _write_workflow(tmp_path, f"permissions:\n  {scope}: write", "    permissions:\n      contents: read\n")
    violations = validate_privileged_workflows(tmp_path)
    assert [item.code for item in violations] == ["workflow-write-permission"]
    assert scope in violations[0].message


@pytest.mark.parametrize("value", ["read-all", "write-all", "null", "[]", "true"])
def test_job_wildcard_and_malformed_grants_are_rejected(tmp_path: Path, value: str) -> None:
    """Explicit job grants must be named maps rather than wildcard or malformed values."""

    _write_workflow(tmp_path, "permissions: {}", f"    permissions: {value}\n")
    violations = validate_privileged_workflows(tmp_path)
    assert [item.code for item in violations] == ["permission-map-required"]
    assert violations[0].job == "test"


@pytest.mark.parametrize(
    "entry",
    ["contents: true", "contents: null", "contents: [read]", "contents: admin", '"": read', "123: read"],
)
@pytest.mark.parametrize("job_level", [False, True])
def test_invalid_scope_values_fail_closed(tmp_path: Path, entry: str, job_level: bool) -> None:
    """Malformed permission entries fail at both workflow and job scope."""

    header = "permissions: {}" if job_level else f"permissions:\n  {entry}"
    job = f"    permissions:\n      {entry}\n" if job_level else ""
    _write_workflow(tmp_path, header, job)
    assert [item.code for item in validate_privileged_workflows(tmp_path)] == ["permission-invalid"]


@pytest.mark.parametrize(
    "header", ["permissions: {}", "permissions:\n  contents: read", "permissions:\n  contents: none"]
)
def test_read_only_or_empty_defaults_are_allowed(tmp_path: Path, header: str) -> None:
    """Empty, read-only, and explicitly disabled workflow grants are valid defaults."""

    _write_workflow(tmp_path, header)
    assert validate_privileged_workflows(tmp_path) == ()


@pytest.mark.parametrize("scope", ["content", "CONTENTS", " contents", "contents ", "security_events", "unknown", "*"])
@pytest.mark.parametrize("job_level", [False, True])
def test_unknown_or_noncanonical_scope_names_are_rejected(tmp_path: Path, scope: str, job_level: bool) -> None:
    """Misspellings, whitespace, and case variants cannot pass as valid scope names."""

    entry = f'"{scope}": read'
    header = "permissions: {}" if job_level else f"permissions:\n  {entry}"
    job = f"    permissions:\n      {entry}\n" if job_level else ""
    _write_workflow(tmp_path, header, job)
    assert [item.code for item in validate_privileged_workflows(tmp_path)] == ["permission-invalid"]


@pytest.mark.parametrize("scope,level", [("id-token", "read"), ("vulnerability-alerts", "write")])
@pytest.mark.parametrize("job_level", [False, True])
def test_scope_specific_invalid_access_levels_are_rejected(
    tmp_path: Path, scope: str, level: str, job_level: bool
) -> None:
    """OIDC and vulnerability alerts reject access levels their APIs do not support."""

    entry = f"{scope}: {level}"
    header = "permissions: {}" if job_level else f"permissions:\n  {entry}"
    job = f"    permissions:\n      {entry}\n" if job_level else ""
    _write_workflow(tmp_path, header, job)
    assert [item.code for item in validate_privileged_workflows(tmp_path)] == ["permission-invalid"]


@pytest.mark.parametrize(
    "scope,levels",
    [
        ("actions", ("read", "write", "none")),
        ("artifact-metadata", ("read", "write", "none")),
        ("attestations", ("read", "write", "none")),
        ("checks", ("read", "write", "none")),
        ("code-quality", ("read", "write", "none")),
        ("contents", ("read", "write", "none")),
        ("deployments", ("read", "write", "none")),
        ("discussions", ("read", "write", "none")),
        ("id-token", ("write", "none")),
        ("issues", ("read", "write", "none")),
        ("packages", ("read", "write", "none")),
        ("pages", ("read", "write", "none")),
        ("pull-requests", ("read", "write", "none")),
        ("security-events", ("read", "write", "none")),
        ("statuses", ("read", "write", "none")),
        ("vulnerability-alerts", ("read", "none")),
    ],
)
def test_documented_scope_levels_are_accepted(tmp_path: Path, scope: str, levels: tuple[str, ...]) -> None:
    """Every documented scope retains its valid job grants and non-write workflow grants."""

    for level in levels:
        _write_workflow(tmp_path, "permissions: {}", f"    permissions:\n      {scope}: {level}\n")
        assert validate_privileged_workflows(tmp_path) == ()
        if level != "write":
            _write_workflow(tmp_path, f"permissions:\n  {scope}: {level}")
            assert validate_privileged_workflows(tmp_path) == ()


def test_explicit_job_grants_do_not_inherit_root_scopes(tmp_path: Path) -> None:
    """An explicit empty job map replaces rather than extends workflow permissions."""

    path = _write_workflow(tmp_path, "permissions:\n  contents: read", "    permissions: {}\n")
    path.write_text(path.read_text().replace(PINNED_ACTION, "actions/checkout@v4"))
    assert validate_privileged_workflows(tmp_path) == ()


def test_job_write_grants_still_enforce_action_pins(tmp_path: Path) -> None:
    """Narrow token grants do not relax the immutable-action requirement for writers."""

    path = _write_workflow(tmp_path, "permissions: {}", "    permissions:\n      contents: write\n")
    path.write_text(path.read_text().replace(PINNED_ACTION, "actions/checkout@v4"))
    assert [item.code for item in validate_privileged_workflows(tmp_path)] == ["action-not-commit-pinned"]


@pytest.mark.parametrize("text", ["", "null", "[]", "workflow", "[broken"])
def test_non_mapping_or_unreadable_workflow_fails_closed(tmp_path: Path, text: str) -> None:
    """Invalid workflow documents produce a policy failure instead of being ignored."""

    path = _write_workflow(tmp_path, "permissions: {}")
    path.write_text(text, encoding="utf-8")
    violations = validate_privileged_workflows(tmp_path)
    assert len(violations) == 1
    assert violations[0].code in {"workflow-invalid", "workflow-unreadable"}


@pytest.mark.parametrize(
    ("filename", "job", "permissions"),
    [
        ("finish-extension-authority-stability.yml", "finish", {"contents": "write"}),
        (
            "guarded-repository.yml",
            "scan",
            {
                "contents": "read",
                "id-token": "write",
                "attestations": "write",
                "artifact-metadata": "write",
                "security-events": "write",
            },
        ),
        ("extension-claim-notice.yml", "notify", {"contents": "read", "pull-requests": "write"}),
        ("gitar-fork-access-notice.yml", "notify", {"pull-requests": "write"}),
        ("release-please.yml", "release-please", {"contents": "write", "pull-requests": "write"}),
        ("release-please.yml", "dispatch-stable-publish", {"actions": "write", "contents": "read"}),
        ("publish-mcp-registry.yml", "publish", {"contents": "read", "id-token": "write"}),
        (
            "scorecard.yml",
            "scorecard",
            {"actions": "read", "contents": "read", "id-token": "write", "security-events": "write"},
        ),
    ],
)
def test_writer_workflows_start_empty_and_preserve_needed_job_grants(
    filename: str, job: str, permissions: dict[str, str]
) -> None:
    """Release, scan, and notification jobs retain exactly their required capabilities."""

    workflow = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text(encoding="utf-8"))
    assert workflow["permissions"] == {}
    assert workflow["jobs"][job]["permissions"] == permissions
    if filename == "publish-mcp-registry.yml":
        publish = workflow["jobs"][job]
        assert publish["needs"] == "verify"
        assert workflow["jobs"]["verify"]["permissions"] == {"actions": "read", "contents": "read"}
        expected_guard = " && ".join(
            (
                "needs.verify.outputs.sha != ''",
                "needs.verify.outputs.branch != ''",
                "vars.RELEASE_PUBLISHING_ENABLED == 'true'",
                "github.event.workflow_run.conclusion == 'success'",
                'contains(fromJSON(\'["push", "workflow_dispatch"]\'), github.event.workflow_run.event)',
                "github.event.workflow_run.run_attempt == 1",
                "github.event.workflow_run.head_repository.full_name == github.repository",
                'contains(fromJSON(\'["main", "release/3.0"]\'), github.event.workflow_run.head_branch)',
                "!contains(github.event.workflow_run.head_commit.message || '', '[skip release publish]')",
            )
        )
        assert " ".join(publish["if"].split()) == expected_guard


def test_gitar_fork_access_notice_only_handles_verified_push_denials() -> None:
    """Live comments and manual backfills require Gitar's verified denial evidence."""

    workflow = (ROOT / ".github/workflows/gitar-fork-access-notice.yml").read_text(encoding="utf-8")
    parsed = yaml.safe_load(workflow)
    assert "permissions: {}" in workflow
    assert "pull-requests: write" in workflow
    assert parsed[True]["workflow_dispatch"]["inputs"]["pr_number"]["required"] is True
    assert "github.event.issue.pull_request != null" in workflow
    assert "github.event.comment.user.login == 'gitar-bot[bot]'" in workflow
    assert "github.event.comment.user.type == 'Bot'" in workflow
    assert "github.event_name == 'workflow_dispatch'" in workflow
    assert "Gitar is not allowed to push to this forked PR." in workflow
    assert '0* | *[!0-9]* | "")' in workflow
    assert "pr_state" in workflow
    assert "head_is_fork" in workflow
    assert "gitar_denial_ids" in workflow
    assert "actions/checkout" not in workflow
    assert "github-actions[bot]" in workflow


def _run_gitar_fork_access_notice(
    tmp_path: Path,
    *,
    state: str = "open",
    head_is_fork: bool = True,
    has_trusted_denial: bool = True,
) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
    """Run the notification shell with a deterministic GitHub CLI substitute."""

    workflow = yaml.safe_load((ROOT / ".github/workflows/gitar-fork-access-notice.yml").read_text(encoding="utf-8"))
    notice_shell = workflow["jobs"]["notify"]["steps"][0]["run"]
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    calls_path = tmp_path / "gh-calls.jsonl"
    fake_gh = fake_bin / "gh"
    fake_gh.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import os
            from pathlib import Path
            import sys

            args = sys.argv[1:]
            with Path(os.environ["GH_CALLS_PATH"]).open("a", encoding="utf-8") as calls:
                print(json.dumps(args), file=calls)

            endpoint = next((arg for arg in args if arg.startswith("repos/")), "")
            method = args[args.index("--method") + 1] if "--method" in args else "GET"
            query = args[args.index("--jq") + 1] if "--jq" in args else ""

            if method == "POST" and endpoint.endswith("/issues/42/comments"):
                print("{}")
            elif endpoint.endswith("/pulls/42"):
                if query == ".state":
                    print(os.environ["FAKE_PR_STATE"])
                elif query == ".head.repo.fork // false":
                    print(os.environ["FAKE_HEAD_IS_FORK"])
                else:
                    sys.exit(f"unexpected pull request query: {query}")
            elif endpoint.endswith("/issues/42/comments?per_page=100"):
                if 'gitar-bot[bot]' in query and os.environ["FAKE_TRUSTED_DENIAL"] == "true":
                    print("987654321")
                elif 'gitar-bot[bot]' not in query and 'github-actions[bot]' not in query:
                    sys.exit(f"unexpected comments query: {query}")
            else:
                sys.exit(f"unexpected GitHub CLI invocation: {args}")
            """
        ),
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)

    environment = os.environ | {
        "GH_CALLS_PATH": str(calls_path),
        "FAKE_PR_STATE": state,
        "FAKE_HEAD_IS_FORK": str(head_is_fork).lower(),
        "FAKE_TRUSTED_DENIAL": str(has_trusted_denial).lower(),
        "GH_TOKEN": "test-token",
        "PR_NUMBER": "42",
        "REPOSITORY": "example/repository",
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
    }
    completed = subprocess.run(
        ["bash", "-c", notice_shell],
        capture_output=True,
        check=False,
        env=environment,
        text=True,
    )
    calls = [json.loads(line) for line in calls_path.read_text(encoding="utf-8").splitlines()]
    return completed, calls


@pytest.mark.parametrize(
    ("state", "head_is_fork", "has_trusted_denial", "should_post"),
    [
        ("open", True, True, True),
        ("closed", True, True, False),
        ("open", False, True, False),
        ("open", True, False, False),
    ],
)
def test_gitar_fork_access_notice_dispatch_posts_only_for_verified_open_forks(
    tmp_path: Path,
    state: str,
    head_is_fork: bool,
    has_trusted_denial: bool,
    should_post: bool,
) -> None:
    """The write-capable manual path fails closed before it posts a contributor notice."""

    completed, calls = _run_gitar_fork_access_notice(
        tmp_path,
        state=state,
        head_is_fork=head_is_fork,
        has_trusted_denial=has_trusted_denial,
    )
    posts = [
        args
        for args in calls
        if "--method" in args
        and args[args.index("--method") + 1] == "POST"
        and any(arg.endswith("/issues/42/comments") for arg in args)
    ]

    assert bool(posts) is should_post
    assert completed.returncode == (0 if should_post else 1)


def test_security_gate_runs_permission_policy_on_pull_requests() -> None:
    """Pull-request validation invokes the same permission policy checked by these tests."""

    workflow = yaml.safe_load((ROOT / ".github/workflows/security-gates.yml").read_text(encoding="utf-8"))
    # PyYAML's YAML 1.1 loader represents the GitHub Actions `on` key as True.
    assert "pull_request" in workflow[True]
    steps = workflow["jobs"]["privileged-workflow-policy"]["steps"]
    assert any(step.get("run") == "uv run --no-sync python scripts/check_privileged_workflows.py" for step in steps)
