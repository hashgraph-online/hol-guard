"""Fixtures for GitHub review work under enabled permissions and linked-worktree edits."""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Any

from .realism_fixtures import write_windows_launcher

GITHUB_REVIEW_CASE = "github-review-work-enabled-permissions"
GITHUB_DELETE_CASE = "explicit-disabled-github-delete-permission"
# The Oh My Pi `github` tool runs `gh api` underneath, so its lookups reach the same stand-in.
GITHUB_LOOKUP_CASE = "omp-native-github-search-prs"
GITHUB_LOOKUP_REPO = "example-org/example-repo"
GITHUB_LOOKUP_QUERY = "is:pr metrics OR analytics"
GITHUB_STUB_CASES = frozenset({GITHUB_REVIEW_CASE, GITHUB_DELETE_CASE, GITHUB_LOOKUP_CASE})
WORKTREE_CASE = "linked-worktree-edit-from-main-checkout"
# Writes into a harness plan folder pass; the hooks file beside it stays reviewed.
PLAN_NOTE_PROTECTION_CASE = "plan-note-protection-codex-hooks"
CODEX_HOOKS = "{}\n"
# Not prefixed by the workspace name, so redaction cannot fold it into {{workspace}}.
WORKTREE_NAME = "review-worktree"
GITHUB_EXTENSION_ID = "command.github"
GH_LOG = "output/gh-calls.log"
SEPARATOR = "\x1f"


def seed_protected_codex_hooks(home: Path, scenario_id: str) -> None:
    """Give the plan-note protection case its hooks file with known bytes.

    A write that reached it then shows as a changed file instead of passing
    because the destination was missing. Guard's Codex install migrates and
    removes ``~/.codex/hooks.json``, so the Codex lane seeds it again after
    installing.
    """
    if scenario_id != PLAN_NOTE_PROTECTION_CASE:
        return
    (home / ".codex").mkdir(mode=0o700, parents=True, exist_ok=True)
    (home / ".codex" / "hooks.json").write_text(CODEX_HOOKS, encoding="utf-8", newline="\n")


_REPLY_BODY = "@reviewer Fixed in abc123"
_RESOLVE_LITERAL = 'mutation { resolveReviewThread(input: {threadId: "PRRT_kwDOSYNTH001"}) { thread { isResolved } } }'
_RESOLVE_VARIABLE = "mutation($t: ID!) { resolveReviewThread(input: {threadId: $t}) { thread { isResolved } } }"
_RESOLVE_COMPOUND = 'mutation { resolveReviewThread(input: {threadId: "PRRT_kwDOSYNTH003"}) { thread { isResolved } } }'
_COMMENTS = "repos/example-org/example-repo/pulls/12/comments"
_REPLY = f"{_COMMENTS}/123/replies"

REVIEW_COMMANDS = (
    f"gh api graphql -f query={shlex.quote(_RESOLVE_LITERAL)}",
    f"gh api graphql -f query={shlex.quote(_RESOLVE_VARIABLE)} -f t=PRRT_kwDOSYNTH002",
    f"gh api {_REPLY} -f body={shlex.quote(_REPLY_BODY)}",
    f"gh api {_COMMENTS} && gh api graphql -f query={shlex.quote(_RESOLVE_COMPOUND)}",
)
# One recorded argv per gh invocation the commands above make, in order.
EXPECTED_GH_CALLS = (
    ("api", "graphql", "-f", f"query={_RESOLVE_LITERAL}"),
    ("api", "graphql", "-f", f"query={_RESOLVE_VARIABLE}", "-f", "t=PRRT_kwDOSYNTH002"),
    ("api", _REPLY, "-f", f"body={_REPLY_BODY}"),
    ("api", _COMMENTS),
    ("api", "graphql", "-f", f"query={_RESOLVE_COMPOUND}"),
)
DELETE_COMMAND = "gh repo delete example-org/example-repo --yes"


def gh_stub_script(log: Path) -> str:
    """A POSIX stand-in that records argv and prints sample JSON; it never opens a socket."""
    return (
        "#!/bin/sh\n"
        f"{{ for a in \"$@\"; do printf '%s\\037' \"$a\"; done; printf '\\n'; }} >> {shlex.quote(str(log))}\n"
        'case "$*" in\n'
        '*graphql*) printf \'%s\\n\' \'{"data":{"resolveReviewThread":{"thread":{"isResolved":true}}}}\' ;;\n'
        '*/replies*) printf \'%s\\n\' \'{"id":456,"body":"reply recorded"}\' ;;\n'
        '*search/issues*) printf \'%s\n\' \'{"total_count":1,"incomplete_results":false,"items":[{"number":12,"title":"Add metrics","state":"open","html_url":"https://github.com/example-org/example-repo/pull/12","pull_request":{}}]}\' ;;\n'
        '*) printf \'%s\\n\' \'[{"id":123,"user":{"login":"reviewer"},"body":"Please rename the helper"}]\' ;;\n'
        "esac\n"
        "exit 0\n"
    )


def gh_stub_python(log: Path) -> str:
    """The same stand-in for Windows, where a shell finds commands only through PATHEXT."""
    return (
        "import sys\n"
        "args = sys.argv[1:]\n"
        f"with open({str(log)!r}, 'a', encoding='utf-8', newline='\\n') as log:\n"
        "    log.write(''.join(arg + '\\x1f' for arg in args) + '\\n')\n"
        "joined = ' '.join(args)\n"
        "if 'graphql' in joined:\n"
        "    out = '{\"data\":{\"resolveReviewThread\":{\"thread\":{\"isResolved\":true}}}}'\n"
        "elif '/replies' in joined:\n"
        "    out = '{\"id\":456,\"body\":\"reply recorded\"}'\n"
        "elif 'search/issues' in joined:\n"
        "    out = '{\"total_count\":1,\"incomplete_results\":false,\"items\":[{\"number\":12,\"title\":\"Add metrics\",\"state\":\"open\",\"html_url\":\"https://github.com/example-org/example-repo/pull/12\",\"pull_request\":{}}]}'\n"
        "else:\n"
        "    out = '[{\"id\":123,\"user\":{\"login\":\"reviewer\"},\"body\":\"Please rename the helper\"}]'\n"
        "sys.stdout.buffer.write(out.encode() + b'\\n')\n"
    )


def write_gh_stub(bin_dir: Path, workspace: Path) -> None:
    stub = bin_dir / "gh"
    stub.write_text(gh_stub_script(workspace / GH_LOG), encoding="utf-8", newline="\n")
    stub.chmod(0o700)
    write_windows_launcher(bin_dir, "gh", gh_stub_python(workspace / GH_LOG))


def recorded_gh_calls(workspace: Path) -> list[tuple[str, ...]] | None:
    """Return recorded argv tuples, or None when the stub never ran."""
    log = workspace / GH_LOG
    try:
        text = log.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    return [tuple(line.split(SEPARATOR)[:-1]) for line in text.splitlines()]


def _is_lookup_call(call: tuple[str, ...]) -> bool:
    """One `gh api` issue-search request carrying the case's query, scoped to its repository."""
    queries = [arg for arg in call if arg.startswith("q=")]
    return (
        call[:1] == ("api",)
        and "/search/issues" in call
        and len(queries) == 1
        and queries == [f"q={GITHUB_LOOKUP_QUERY} repo:{GITHUB_LOOKUP_REPO} is:pr"]
    )


def github_checks(workspace: Path, scenario_id: str) -> dict[str, bool]:
    if scenario_id == GITHUB_REVIEW_CASE:
        return {"github-stub-calls-exact": recorded_gh_calls(workspace) == list(EXPECTED_GH_CALLS)}
    if scenario_id == GITHUB_LOOKUP_CASE:
        calls = recorded_gh_calls(workspace)
        return {"github-lookup-ran-once": calls is not None and len(calls) == 1 and _is_lookup_call(calls[0])}
    return {}


def add_linked_worktree(main: Path, home: Path, environment: dict[str, str]) -> Path:
    """Create a linked worktree beside the main checkout, under the fixture's private home."""
    worktree = home / WORKTREE_NAME
    subprocess.run(
        ["git", "-C", str(main), "worktree", "add", "--quiet", "-b", "linked", str(worktree)],
        env=environment,
        check=True,
        capture_output=True,
        timeout=15,
    )
    return worktree


def worktree_checks(fixture_home: Path, workspace: Path, scenario_id: str, before: str, after: str) -> dict[str, bool]:
    """Bind the edit to the linked worktree and prove the main checkout stayed unchanged."""
    if scenario_id != WORKTREE_CASE:
        return {}

    def text(path: Path) -> str | None:
        try:
            return None if path.is_symlink() else path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return None

    linked = fixture_home / WORKTREE_NAME
    return {
        "linked-worktree-settings-exact": text(linked / "src/settings.ts") == after,
        "linked-worktree-note-exact": text(linked / "docs/change.md") == "Retry limit increased from 3 to 5.\n",
        "main-checkout-settings-unchanged": text(workspace / "src/settings.ts") == before,
    }


def configure_github_review_controls(daemon: Any, guard_home: Path) -> dict[str, Any]:
    """Sign the GitHub extension and every one of its permissions as enabled."""
    from codex_plugin_scanner.guard.runtime.github_capability_contract import github_capability_contracts

    from .extension_adapters import configure_extension_controls

    permissions = [contract.permission_id for contract in github_capability_contracts()]
    revision = configure_extension_controls(daemon, guard_home, GITHUB_EXTENSION_ID, enabled_permissions=permissions)
    return {
        "extension_id": GITHUB_EXTENSION_ID,
        "enabled_permissions": permissions,
        "control_revision": revision,
    }
