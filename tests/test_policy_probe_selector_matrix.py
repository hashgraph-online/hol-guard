"""Every indexed generic policy selector keeps its conjunctive conditions."""

import sqlite3

from codex_plugin_scanner.guard.runtime.approval_context import build_approval_context_token
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_policy import _bounded_non_consuming_policy_rows


def test_non_consuming_policy_probe_partitions_preserve_every_scope_selector(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact_id = "codex:project:tool-action:selector-matrix"
    context_hash = build_approval_context_token(
        identity={"artifact_id": "codex:project:mcp-tool:read", "workspace": "/workspace/a"},
        content="sha256:selector-matrix",
        capabilities=["filesystem:read"],
        policy={"version": "policy-v1"},
        sandbox={"profile": "workspace-read"},
    )
    runtime_hash = "runtime-exact:selector-matrix"
    matching_rows = (
        ("artifact-null", "codex", "artifact", artifact_id, None, None, None),
        ("artifact-context", "codex", "artifact", artifact_id, context_hash, None, None),
        ("artifact-runtime", "*", "artifact", artifact_id, runtime_hash, None, None),
        (
            "workspace-broad",
            "codex",
            "workspace",
            None,
            None,
            "workspace:sha256:current",
            None,
        ),
        ("workspace-broad-context", "codex", "workspace", None, context_hash, "workspace:sha256:current", None),
        ("workspace-null", "codex", "workspace", artifact_id, None, "/workspace/current", None),
        (
            "workspace-context",
            "*",
            "workspace",
            artifact_id,
            context_hash,
            "workspace:sha256:current",
            None,
        ),
        ("publisher-null", "codex", "publisher", None, None, None, "publisher-current"),
        ("publisher-context", "codex", "publisher", None, context_hash, None, "publisher-current"),
        ("publisher-legacy", "*", "publisher", None, "sha256:legacy", None, "publisher-current"),
        ("harness-broad", "codex", "harness", None, None, None, None),
        ("harness-context", "codex", "harness", "family:tool-action", context_hash, None, None),
        ("harness-runtime", "*", "harness", "family:tool-action", runtime_hash, None, None),
        ("harness-legacy", "codex", "harness", "family:tool-action", "sha256:legacy", None, None),
        ("global-broad", "codex", "global", None, None, None, None),
        ("global-artifact", "codex", "global", artifact_id, context_hash, None, None),
        ("global-family", "*", "global", "family:tool-action", runtime_hash, None, None),
        ("global-legacy", "codex", "global", "family:tool-action", "sha256:legacy", None, None),
    )
    ignored_rows = (
        ("artifact-other-context", "codex", "artifact", artifact_id, "guard-approval-context:v1:other", None, None),
        (
            "workspace-broad-other-context",
            "codex",
            "workspace",
            None,
            "guard-approval-context:v1:other",
            "workspace:sha256:current",
            None,
        ),
        (
            "workspace-runtime",
            "codex",
            "workspace",
            artifact_id,
            runtime_hash,
            "workspace:sha256:current",
            None,
        ),
        (
            "publisher-other-context",
            "codex",
            "publisher",
            None,
            "guard-approval-context:v1:other",
            None,
            "publisher-current",
        ),
        (
            "harness-other-family",
            "codex",
            "harness",
            "family:file-read",
            "sha256:legacy",
            None,
            None,
        ),
        (
            "global-other-context",
            "codex",
            "global",
            "family:tool-action",
            "guard-approval-context:v1:other",
            None,
            None,
        ),
        ("other-harness", "cursor", "global", None, None, None, None),
    )
    with sqlite3.connect(store.path) as connection:
        connection.executemany(
            """
            insert into policy_decisions (
              reason, harness, scope, artifact_id, artifact_hash, workspace, publisher,
              action, source, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, 'allow', 'team-policy', '2026-07-17T12:00:00+00:00')
            """,
            (*matching_rows, *ignored_rows),
        )
        connection.row_factory = sqlite3.Row
        rows = _bounded_non_consuming_policy_rows(
            connection,
            harness="codex",
            artifact_id=artifact_id,
            artifact_hash=context_hash,
            runtime_exact_match_key=runtime_hash,
            global_runtime_exact_match_key=runtime_hash,
            workspace_key="workspace:sha256:current",
            workspace="/workspace/current",
            publisher="publisher-current",
            action_family_key="family:tool-action",
            current_time="2026-07-17T12:01:00+00:00",
        )

    assert {str(row["reason"]) for row in rows} == {row[0] for row in matching_rows}
