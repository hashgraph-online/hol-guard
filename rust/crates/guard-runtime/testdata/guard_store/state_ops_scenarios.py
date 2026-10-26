# ruff: noqa: E501
"""Scenarios for the artifact-diff, OAuth-source and keyring-mirror parity vectors.

Shared by the recorder (which runs them through the ORIGINAL Python store) and
the Python parity test (which replays them through the new wrappers). Steps are
either `{"sql": [(statement, params), ...]}` or `{"method", "kwargs"}`.
"""

from __future__ import annotations

NOW = "2026-10-10T12:00:00.000000+00:00"
T1 = "2026-10-10T10:00:00+00:00"
T2 = "2026-10-10T10:05:00+00:00"
KEY = "oauth_local_credentials"


def call(method: str, label: str = "", **kwargs: object) -> dict[str, object]:
    return {"method": method, "label": label, "kwargs": kwargs}


def sql(label: str, *statements: tuple[str, tuple[object, ...]]) -> dict[str, object]:
    return {"label": label, "sql": list(statements)}


def diff(
    artifact_id: str, harness: str, fields: str, previous: str | None, current: str
) -> tuple[str, tuple[object, ...]]:
    return (
        "insert into artifact_diffs (artifact_id, harness, changed_fields_json, previous_hash, current_hash, recorded_at) values (?, ?, ?, ?, ?, ?)",
        (artifact_id, harness, fields, previous, current, T1),
    )


def state(state_key: str, payload: str) -> tuple[str, tuple[object, ...]]:
    return (
        "insert or replace into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)",
        (state_key, payload, T1),
    )


PROVENANCE = {"source": "mdm", "revision": 3, "nested": {"z": 1, "a": [1, 2]}}
MANAGED = {"keys": [{"kid": "m1", "pub": "é"}], "version": 1}
LOCAL = {"keys": [], "version": 1}

SCENARIOS: list[dict[str, object]] = [
    {
        "name": "latest_diff",
        "steps": [
            call("get_latest_diff", "empty", harness="codex", artifact_id="a:1"),
            sql(
                "seed",
                diff("a:1", "codex", '["version", "hash"]', None, "h1"),
                diff("a:1", "codex", '{"a": 1}', "h1", "h2"),
                diff("a:2", "codex", "[]", "x", "y"),
                diff("a:1", "claude-code", '["other"]', "p", "q"),
            ),
            call("get_latest_diff", "newest wins", harness="codex", artifact_id="a:1"),
            call("get_latest_diff", "other harness", harness="claude-code", artifact_id="a:1"),
            call("get_latest_diff", "other artifact", harness="codex", artifact_id="a:2"),
            call("get_latest_diff", "unknown", harness="codex", artifact_id="a:9"),
            sql("later row", diff("a:1", "codex", '{"big": 12345678901234567890, "f": 1.5, "s": "é"}', "h2", "h3")),
            call("get_latest_diff", "numbers and unicode", harness="codex", artifact_id="a:1"),
            sql("corrupt", diff("a:3", "codex", "{not json", None, "z")),
            call("get_latest_diff", "invalid changed_fields", harness="codex", artifact_id="a:3"),
        ],
    },
    {
        "name": "oauth_sources",
        "steps": [
            call("list_oauth_sources", "empty"),
            sql("default", state(KEY, '{"issuer": "https://hol.org", "workspace_id": "ws-1", "extra": 1}')),
            call("list_oauth_sources", "default only"),
            sql(
                "more",
                state(f"{KEY}:work", '{"issuer": "https://work.example", "workspace_id": "ws-2"}'),
                state(f"{KEY}:team-b", '{"issuer": 7, "workspace_id": null}'),
                state(f"{KEY}:list", "[1, 2]"),
                state(f"{KEY}:", '{"issuer": "i"}'),
            ),
            call("list_oauth_sources", "named sources"),
            sql(
                "like quirks",
                state("OAUTH_LOCAL_CREDENTIALS:upper", '{"issuer": "upper"}'),
                state("oauth-local-credentials:dash", '{"issuer": "dash"}'),
                state(f"{KEY}x", '{"issuer": "nosep"}'),
            ),
            call("list_oauth_sources", "like matches startswith skips"),
            sql("corrupt", state(f"{KEY}:bad", "{oops")),
            call("list_oauth_sources", "invalid payload"),
        ],
    },
    {
        "name": "keyring_mirror",
        "steps": [
            call(
                "reconcile_managed_policy_bundle_keyring_state",
                "unconfigured no marker",
                managed_keyring=None,
                quarantined_local_keyring=None,
                provenance=None,
                now=NOW,
            ),
            sql("stray anchor", state("policy_bundle_keyring", '{"keys": [{"kid": "rogue"}]}')),
            call(
                "reconcile_managed_policy_bundle_keyring_state",
                "unconfigured no marker keeps rows",
                managed_keyring=None,
                quarantined_local_keyring=None,
                provenance=None,
                now=NOW,
            ),
            call(
                "reconcile_managed_policy_bundle_keyring_state",
                "forced clear removes rows",
                managed_keyring=None,
                quarantined_local_keyring=None,
                provenance=None,
                now=NOW,
                force_clear=True,
            ),
            call(
                "reconcile_managed_policy_bundle_keyring_state",
                "configured writes three rows",
                managed_keyring=MANAGED,
                quarantined_local_keyring=LOCAL,
                provenance=PROVENANCE,
                now=T1,
            ),
            call(
                "reconcile_managed_policy_bundle_keyring_state",
                "configured updates in place",
                managed_keyring={**MANAGED, "version": 2},
                quarantined_local_keyring=LOCAL,
                provenance=PROVENANCE,
                now=T2,
            ),
            call(
                "reconcile_managed_policy_bundle_keyring_state",
                "incomplete",
                managed_keyring=MANAGED,
                quarantined_local_keyring=None,
                provenance=PROVENANCE,
                now=NOW,
            ),
            call(
                "reconcile_managed_policy_bundle_keyring_state",
                "nan rejected",
                managed_keyring={"bad": float("nan")},
                quarantined_local_keyring=LOCAL,
                provenance=PROVENANCE,
                now=NOW,
            ),
            call(
                "reconcile_managed_policy_bundle_keyring_state",
                "unconfigured with marker clears",
                managed_keyring=None,
                quarantined_local_keyring=None,
                provenance=None,
                now=NOW,
            ),
        ],
    },
]
