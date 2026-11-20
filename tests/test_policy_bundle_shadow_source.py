"""Which stored policy bundle shadows a v2 candidate, as the runtime chooses it."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime import runner_policy_shadow as authority


def test_the_shadow_is_the_stored_legacy_bundle_unless_it_predates_the_candidate() -> None:
    candidate = {
        "contractVersion": "guard-policy-bundle.v2",
        "issuedAt": "2026-11-20T10:00:00Z",
        "payload": {"spec": {"defaults": {"mode": "observe"}}},
    }
    same_publication = {"contractVersion": "guard-policy-bundle.v1", "issuedAt": "2026-11-20T10:00:00+00:00"}
    older_publication = {"contractVersion": "guard-policy-bundle.v1", "issuedAt": "2026-11-19T10:00:00Z"}
    active_v2 = {"contractVersion": "guard-policy-bundle.v2", "issuedAt": "2026-11-21T10:00:00Z"}
    source = authority.policy_shadow_source

    assert source(candidate, stored_legacy=same_publication, existing=None) == ("stored", True)
    assert source(candidate, stored_legacy=older_publication, existing=same_publication) == (None, True)
    assert source(candidate, stored_legacy=None, existing=same_publication) == ("existing", True)
    assert source(candidate, stored_legacy="not-a-bundle", existing=active_v2) == (None, True)


def test_the_shadow_request_carries_only_the_fields_the_choice_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict[str, object]] = []

    def _answer(kind: str, args: dict[str, object]) -> dict[str, object]:
        assert kind == "policy_shadow_source"
        sent.append(args)
        return {"legacy": "existing", "evaluating": False}

    monkeypatch.setattr(authority, "native_runner_authority", _answer)
    stored = {"contractVersion": "guard-policy-bundle.v1", "rules": ["x" * 64], "issuedAt": "2026-11-20T10:00:00Z"}
    candidate = {
        "contractVersion": "guard-policy-bundle.v2",
        "issuedAt": "2026-11-21T10:00:00Z",
        "payload": {"spec": {"defaults": {"mode": "enforce", "label": "x"}, "rules": ["y" * 64]}, "kind": "k"},
        "signature": "s",
    }

    assert authority.policy_shadow_source(candidate, stored_legacy=stored, existing=["x"]) == ("existing", False)
    assert authority.policy_shadow_source({"a": 1}, stored_legacy=None, existing=None) == ("existing", False)
    assert sent == [
        {
            "candidate": {
                "contractVersion": "guard-policy-bundle.v2",
                "issuedAt": "2026-11-21T10:00:00Z",
                "payload": {"spec": {"defaults": {"mode": "enforce"}}},
            },
            "stored_legacy": {"contractVersion": "guard-policy-bundle.v1", "issuedAt": "2026-11-20T10:00:00Z"},
            "existing": None,
        },
        {"candidate": {}, "stored_legacy": None, "existing": None},
    ]
