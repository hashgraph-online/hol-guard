from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import local_cli_grant_decision as decision
from codex_plugin_scanner.guard.local_cli_hook import apply_local_cli_grant
from codex_plugin_scanner.guard.local_cli_trust import matching_local_cli_grant, utc_now
from codex_plugin_scanner.guard.native_local_cli_grant import NativeLocalCliGrant
from codex_plugin_scanner.guard.native_local_cli_identity import LocalCliIdentityUnavailableError
from codex_plugin_scanner.guard.runtime.local_cli_identity import identify_unlisted_cli
from codex_plugin_scanner.guard.store import GuardStore

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401


def _blocked_store(tmp_path: Path):
    script = tmp_path / "ship.py"
    script.write_text("print('hi')\n", encoding="utf-8")
    command = f"python3 {script} deploy"
    identity = identify_unlisted_cli(command, cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None
    store = GuardStore(tmp_path / "home")
    store.record_local_cli_observation(identity, seen_at=utc_now())
    store.upsert_local_cli_grant(identity=identity, state="blocked", expected_revision=0, updated_at=utc_now())
    return store, command, identity


@pytest.mark.parametrize("answer", ["none_reply", "other_identity"])
def test_native_failure_is_unavailable_never_no_grant(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: str
) -> None:
    store, command, identity = _blocked_store(tmp_path)
    reply = (
        None
        if answer == "none_reply"
        else NativeLocalCliGrant(state="allowed", cli_id=identity.cli_id, identity_hash="f" * 64)
    )
    monkeypatch.setattr(decision, "native_local_cli_grant", lambda **_kwargs: reply)

    with pytest.raises(LocalCliIdentityUnavailableError):
        matching_local_cli_grant(store=store, command=command, cwd=tmp_path, home_dir=tmp_path, current_action="allow")

    # A stored block rule exists, so an allowed command is held for review
    # instead of being waved through or silently treated as ungranted.
    assert (
        apply_local_cli_grant(store=store, command=command, cwd=tmp_path, home_dir=tmp_path, current_action="allow")
        == "review"
    )
    assert (
        apply_local_cli_grant(store=store, command=command, cwd=tmp_path, home_dir=tmp_path, current_action="block")
        == "block"
    )


def test_native_answer_is_presented_not_recomputed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    store, command, identity = _blocked_store(tmp_path)
    calls: list[dict[str, object]] = []

    def answer(**kwargs: object) -> NativeLocalCliGrant:
        calls.append(kwargs)
        return NativeLocalCliGrant(state="allowed", cli_id=identity.cli_id, identity_hash=identity.identity_hash)

    monkeypatch.setattr(decision, "native_local_cli_grant", answer)

    # The store row says blocked; only the resident's answer decides.
    assert (
        apply_local_cli_grant(store=store, command=command, cwd=tmp_path, home_dir=tmp_path, current_action="review")
        == "allow"
    )
    assert calls[0]["current_action"] == "review"
    assert calls[0]["source"] == identity.identity_source
