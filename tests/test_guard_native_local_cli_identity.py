"""The Python side only accepts well-formed local CLI identities from native."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_local_cli_identity as module

_VALID = {
    "cli_id": "local-cli.eslint-144fb167",
    "name": "eslint",
    "kind": "executable",
    "identity_hash": "1fe2e43491b55ef10ac3bb3b8446a48cd4bf6714b2beaa7da04ef2b091b2c565",
}


def test_a_well_formed_identity_is_accepted() -> None:
    assert module.valid_local_cli_identity(dict(_VALID))


@pytest.mark.parametrize(
    "identity",
    [
        None,
        {**_VALID, "extra": "x"},
        {**_VALID, "kind": "package"},
        {**_VALID, "identity_hash": "AB" * 32},
        {**_VALID, "cli_id": "local-cli.Bad_ID"},
        {**_VALID, "cli_id": "local-cli.a-b-c-d-e-f-g-h-i-j"},
        {**_VALID, "name": 3},
    ],
)
def test_a_malformed_identity_is_rejected(identity: object) -> None:
    assert not module.valid_local_cli_identity(identity)


def test_no_resident_answer_for_the_local_cli_step_is_the_host_outage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Python used to pick the action here: review while a block rule existed,
    # the action unchanged otherwise. The resident holds an unverifiable grant
    # for review itself (``an_unreadable_grant_is_unverified`` in Rust); no
    # answer at all is an outage the hook answers with the host outage
    # response, as the direct hook path does, whatever the store holds.
    from codex_plugin_scanner.guard.native_hook_decision import NativeHookDecisionError
    from tests import runtime_wrapper_support

    monkeypatch.setattr(runtime_wrapper_support, "native_local_cli_hook", lambda *_args, **_kwargs: None)

    class Store:
        guard_home = tmp_path
        path = tmp_path / "guard.db"
        guard_source = "local"

        def has_local_cli_block_rules(self) -> bool:
            raise AssertionError("the transport must not probe the store")

    for action in ("allow", "warn", "review", "block"):
        for grant_allowed in (True, False):
            with pytest.raises(NativeHookDecisionError) as raised:
                runtime_wrapper_support.local_cli_grant_action(
                    store=Store(),  # type: ignore[arg-type]
                    command="tool",
                    cwd=tmp_path,
                    home_dir=tmp_path,
                    current_action=action,  # type: ignore[arg-type]
                    grant_allowed=grant_allowed,
                )
            assert raised.value.code == "native_local_cli_hook_unavailable"
    # No command launches no CLI: nothing to ask, the action stands.
    assert (
        runtime_wrapper_support.local_cli_grant_action(
            store=Store(),  # type: ignore[arg-type]
            command=None,
            cwd=tmp_path,
            home_dir=tmp_path,
            current_action="allow",
            grant_allowed=True,
        )
        == "allow"
    )
