from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.network_policy_contract import ProcessTreeIdentity
from codex_plugin_scanner.guard.runtime.network_process_lifecycle import ProcessTreeLifecycle


def _identity(*, digest: str = "c" * 64) -> ProcessTreeIdentity:
    return ProcessTreeIdentity("install.alpha", "session.alpha", 42, 1_000, digest)


def test_process_tree_session_cannot_be_rebound_while_active() -> None:
    lifecycle = ProcessTreeLifecycle()
    identity = _identity()
    lifecycle.start(identity)
    lifecycle.start(identity)

    with pytest.raises(RuntimeError, match="identity changed"):
        lifecycle.start(_identity(digest="d" * 64))
    assert lifecycle.resolve("install.alpha", "session.alpha") == identity


def test_stop_requires_exact_identity_and_removes_tree_atomically() -> None:
    lifecycle = ProcessTreeLifecycle()
    identity = _identity()
    lifecycle.start(identity)

    assert not lifecycle.stop(_identity(digest="d" * 64))
    assert lifecycle.stop(identity)
    assert lifecycle.resolve("install.alpha", "session.alpha") is None
    assert lifecycle.active() == ()
