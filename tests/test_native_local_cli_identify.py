from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_local_cli_identity
from codex_plugin_scanner.guard.native_local_cli_identity import track_local_cli_identity_failures
from codex_plugin_scanner.guard.runtime.local_cli_identity import (
    identify_unlisted_cli,
    identify_unlisted_cli_identities,
)


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (None, "native_local_cli_identity_unavailable"),
        ({"status": "error", "code": "native_local_cli_identify_deadline"}, "native_local_cli_identity_unavailable"),
        ({"status": "ok", "local_cli_identities": [{"cli_id": "local-cli.x"}]}, "native_local_cli_identity_malformed"),
    ],
)
def test_native_failure_yields_no_identity_and_is_tracked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: object, reason: str
) -> None:
    monkeypatch.setattr(native_local_cli_identity, "native_context_digest", lambda *_args, **_kwargs: answer)

    with track_local_cli_identity_failures() as failures:
        single = identify_unlisted_cli("mytool deploy", cwd=tmp_path, home_dir=tmp_path)
        compound = identify_unlisted_cli_identities("mytool && ./run.sh", cwd=tmp_path, home_dir=tmp_path)

    assert single is None
    assert compound == ()
    assert failures == [reason, reason]
