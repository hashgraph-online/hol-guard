"""Answer the native `hook-exit-code` op with a fixed status.

The table is native and tested there; a test of the Python outage path that
needs a particular status states it here instead of restating the table.
"""

from __future__ import annotations

import pytest

_TARGET = "codex_plugin_scanner.guard.mdm.runtime_request.runtime_answer"


def native_exit_code_is(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    def answer(feature: str, command: str, _request: object, **_kwargs: object) -> dict[str, object]:
        assert (feature, command) == ("native-hook-exit-code-v1", "hook-exit-code")
        return {"exit_code": code}

    monkeypatch.setattr(_TARGET, answer)
