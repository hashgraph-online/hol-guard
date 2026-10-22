"""Keep the publisher's binding memo out of tests that do not ask for it."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import native_command_control_binding_memo


@pytest.fixture(autouse=True)
def _command_control_binding_memo(monkeypatch: pytest.MonkeyPatch) -> None:
    # Tests swap binding inputs the memo does not key on (a patched authority
    # read, a replaced view) and count the connections a read opens, so the
    # memo stays out of the way unless a test restores its key.
    native_command_control_binding_memo.forget()
    monkeypatch.setattr(native_command_control_binding_memo, "input_key", lambda _store: None)
