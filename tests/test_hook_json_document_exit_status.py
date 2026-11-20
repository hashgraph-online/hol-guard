"""The JSON document route takes its process status from the resident.

The directive decides both the document and the status it exits with. A
replayed decision relaxes ``exit_code`` to 0 so the fallback envelope
acknowledges without re-blocking; the document answers before that branch, so
it carries ``json_exit_code`` — the status the harness itself expects.
"""

from __future__ import annotations

from codex_plugin_scanner.guard.cli import commands_support_hook_payload as payload


class TestTheRouteReportsTheStatusItWasGiven:
    def test_the_python_exit_table_is_gone_from_this_route(self) -> None:
        assert not hasattr(payload, "native_hook_verdict_exit_code")
