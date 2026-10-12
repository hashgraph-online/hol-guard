from codex_plugin_scanner.guard.runtime.secret_file_request_services.request_models import ToolActionRequestMatch
from codex_plugin_scanner.guard.runtime.secret_file_request_services.tool_action_requests import (
    _request_with_wrapper_context,
)


def test_wrapper_context_keeps_the_script_read_identity() -> None:
    request = ToolActionRequestMatch(
        tool_name="Bash",
        normalized_tool_name="bash",
        command_text="./run.sh",
        action_class="local script execution shell command",
        reason="review",
        script_read_identity_sha256="a" * 64,
    )

    wrapped = _request_with_wrapper_context(request, raw_command_text="bash -c ./run.sh", wrapper_chain=("bash",))

    assert wrapped.script_read_identity_sha256 == "a" * 64
    assert wrapped.raw_command_text == "bash -c ./run.sh"
    assert wrapped.wrapper_chain == ("bash",)
