from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.trusted_local_tools import (
    local_tool_approval_eligibility,
    parse_local_tool_grant_selection,
)

pytestmark = pytest.mark.usefixtures("approval_questionnaire_mode")


def _write_event(
    path: Path,
    *,
    workspace: Path,
    command: str,
    call_id: str,
    policy_action: str | None = None,
) -> None:
    payload: dict[str, object] = {
        "session_id": "trusted-local-tool",
        "turn_id": call_id,
        "cwd": str(workspace),
        "hook_event_name": "PreToolUse",
        "model": "gpt-5.6-sol",
        "permission_mode": "bypassPermissions",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": call_id,
    }
    if policy_action is not None:
        payload["policy_action"] = policy_action
    _ = path.write_text(json.dumps(payload))


def _json_object(value: str) -> dict[str, object]:
    parsed = cast(object, json.loads(value))
    assert isinstance(parsed, Mapping)
    return dict(cast(Mapping[str, object], parsed))


def _run_hook(*, guard_home: Path, workspace: Path, event_path: Path) -> int:
    return main(
        [
            "guard",
            "hook",
            "--harness",
            "codex",
            "--home",
            str(guard_home),
            "--workspace",
            str(workspace),
            "--event-file",
            str(event_path),
        ]
    )


@pytest.fixture
def local_tool_workspace(tmp_path: Path) -> tuple[Path, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tool = workspace / "xads.mjs"
    _ = tool.write_text("export const version = 1;\n")
    return workspace, tool


@pytest.mark.usefixtures("native_context_digest")
def test_local_tool_eligibility_is_digest_bound_and_read_only(
    local_tool_workspace: tuple[Path, Path],
) -> None:
    workspace, tool = local_tool_workspace
    command = (
        "node xads.mjs request --method=GET --path=/stats "
        "--query='entity=PROMOTED_TWEET&start_time=2026-07-28T13:00:00Z'"
    )
    first = local_tool_approval_eligibility(command, cwd=workspace, home_dir=workspace)
    assert first is not None
    assert first.tool_name == "xads.mjs"
    assert first.capability == "request"
    assert first.read_only_reason == "http_get"

    varied = local_tool_approval_eligibility(
        command.replace("13:00:00Z", "20:00:00Z"),
        cwd=workspace,
        home_dir=workspace,
    )
    assert varied is not None
    assert varied.tool_identity_hash == first.tool_identity_hash

    changed_options = local_tool_approval_eligibility(
        command + " --granularity=TOTAL",
        cwd=workspace,
        home_dir=workspace,
    )
    assert changed_options is not None
    assert changed_options.tool_identity_hash != first.tool_identity_hash

    changed_semantics = local_tool_approval_eligibility(
        command + " --mode=write",
        cwd=workspace,
        home_dir=workspace,
    )
    assert changed_semantics is not None
    assert changed_semantics.tool_identity_hash != first.tool_identity_hash

    _ = tool.write_text("export const version = 2;\n")
    changed = local_tool_approval_eligibility(command, cwd=workspace, home_dir=workspace)
    assert changed is not None
    assert changed.tool_identity_hash != first.tool_identity_hash


@pytest.mark.usefixtures("native_context_digest")
def test_local_tool_eligibility_supports_verified_jq_output_processing(
    local_tool_workspace: tuple[Path, Path],
) -> None:
    workspace, _tool = local_tool_workspace
    eligibility = local_tool_approval_eligibility(
        (
            "node xads.mjs request --method=GET --path=/stats "
            + "--query='start_time=2026-07-28T13:00:00Z' | "
            + "jq '[.data[] | {id, impressions: (.metrics.impressions[0] // 0)}]'"
        ),
        cwd=workspace,
        home_dir=workspace,
    )
    assert eligibility is not None
    assert eligibility.capability == "request"
    assert eligibility.read_only_reason == "http_get"
    changed_filter = local_tool_approval_eligibility(
        "node xads.mjs request --method=GET --path=/stats | jq '.data[0]'",
        cwd=workspace,
        home_dir=workspace,
    )
    assert changed_filter is not None
    assert changed_filter.tool_identity_hash != eligibility.tool_identity_hash


def test_impeccable_local_scan_can_receive_conditional_package_trust(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    target = source / "email.tsx"
    _ = target.write_text("export const Email = () => null;\n")
    context = tmp_path / "docs"
    context.mkdir()
    command = f"IMPECCABLE_CONTEXT_DIR={context} npx impeccable --json {target}"

    eligibility = local_tool_approval_eligibility(command, cwd=tmp_path, home_dir=tmp_path)

    assert eligibility is not None
    assert eligibility.tool_name == "impeccable"
    assert eligibility.capability == "scan"
    assert eligibility.trust_basis == "package-profile"
    assert eligibility.to_payload()["allowed_durations"] == [
        "once",
        "15m",
        "1h",
        "5h",
    ]
    pinned = local_tool_approval_eligibility(
        command.replace("npx impeccable", "npx impeccable@3.3.1"),
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert pinned is not None
    assert "always" in cast(list[object], pinned.to_payload()["allowed_durations"])
    latest = local_tool_approval_eligibility(
        command.replace("npx impeccable ", "npx impeccable@latest "),
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert latest is not None
    assert latest.tool_identity_hash != eligibility.tool_identity_hash


def test_impeccable_package_trust_without_home_stays_in_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.tsx"
    _ = outside.write_text("export const Outside = () => null;\n")

    assert (
        local_tool_approval_eligibility(
            f"npx impeccable@3.3.1 --json {outside}",
            cwd=workspace,
            home_dir=None,
        )
        is None
    )


@pytest.mark.parametrize(
    "arguments",
    (
        "skills install",
        "detect https://example.test",
        "--output report.json src",
        "--json ~/.ssh",
    ),
)
def test_impeccable_package_trust_rejects_mutating_or_unsafe_calls(tmp_path: Path, arguments: str) -> None:
    (tmp_path / "src").mkdir()
    command = f"npx impeccable {arguments}"
    assert local_tool_approval_eligibility(command, cwd=tmp_path, home_dir=tmp_path) is None


def test_indefinite_trust_is_limited_to_package_profiles(
    local_tool_workspace: tuple[Path, Path],
) -> None:
    workspace, _tool = local_tool_workspace
    direct = local_tool_approval_eligibility(
        "node xads.mjs request --method=GET --path=/stats",
        cwd=workspace,
        home_dir=workspace,
    )
    assert direct is not None
    request = {"scanner_evidence": [direct.to_evidence()]}

    with pytest.raises(ValueError, match="invalid_local_tool_grant_duration"):
        _ = parse_local_tool_grant_selection(
            request,
            target="capability",
            duration="always",
            now="2026-08-02T12:00:00+00:00",
        )


@pytest.mark.parametrize(
    "command",
    (
        "node xads.mjs request --method=POST --path=/campaigns",
        "node xads.mjs request --method=POST --method=GET --path=/campaigns",
        "node xads.mjs delete --method=GET --path=/campaigns/1",
        "node xads.mjs request --method=GET --path=/stats; touch marker",
        "node xads.mjs request --method=GET --path=/stats > result.json",
        "node xads.mjs request --method=GET --path=/stats --output=result.json",
        "node xads.mjs request --method=GET --path=/stats --write",
        "node xads.mjs request -X POST --path=/campaigns",
        "node xads.mjs request --request=POST --path=/campaigns",
        "node xads.mjs request --method=GET --path=/stats -o result.json",
        "TOKEN=value node xads.mjs request --method=GET --path=/stats",
        "node -e 'process.stdout.write(\"safe\")' request --method=GET",
    ),
)
def test_local_tool_trust_rejects_mutations_and_shell_expansion(
    local_tool_workspace: tuple[Path, Path],
    command: str,
) -> None:
    workspace, _tool = local_tool_workspace
    assert local_tool_approval_eligibility(command, cwd=workspace, home_dir=workspace) is None


def test_local_tool_trust_rejects_jq_file_inputs(
    local_tool_workspace: tuple[Path, Path],
) -> None:
    workspace, _tool = local_tool_workspace
    assert (
        local_tool_approval_eligibility(
            "node xads.mjs request --method=GET --path=/stats | jq -f filter.jq",
            cwd=workspace,
            home_dir=workspace,
        )
        is None
    )
    assert (
        local_tool_approval_eligibility(
            "node xads.mjs request --method=GET --path=/stats | jq '.data' /path/to/secret",
            cwd=workspace,
            home_dir=workspace,
        )
        is None
    )
