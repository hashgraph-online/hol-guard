# Strands Agents command inspection

HOL Guard can be used from a Strands Agents `BeforeToolCallEvent` hook to inspect **command-bearing tools before execution**.

This recipe is intentionally narrow. HOL Guard does not currently ship a native `strands` harness adapter, and `hol-guard command test` is a side-effect-free command inspection surface rather than a final HOL Guard policy decision. The integration below cancels a Strands tool call unless the command is explicitly classified as benign.

## Install

The `command test` inspection surface is currently in the HOL Guard 3.x alpha channel. Install an exact published alpha separately from Strands. For example, the current release at the time of this guide is:

```bash
pipx install --force "hol-guard==3.0.0a249"
```

Check the [HOL Guard prereleases](https://github.com/hashgraph-online/hol-guard/releases) for a newer 3.x alpha before pinning a production evaluation.

Guard Cloud is not required for this local inspection path.

## Hook a command tool

Strands emits `BeforeToolCallEvent` immediately before a selected tool is invoked. Setting `event.cancel_tool` stops that tool call and returns an error tool result instead of invoking the tool.

The example below assumes a tool named `shell` whose input contains a string `command` field. Adapt the tool name and input key to the command tool you actually expose.

```python
from __future__ import annotations

import json
import subprocess

from strands import Agent
from strands.hooks import BeforeToolCallEvent


def inspect_with_hol_guard(command: str) -> dict:
    completed = subprocess.run(
        ["hol-guard", "command", "test", command, "--json"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("HOL Guard command inspection failed")
    return json.loads(completed.stdout)


def hol_guard_before_tool(event: BeforeToolCallEvent) -> None:
    tool_use = event.tool_use
    if tool_use.get("name") != "shell":
        return

    tool_input = tool_use.get("input")
    if not isinstance(tool_input, dict):
        event.cancel_tool = "HOL Guard: command tool input was not structured as expected."
        return

    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        event.cancel_tool = "HOL Guard: command text is missing or invalid."
        return

    try:
        result = inspect_with_hol_guard(command)
    except (OSError, subprocess.TimeoutExpired, RuntimeError, json.JSONDecodeError):
        event.cancel_tool = "HOL Guard: command inspection was unavailable or invalid."
        return

    classification = result.get("classification")
    explicitly_benign = isinstance(classification, dict) and classification.get("explicitly_benign") is True
    minimum_action = result.get("minimum_action")

    if not explicitly_benign or minimum_action != "allow":
        event.cancel_tool = "HOL Guard: command requires review before execution."


agent = Agent()
agent.add_hook(hol_guard_before_tool)
```

## Security boundary

`hol-guard command test` parses and classifies the command without executing it or persisting Guard state. Its JSON includes `classification.explicitly_benign`, structured rule matches, `minimum_action`, and `policy_evaluation: "not_run"`.

For this recipe:

- only an explicitly benign result with `minimum_action == "allow"` proceeds;
- review, risky, unknown, malformed, timeout, unavailable Guard, or unexpected output cancels the Strands tool call;
- the hook does not claim full HOL Guard runtime policy, approvals, receipts, or native Strands harness protection;
- non-command tools are unchanged unless you explicitly map them to another supported HOL Guard surface.

For full runtime enforcement, approvals, receipts, and harness-specific behavior, use one of the harnesses listed in the [HOL Guard support matrix](./harness-support.md).

## Verify zero downstream execution

When adapting this pattern, test the execution boundary directly. Use a fake command tool that increments a counter and assert:

1. an explicitly benign command reaches the tool exactly once;
2. a command that Guard marks for review never reaches the tool;
3. malformed Guard output, timeout, or a missing Guard executable never reaches the tool.

This protects the important ordering property: inspection happens before the command-bearing tool can produce side effects.
