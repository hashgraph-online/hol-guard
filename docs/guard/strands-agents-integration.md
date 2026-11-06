# Strands Agents intervention

HOL Guard ships a reusable Strands `InterventionHandler` for **command-bearing tools**. It evaluates the command before tool execution and fails closed unless HOL Guard explicitly classifies the command as benign.

This integration is intentionally narrow. It does not claim that arbitrary Strands tools are automatically protected, and HOL Guard's `command test` surface is side-effect-free command inspection rather than a final Guard policy decision.

## Install

The vended intervention is part of HOL Guard 3.x, not an alpha-only API. However, as of October 30, 2026, HOL Guard 3.58.x pins `idna==3.15`. The Strands catalog maintainer reported that a plain `pip install strands-agents hol-guard` backtracked to HOL Guard 2.2.x, which does **not** include this intervention. The exact `idna` pin was removed in the 3.59.0 prerelease series, starting with 3.59.0a13 ([dependency change](https://github.com/hashgraph-online/hol-guard/pull/6506)).

Until a compatible stable 3.59.x release is published, explicitly select a published 3.59 prerelease and inspect the installed package and import:

```bash
python -m pip install --pre "hol-guard>=3.59.0a13,<4" "strands-agents>=1.53,<2"
python -m pip show hol-guard strands-agents
python -c "from codex_plugin_scanner.guard.strands_intervention import HolGuardIntervention; print(HolGuardIntervention.__name__)"
```

Do not treat successful dependency resolution as proof the integration is enforcing policy. Confirm that pip selected HOL Guard 3.59 or later, and test your own tool boundary as described below. The commands above check installation and import only; they do not run a Strands agent or test downstream execution.

Once a compatible stable HOL Guard 3.59.x (or newer 3.x) is released, the intended stable-only installation is:

```bash
python -m pip install "hol-guard>=3.59,<4" "strands-agents>=1.53,<2"
```

Pin the exact compatible versions you actually tested. Guard Cloud is not required for this local inspection path.

## Attach the intervention

Map each command-bearing Strands tool name to the input field that contains its command text. Tools not included in this mapping are left unchanged.

```python
from strands import Agent
from codex_plugin_scanner.guard.strands_intervention import HolGuardIntervention

hol_guard = HolGuardIntervention(
    {
        "shell": "command",
        "terminal": "command",
    }
)

agent = Agent(interventions=[hol_guard])
```

`HolGuardIntervention.before_tool_call(...)` runs immediately before the protected tool call. For each mapped tool it invokes:

```bash
hol-guard command test '<command>' --json
```

The intervention returns Strands `Proceed` only when both conditions are true:

- `classification.explicitly_benign` is `true`;
- `minimum_action` is `allow`.

Every other result returns Strands `Deny`, so the protected tool does not execute. The handler also sets Strands `on_error = "deny"`, preserving fail-closed behavior if the intervention itself raises unexpectedly.

## Security boundary

`hol-guard command test` parses and classifies the command without executing it or persisting Guard state. Its JSON includes `classification.explicitly_benign`, structured rule matches, `minimum_action`, and `policy_evaluation: "not_run"`.

For this intervention:

- explicitly benign + `allow` proceeds;
- review, risky, unknown, malformed, timeout, unavailable Guard, non-zero CLI exit, or unexpected output denies before execution;
- mapped command tools with missing or malformed command input are denied;
- unmapped tools proceed unchanged;
- the intervention does not claim full HOL Guard runtime policy, approvals, receipts, or native harness-wide coverage.

For full runtime enforcement, approvals, receipts, and harness-specific behavior, use one of the harnesses listed in the [HOL Guard support matrix](./harness-support.md).

## Verify zero downstream execution

When integrating a command tool, test the execution boundary directly. Use a fake command tool with a counter and assert:

1. an explicitly benign command reaches the tool exactly once;
2. a command that Guard marks for review never reaches the tool;
3. malformed Guard output, timeout, a missing Guard executable, or malformed command input never reaches the tool.

This is the core ordering property of the vended intervention: HOL Guard decides before the command-bearing tool can produce side effects.
