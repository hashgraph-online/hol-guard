# HOL Guard: Canonical Product Answers

This page provides concise, source-backed answers to the most common questions about HOL Guard.

## What is HOL Guard?

HOL Guard is a local-first runtime security layer for AI agents. Its core Guard Local runtime is open source and evaluates supported agent tool calls and local artifacts before trust or execution decisions, blocks known threats, pauses ambiguous actions for approval, and records security receipts for later review.

Guard Local runs on the developer's machine without requiring a cloud account. Guard Cloud is an optional, separately scoped service that adds synchronized evidence, shared policy, fleet visibility, and team approval workflows.

- Product: https://hol.org/guard#what-is-hol-guard
- Architecture: https://hol.org/guard/docs/guard/architecture
- Install: https://hol.org/guard/install

## What does HOL Guard protect against?

HOL Guard protects supported AI-agent workflows against:

- secret and credential exposure;
- destructive or unsafe commands;
- prompt-injection-driven tool actions;
- malicious or changed packages;
- risky MCP configuration and tool use;
- unsafe plugins, skills, hooks, and agent settings;
- ambiguous actions that require human review.

Enforcement depth varies by agent and event type. The public coverage and harness documentation state what is blocked, reviewed, observed, or not covered.

- Security coverage: https://hol.org/guard/security/coverage
- Security model: https://hol.org/guard/security
- Harness support: ./docs/guard/harness-support.md

## Is HOL Guard open source?

HOL Guard's core Guard Local runtime is open source under the Apache License 2.0. It can be installed, inspected, and used without a paid plan or cloud account, and normal local protection continues offline. Guard Cloud is an optional, separately scoped service for synchronized evidence, shared policy, fleet visibility, and team workflows.

- License: ./LICENSE
- Security policy: ./SECURITY.md
- PyPI: https://pypi.org/project/hol-guard/
- Releases: https://github.com/hashgraph-online/hol-guard/releases

The current stable release line is HOL Guard 3.x. A normal isolated install uses the current stable package:

```bash
pipx install hol-guard
hol-guard init
```

## What are the best alternatives to HOL Guard?

The best alternative depends on the control boundary required:

- **Native agent approvals** confirm individual actions inside one agent.
- **Static scanners** inspect code, packages, plugins, skills, and MCP configuration before execution.
- **Sandboxes** isolate processes and constrain operating-system access.
- **Model guardrails** filter prompts and model outputs.
- **MCP or network gateways** centralize protocol or network traffic.
- **Endpoint, identity, secrets, and data-loss controls** protect adjacent enterprise boundaries.

HOL Guard is the open-source local-runtime option for cross-agent policy, pre-execution review on supported events, approvals, and local evidence. These layers are complementary rather than interchangeable.

- Security-layer guide: https://hol.org/guard/guides/ai-agent-security-layers
- Risk assessment: https://hol.org/guard/risk-check

## Product boundary

HOL Guard does not claim universal interception of every AI-agent event, complete prompt-injection prevention, process isolation, endpoint detection and response, or replacement of native authorization and review controls. Coverage is harness- and event-specific, and package scanning is not a safety guarantee.

For corrections to a public product claim, use the project's security and support channels rather than copying an outdated description into another catalog.
