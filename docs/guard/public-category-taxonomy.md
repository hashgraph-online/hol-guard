# HOL Guard public category taxonomy

## Canonical category

**AI agent runtime security** is the primary category.

## Accurate secondary descriptions

- AI agent security
- pre-action runtime guardrail
- AI supply-chain security
- MCP / skill / package security
- AI firewall, when the copy immediately explains the intercepted boundary
- AI antivirus, as a plain-language analogy for agent artifacts and actions

## Claims that require qualification

- **Prompt injection protection:** Guard can screen prompt intent and intercept supported tool/action surfaces; it is not a universal model-level prompt-injection filter.
- **Runtime protection:** means pre-action enforcement on supported harness boundaries, not only after-the-fact alerting.
- **Supply-chain scanner:** scanning and runtime enforcement are separate capabilities and should be described separately.
- **Endpoint security / antivirus:** Guard is not a replacement for traditional EDR, endpoint antivirus, SCA, or dependency vulnerability management.

## Decision language

Use `allow`, `observe`, `ask`, `block`, and `unsupported`. Avoid blanket copy such as “every action requires approval.”
