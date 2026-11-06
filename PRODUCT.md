# Product

## Register

product

## Users

HOL Guard serves people running local AI harnesses such as Codex, Claude Code, Copilot, Cursor, Gemini, Hermes, and OpenCode. The primary user is a developer or operator in the middle of real work who needs fast, trustworthy decisions before a tool reads secrets, changes files, or makes outbound requests. They are often switching between chat, terminal, and a local approval center, so the product has to lower stress instead of adding ceremony.

## Product Purpose

HOL Guard protects local AI harness activity before risky work executes. It detects new or changed artifacts, pauses when trust is unclear, routes blocked work into native harness approvals or the local Guard approval center, stores receipts, and keeps optional cloud sync separate from core local protection. Success looks like users trusting that Guard is accurate, fast, honest about what happened, and able to get them back into their workflow without confusion.

## Brand Personality

Trustworthy, precise, and calm. The voice should feel like a serious local safety layer, not a crypto dashboard, not a playful assistant, and not a debugging console. It should reduce anxiety during risky moments, explain consequences plainly, and make operators feel in control.

## Anti-references

- Generic AI-generated dashboards with repeated cards, vague gradients, and filler metrics
- Security theater UI that feels loud, punitive, or overloaded with red chrome
- Consumer gamification, mascot-heavy onboarding, or celebratory language during risk decisions
- Developer tools that read like raw logs, transport dumps, or protocol internals instead of product UX

## Design Principles

1. Keep the user in flow: approvals, receipts, and status should help users return to the right harness state with minimal extra work.
2. Make risk understandable fast: every blocked action should explain what happened, why it matters, and the one best next step.
3. Stay honest about capability: never imply Guard resumed or protected something it did not actually do.
4. Prefer calm operational clarity over decorative security styling: the interface should feel dependable and deliberate under pressure.
5. Preserve local trust: avoid leaking sensitive local context, avoid surprising side effects, and keep optional cloud features clearly separate from core local protection.

## Accessibility & Inclusion

Target WCAG AA across dashboard and approval-center surfaces. Prioritize readable contrast, keyboard support, focus visibility, reduced-motion respect, clear status language, and touch-friendly targets for localhost approval flows that may be used on laptops, tablets, or phones. Copy should stay legible for mixed experience levels, especially when the user is stressed or trying to unblock work quickly.
