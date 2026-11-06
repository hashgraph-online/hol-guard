---
name: status
description: Check HOL Guard local protection status for Claude Code without changing configuration. Use when the user asks whether Guard is installed, active, healthy, or protecting Claude Code.
disable-model-invocation: true
---

# Check HOL Guard status

Perform read-only checks first. Do not repair, install, reconnect, or change policy unless the user separately asks for that action.

1. Confirm the CLI exists:

   ```bash
   command -v hol-guard
   ```

2. If present, report the installed version and current protection state:

   ```bash
   hol-guard --version
   hol-guard status
   ```

3. Summarize only what the CLI proves. Distinguish active local protection from optional Guard Cloud connectivity.

4. If Guard reports degraded or missing Claude Code protection, suggest running `/hol-guard:setup`. Do not claim that having this Claude plugin installed means runtime protection is active.
