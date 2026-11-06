---
name: setup
description: Install or initialize HOL Guard local runtime protection for Claude Code. Use when the user explicitly asks to install, enable, set up, or repair HOL Guard.
disable-model-invocation: true
---

# Set up HOL Guard for Claude Code

HOL Guard is a separate open-source local runtime package. This plugin is the Claude Code discovery and setup companion; the actual security boundary is installed and maintained by the `hol-guard` CLI.

Follow this sequence exactly:

1. Check whether HOL Guard is already available without changing the machine:

   ```bash
   command -v hol-guard && hol-guard --version
   ```

2. If `hol-guard` is missing, explain that installation changes the user's Python/pipx environment and ask for explicit approval before installing it. Do not silently substitute another package manager.

3. After approval, install from PyPI with the documented command:

   ```bash
   pipx install hol-guard
   ```

   If `pipx` is unavailable, stop and show the user the install requirement. Do not curl or execute an unreviewed bootstrap script as a fallback.

4. Initialize Guard interactively:

   ```bash
   hol-guard init
   ```

   Do not add `--yes` unless the user explicitly requests unattended setup. `hol-guard init` owns Claude Code hook installation and avoids maintaining a second security implementation in this plugin.

5. Verify the resulting local protection:

   ```bash
   hol-guard status
   ```

6. Tell the user what Guard reports as active or degraded. Do not claim protection from plugin installation alone.

HOL Guard works locally without Guard Cloud. Cloud connection is optional and should only be offered when the user asks for synchronized history, team policy, fleet visibility, or shared approvals.
