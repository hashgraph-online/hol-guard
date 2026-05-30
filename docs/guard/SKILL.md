# HOL Guard Skill Guidance

Use this guidance when an AI agent is about to add or update dependencies.

## Before package installs

1. Preview the install decision:
   - `hol-guard protect --dry-run -- npm install <package>`
2. Check current workspace risk posture:
   - `hol-guard supply-chain scan --json`
3. Explain a specific package verdict:
   - `hol-guard supply-chain explain <package>@<version> --ecosystem <ecosystem>`
4. Confirm package manager interception is installed:
   - `hol-guard package-shims status --json`
5. Repair a missing or tampered package manager shim:
   - `hol-guard package-shims repair --manager npm --json`

## Cursor editor and Cursor CLI

Cursor has two protection surfaces. **Cursor editor** covers MCP servers in `.cursor/mcp.json`. **Cursor CLI** covers the `cursor-agent` command path. Keep them distinct when activating, checking, repairing, or removing Guard.

1. Connect Cursor editor protection:
   - `hol-guard apps connect cursor --surface editor`
2. Connect Cursor CLI protection:
   - `hol-guard apps connect cursor --surface cli`
3. Test a Cursor surface without changing config:
   - `hol-guard apps test cursor --surface editor`
   - `hol-guard apps test cursor --surface cli`
4. Repair only the stale surface named by Guard Cloud:
   - `hol-guard apps repair cursor --surface editor`
   - `hol-guard apps repair cursor --surface cli`
5. Remove protection only after confirmation:
   - `hol-guard apps disconnect cursor --surface editor --confirm disconnect-cursor`
   - `hol-guard apps disconnect cursor --surface cli --confirm disconnect-cursor`

Guard owns trust checks, drift repair, redacted receipts, and Cloud sync. Cursor owns its native editor and CLI behavior. If a surface is missing, unsupported, or unavailable, report that state instead of inventing an install URL or fallback command.

## During CI and automation

- Route dependency installs through Guard:
  - `hol-guard protect -- npm ci`
- Use workspace audits before release:
  - `hol-guard supply-chain audit --json`

## If Guard blocks a package

- Review the blocking reason and suggested fix version.
- Prefer upgrading to a safe version.
- If it is a verified false positive, use a scoped and expiring exception with recorded reason.
