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

## During CI and automation

- Route dependency installs through Guard:
  - `hol-guard protect -- npm ci`
- Use workspace audits before release:
  - `hol-guard supply-chain audit --json`

## If Guard blocks a package

- Review the blocking reason and suggested fix version.
- Prefer upgrading to a safe version.
- If it is a verified false positive, use a scoped and expiring exception with recorded reason.
