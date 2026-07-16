# HOL Guard Remediation Guide

Use this guide when a dependency is blocked or flagged and you need to recover safely.

## 1. Confirm the finding

- Re-run the decision for the exact package:
  - `hol-guard supply-chain explain <package>@<version> --ecosystem <ecosystem>`
- Review current workspace posture:
  - `hol-guard supply-chain scan --json`

## 2. Preferred fix path

1. Upgrade to the recommended safe version.
2. Re-run your install through Guard:
   - `hol-guard protect -- npm install <package>@<safe-version>`

## 3. Handling verified false positives

Only after verification:

1. Create a narrowly scoped exception (specific package/version/workspace).
2. Require a clear reason and short expiry.
3. Re-run the blocked command through Guard to confirm the exception behavior.

Avoid broad or permanent exceptions.

### Package approval reuse

A saved **This project** package approval is portable only between linked Git
worktrees whose package execution context is identical. Guard v2 binds that
decision to the repository identity, workspace-relative location, package
manager executable, manifests and lockfiles, registry and proxy settings,
lifecycle hooks, overrides, patches, workspace configuration, and relevant
environment policy. The approval center names the component that changed when
it asks again.

Guard intentionally ignores legacy v1 portable package approvals. It also
limits the decision to **This retry only** when a required input is unreadable,
unsupported, oversized, symlinked, or dynamically loaded. This may add a prompt
for unusual package-manager setups or projects with local lifecycle hooks, but
it prevents an incomplete context from silently widening a previous approval.
Registry credentials and configuration values are never included in approval
evidence; only digests and safe component labels are retained.

## 4. Audit and rollback

- Keep the remediation trail in Guard evidence/audit output.
- Remove temporary exceptions as soon as upstream data is corrected.

## 5. Package firewall recovery

Use the local dashboard Package Firewall panel first when the daemon is paired. It can protect, repair, test, audit, sync, or remove package manager shims with signed receipts.

CLI fallback:

1. Check current shim state:
   - `hol-guard package-shims status --json`
2. Install interception for selected managers:
   - `hol-guard package-shims install --manager npm --manager pip --json`
3. Repair missing or tampered shims:
   - `hol-guard package-shims repair --manager npm --json`
4. Remove a selected shim:
   - `hol-guard package-shims uninstall --manager npm --json`

If status reports `path_repair_required`, prepend the returned shim directory to PATH using the shell hint in the JSON payload, then restart the shell before testing again.
