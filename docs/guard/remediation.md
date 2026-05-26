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

## 4. Audit and rollback

- Keep the remediation trail in Guard evidence/audit output.
- Remove temporary exceptions as soon as upstream data is corrected.
