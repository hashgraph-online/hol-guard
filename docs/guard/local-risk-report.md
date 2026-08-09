# Local risk report

`hol-guard risk-report` creates a coarse posture summary from the local Guard status model.

The report is designed to be safe to inspect or deliberately share. It contains:

- Guard version and generation time;
- coarse runtime state;
- installed harness names;
- counts of managed harnesses, changed managed artifacts, pending approvals, and receipts;
- whether Guard Cloud sync is configured;
- a SHA-256 integrity digest over the sanitized report fields.

It does **not** contain prompts, commands, source code, raw findings, file paths, hostnames, usernames, secrets, tokens, raw receipts, or workspace contents.

## Create JSON

```bash
hol-guard risk-report --format json --output guard-risk-report.json
```

## Create local HTML

```bash
hol-guard risk-report --format html --output guard-risk-report.html
```

The HTML includes `noindex,nofollow`. Creating a report does not upload it anywhere. Sharing or publishing a report is a separate user-controlled action outside this command.

## Important limitation

A local risk report is a posture summary, not a certification and not proof that every attack will be blocked. Coverage depends on the installed Guard version, harness, event surface, policy, and runtime state.
