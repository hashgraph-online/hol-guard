# HOL Guard Testing Matrix

This matrix exists so local Guard, Cloud Guard, and CI wrapper behavior stay aligned.

## Canonical Install And Connect Commands

- `hol-guard bootstrap`
- `hol-guard install codex`
- `hol-guard run codex --dry-run`
- `hol-guard run codex`
- `hol-guard approvals`
- `hol-guard receipts`
- `hol-guard status`
- `hol-guard connect`
- `hol-guard connect status`
- `hol-guard connect repair`
- `hol-guard sync`
- `hol-guard explain install-connect`

## Supply Chain Support Levels

- Protected: package install and execution paths that Guard can block before side effects run.
- Beta: package ecosystems where Guard can inspect and explain risk but still needs more live coverage.
- Monitor-only: package managers or platforms where Guard records evidence and receipts without claiming enforcement.

Use `hol-guard cloud sync-intel` before production rollout so local policy uses the latest cloud intelligence.

## CI Wrapper Examples

Install dependencies through HOL Guard in `.github/workflows`:

```bash
hol-guard protect -- npm ci
```

Run local package checks before allowing agent-driven dependency changes:

```bash
hol-guard supply-chain scan
hol-guard supply-chain explain
```
