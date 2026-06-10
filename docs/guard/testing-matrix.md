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

### Ecosystem labels (current Local manager list)

| Ecosystem | Support label | Shim-supported managers |
| :--- | :--- | :--- |
| npm | Protected | `npm`, `npx`, `pnpm`, `yarn`, `bun` |
| PyPI | Protected | `pip`, `pip3`, `pipenv`, `pipx`, `poetry`, `uv`, `uvx` |
| Cargo | Beta | `cargo` |
| Go modules | Beta | `go` |
| Maven/Gradle | Beta | `mvn`, `gradle` |
| Composer | Beta | `composer` |
| RubyGems | Beta | `bundle` |
| Docker base images | Monitor-only | not shim-managed |
| GitHub Actions | Monitor-only | not shim-managed |
| System packages | Monitor-only | not shim-managed |
| NuGet | Monitor-only | not shim-managed |

`package_shim_supported_managers()` in Local Guard is the source of truth for shim-supported package managers.

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
