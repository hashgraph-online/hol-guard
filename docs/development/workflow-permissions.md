# GitHub Actions token permissions

Workflow defaults must be an explicit map containing only `read` or `none`, or
`permissions: {}`. A job that needs to publish, attest, upload findings, comment,
or dispatch another workflow declares its own named scopes. Do not use
`read-all`, `write-all`, or rely on the repository's default token settings.
Job-level maps replace the workflow map; they do not add to it.

`Security Gates / Privileged workflow policy` enforces these rules on pull
requests and merge groups, alongside the existing full action SHA and exact uv
version requirements for privileged jobs. Test locally with:

```sh
uv run --no-sync python scripts/check_privileged_workflows.py
uv run --no-sync pytest tests/test_privileged_workflow_policy.py tests/test_workflow_token_permissions.py
```

## Permissions that are intentionally retained

| Workflow or job | Write access | Consumer |
| --- | --- | --- |
| `dependabot-uv-lock.yml` | `contents` | Commits the regenerated lockfile to the Dependabot branch. |
| `finish-extension-authority-stability.yml` / `finish` | `contents` | Updates its dedicated repair branch; no other job inherits this grant. |
| `publish.yml` tag reservation and reservation cleanup jobs | `contents` | Creates or deletes release reservation tags. |
| `publish.yml` PyPI jobs | `id-token` | Authenticates the existing trusted-publisher uploads. |
| `publish.yml` release jobs | `contents`, `attestations`, `id-token` | Publishes release assets and their provenance. |
| `publish.yml` / `publish-container` and `devcontainer-features.yml` / `publish` | `packages` | Publishes images or features to GHCR. |
| `desktop-core-alpha-feed.yml` / `publish-macos-arm64` | `contents`, `attestations`, `id-token` | Publishes the signed Core sidecar and provenance. |
| `publish-mcpb.yml` / `publish` | `contents` | Attaches the bundle and checksum to the verified release. |
| `publish-mcp-registry.yml` / `publish` | `id-token` | Authenticates the MCP Registry publisher. |
| `codeql.yml`, `fuzz.yml`, and `scorecard.yml` analysis jobs | `security-events` | Uploads code-scanning findings. Scorecard also uses `id-token` to publish its results. |
| `guarded-repository.yml` / `scan` | `security-events`, `attestations`, `artifact-metadata`, `id-token` | Scans, attests, and registers the caller's repository. The caller must authorize the required scopes. |
| `extension-claim-notice.yml` / `notify` | `pull-requests` | Comments on verified merged contribution PRs. Separate `issues: write` is unnecessary. |
| `wake-desktop-core-alpha-feed.yml` / `wake` | `actions` | Dispatches the existing Core feed producer. |

These grants are not exemptions from the policy. They are explicit job-level
capabilities, with the workflows' existing event, source, and publication checks
unchanged. Do not remove a required scope merely to silence a scanner warning,
or replace the workflow token with a broader personal access token.

## Reading Scorecard results

The OpenSSF `Token-Permissions` check penalizes broad workflow-level grants.
It can still print warnings about sensitive **job-level** permissions while
awarding full marks when workflow defaults are read-only or empty. The warnings
above are therefore not a reason to break releases, disable fuzz SARIF, or remove
provenance. A full score does not prove that every privileged step is safe.

References:

- [OpenSSF Token-Permissions check](https://github.com/ossf/scorecard/blob/main/docs/checks.md#token-permissions)
- [GitHub workflow permission syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)
- [Comment API permission alternatives](https://docs.github.com/en/rest/issues/comments#create-an-issue-comment)
