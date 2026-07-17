# Guard Release Checklist

Before each Guard harness release:

- Run the automated CI suite for the release branch.
- Update smoke evidence from `tests/fixtures/smoke-evidence-template.json` with current manual results.
- Confirm browser-assisted Guard Cloud connect flows still open the hosted OAuth connect page and can reach the local daemon.
- In release notes, call out that `hol-guard connect` is the canonical Guard Cloud sign-in flow and `hol-guard connect --headless` is the canonical SSH/CI flow.
- In release notes, call out that pasted `--token` login and legacy bearer setup are retired.
- Attach smoke evidence to the release notes or pull request before publishing.

When running Guard scans against untrusted content in a container, keep the runtime sandboxed:

- mount the target workspace read-only when possible
- disable outbound network access with `--network=none`
- drop ambient privileges with `--cap-drop=ALL` and `--security-opt=no-new-privileges`
- set explicit `--memory`, `--cpus`, and `--pids-limit` caps
- use a writable `tmpfs` only for the minimal paths the scan needs, such as `/tmp`

## Release channels

Guard uses two isolated release lines:

- `main` remains the stable 2.x source. Stable manual publishes are accepted only from `main`; normal installation continues to select the latest 2.x release.
- `feat/guard-policy-v3` is the long-lived 3.x integration branch until the 3.x compatibility gates are closed. It receives 2.x fixes by regular forward merges from `main`, never by backporting unfinished 3.x behavior into `main`.
- PyPI 3.x alpha versions use public PEP 440 versions such as `3.0.0a1`. Package installers ignore these prereleases unless users opt in with an exact version or an explicit prerelease flag.
- `plugin-scanner` remains on its stable release line during Guard 3.x alpha publishing. The alpha workflow removes its distributions before upload.

### Publish a 3.x alpha

1. Merge the intended changes and the latest `main` into `feat/guard-policy-v3`.
2. Wait for the standard Linux and cross-platform CI jobs on the branch to pass.
3. Run the `Publish to PyPI` workflow from `feat/guard-policy-v3` with `publish_target=pypi`, `release_channel=alpha`, and a new `alpha_version` such as `3.0.0a1`.
4. Confirm the workflow's Linux suite, Windows suite, package checks, and PyPI trusted publish all pass.
5. Verify the generated `alpha/v<VERSION>` GitHub prerelease and install the exact version in a clean environment.
6. Record compatibility findings against the alpha without changing the default 2.x installer path.

The workflow rejects alpha versions outside the 3.x line, rejects non-alpha prerelease types, rejects alpha publishes from any other branch, and prevents alpha artifacts from entering the stable repository-version synchronization flow.

### Continue 2.x maintenance

1. Land compatible fixes on `main` and publish them through the existing stable path.
2. Forward-merge `main` into `feat/guard-policy-v3`. Resolve behavior conflicts in favor of the fixed 2.x invariant while preserving the 3.x contract.
3. Let both branch CI matrices pass before the next alpha.

### Promote 3.x later

Promotion is a separate decision. Do not merge the 3.x branch into `main` or publish `3.0.0` until compatibility, migration, telemetry, and rollback gates are explicitly approved. At promotion, merge the proven branch, publish the stable `3.0.0` version from `main`, and retain the latest 2.x tag as the rollback installation target.
