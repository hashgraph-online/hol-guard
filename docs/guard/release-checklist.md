# Guard Release Checklist

Before each Guard harness release:

- Run the automated CI suite for the release branch.
- Confirm the privileged-workflow policy passes and every write/OIDC/package job uses full action commit SHAs.
- Confirm `uv` is exactly the reviewed release version and the release toolchain CycloneDX SBOM records its SHA-256.
- Update smoke evidence from `tests/fixtures/smoke-evidence-template.json` with current manual results.
- Confirm browser-assisted Guard Cloud connect flows still open the hosted OAuth connect page and can reach the local daemon.
- Confirm a fresh or upgraded installation reports Guard Cloud commands disabled until a local capability is issued.
- Confirm command capability issuance, expiry, tamper detection, one-job local approval, replay rejection, and revocation in an isolated instance; verify read-only Cloud sync remains available after command revocation.
- In release notes, call out that `hol-guard connect` is the canonical Guard Cloud sign-in flow and `hol-guard connect --headless` is the canonical SSH/CI flow.
- In release notes, call out that pasted `--token` login and legacy bearer setup are retired.
- Attach smoke evidence to the release notes or pull request before publishing.
- Verify trust attestation consumers support the v3 domain-separated subject bindings, key revocation, and replay policy described in `trust-attestation-security.md`.
- For Grok releases, complete the trusted executable checks in `docs/guard/grok-executable-security.md`, including
  workspace PATH collision, explicit custom registration, executable replacement, and sanitized-environment coverage.
- Verify known read-only `gh` commands remain prompt-free and remote mutations still require approval when piped
  through output formatters; see [GitHub CLI Capability Boundary](github-command-capability-security.md).
- Exercise device-key and observer-credential rotation/revocation using [the Protection Credential Rotation and Revocation Runbook](protection-credential-rotation-runbook.md), and attach the redacted acceptance record.
- Walk the confirmed deletion, false-positive/expected-offline, authorized-removal, transfer, and retirement cases in [the Protection Incident Response Runbook](protection-incident-response-runbook.md).

For GitHub Action pin updates, keep Dependabot updates as individual pull requests. Review the upstream changelog
between the old and new commits, verify permission and runtime changes, retain the full commit SHA, and require the
configured CODEOWNER review before merging. If `astral-sh/setup-uv` changes, update its exact `uv-version` only after
reviewing both releases; the privileged-workflow policy rejects a floating or missing version.

When running Guard scans against untrusted content in a container, keep the runtime sandboxed:

- mount the target workspace read-only when possible
- disable outbound network access with `--network=none`
- drop ambient privileges with `--cap-drop=ALL` and `--security-opt=no-new-privileges`
- set explicit `--memory`, `--cpus`, and `--pids-limit` caps
- use a writable `tmpfs` only for the minimal paths the scan needs, such as `/tmp`

## Release channels

Guard uses two isolated release lines:

- `main` is the stable 3.x source. Merge the Release Please pull request, or dispatch `Publish to PyPI` as a break-glass path, to publish from `main`.
- `release/3.0` remains the long-lived 3.x alpha release branch. It receives compatible `main` fixes by regular forward merges, never by backporting unfinished alpha-only behavior into `main`.
- PyPI 3.x alpha versions use public PEP 440 versions such as `3.0.0a1`. Package installers ignore these prereleases unless users opt in with an exact version or an explicit prerelease flag.
- `plugin-scanner` remains on its stable release line during Guard 3.x alpha publishing. The alpha workflow removes its distributions before upload.

### Publish a stable 3.x release from main

1. Land the intended changes on `main` with conventional commits (`feat` for minor, `fix` for patch, `feat!` or `BREAKING CHANGE` for major).
2. The `Release Please` workflow opens or updates a `chore(release): <version>` pull request with changelog and version metadata.
3. Merge that pull request when the batch is ready. Merging it tags the release commit and dispatches `Publish to PyPI` for `release_channel=stable` and `release_train=main`.
4. Confirm the dispatched publish builds native wheels, uploads to PyPI, and creates the GitHub release assets.
5. Maintainers can still dispatch `Publish to PyPI` from `main`, or from the existing `v<version>` tag if `main` has moved, with the exact version and `expected_sha`.

Normal pushes to `main` still build and verify packages without publishing.

### Publish a 3.x alpha

1. Merge the intended changes and the latest compatible `main` fixes into `release/3.0`.
2. Wait for the standard Linux and cross-platform CI jobs on the branch to pass.
3. A push to `release/3.0` automatically computes the next unused `3.0.0aN` version from PyPI, TestPyPI, and existing alpha tags, reserves `alpha/v<VERSION>` against the exact branch commit, and publishes the verified artifact to both registries.
4. For an explicitly authorized replay or fixed version, run the `Publish to PyPI` workflow from `release/3.0` with `release_channel=alpha`, `release_train=3.0`, a new `release_version` such as `3.0.0a1`, and `expected_sha` set to the authorized branch commit.
5. Confirm the workflow's Linux suite, Windows suite, package checks, and PyPI trusted publish all pass.
6. Verify the generated `alpha/v<VERSION>` GitHub prerelease and install the exact version in a clean environment.
7. Record compatibility findings against the alpha without changing the default stable installer path.

The workflow rejects alpha versions outside the 3.x line, rejects non-alpha prerelease types, rejects alpha publishes from any other branch, binds every tag and artifact to the exact branch commit, and prevents alpha artifacts from entering the stable repository-version synchronization flow.

### Desktop Core alpha sidecars

The `Desktop Core macOS feed` workflow can publish signed, notarized macOS Core sidecars to an existing `alpha/v<VERSION>` prerelease. Alpha runs happen only by explicit dispatch; scheduled and push runs stay stable-only and never look for alpha releases.

Dispatch from `main` with an exact version, the alpha publish run, and the alpha source commit:

```sh
gh workflow run desktop-core-alpha-feed.yml --ref main \
  -f core_version=<VERSION> -f release_channel=alpha \
  -f publication_run_id=<RUN_ID> -f publication_source_sha=<ALPHA_SOURCE_SHA>
```

- `core_version` must match `3.<minor>.<patch>a<N>` exactly. `release_channel` defaults to `stable`, which keeps the existing behavior.
- The `alpha/v<VERSION>` release must be a published prerelease, not a draft, and its tag must point at `publication_source_sha`. The workflow never creates or edits releases.
- The publish run must be a `main` dispatch of `publish.yml` whose `Publish alpha to PyPI` job succeeded. The alpha source commit must be an ancestor of that run's commit, not necessarily the head of `main`.
- Manifests declare `"channel": "alpha"`. Existing complete sidecar assets are reused, so rerunning a dispatch is safe.
- If the prerelease or tag is deleted before upload, the run fails and nothing is recreated.
- Alpha dispatches queue separately from the stable feed. A `main` run in which only the alpha publish jobs succeeded does not trigger MCP registry or MCPB publishing.

### Cut an optional test alpha from main

Use this to try a large batch on real machines before the stable Release Please PR merges. A main alpha never changes the stable version line, the Release Please PR, or the default installer path.

1. Run the `Release Please` workflow from `main` with `workflow_dispatch`. Leave `alpha_version` as `next`, or name an exact unused `X.Y.0aN`. Only maintainers may start it.
2. The workflow dispatches `Publish to PyPI` with `release_channel=alpha`, `release_train=main`, and `expected_sha` set to the current `main` commit. `next` resolves to the next minor after the current stable version, for example `3.43.0a1` while `3.42.0` is current, then `3.43.0a2` for the next request.
3. The publish reserves `alpha/v<VERSION>`, uploads the verified artifact to PyPI, creates the `alpha/v<VERSION>` GitHub prerelease, and dispatches the Desktop Core feed with `release_channel=alpha` so the signed sidecars land on that prerelease.
4. Main may keep moving during the publish; the source commit only has to remain part of `main`'s history.

Once `X.Y.0` ships as stable, later `next` requests move to `X.(Y+1).0a1`.

To test the alpha:

- CLI: `hol-guard update --alpha`, or install the exact version with `uv tool install 'hol-guard==<VERSION>'`.
- Desktop: select the Alpha update channel. Desktop offers only alpha Core builds that still have a live `alpha/v<VERSION>` prerelease with signed sidecars.

### Delete a test alpha

Run the `Delete alpha release` workflow with the alpha `version`. It deletes the `alpha/v<VERSION>` prerelease, its tag, the Desktop Core sidecars attached to it, and the matching container image. Guard and Desktop alpha updates stop offering that version immediately.

The same cleanup by hand:

```bash
gh release delete alpha/v<VERSION> --repo hashgraph-online/hol-guard --cleanup-tag --yes
```

PyPI never allows a published version to be deleted or reused. The PyPI files stay, but installers skip prereleases unless asked for one. To hide the version from exact pins too, yank it on the PyPI release management page. The next `next` request skips deleted numbers and uses a fresh `aN`.

### Continue alpha maintenance

1. Land compatible fixes on `main` and publish them through the stable Release Please path.
2. Forward-merge compatible `main` fixes into `release/3.0`.
3. Let both branch CI matrices pass before the next alpha.
