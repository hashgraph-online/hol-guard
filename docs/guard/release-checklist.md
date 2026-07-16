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
