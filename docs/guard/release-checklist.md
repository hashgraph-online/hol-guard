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
