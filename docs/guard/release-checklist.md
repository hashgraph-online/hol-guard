# Guard Release Checklist

Before each Guard harness release:

- Run the automated CI suite for the release branch.
- Update smoke evidence from `tests/fixtures/smoke-evidence-template.json` with current manual results.
- Confirm browser-assisted Guard Cloud connect flows still open the hosted pairing page and can reach the local daemon.
- Attach smoke evidence to the release notes or pull request before publishing.
