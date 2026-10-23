# One-command CI check (inactive integration)

`ci check` runs the existing profiles, freezes live inputs, executes every shard,
audits results and writes one upload directory. No production workflow is enabled.
The inactive GitHub Actions example is
[`examples/gauntlet-check.yml.example`](examples/gauntlet-check.yml.example).
It pins the upload action to a reviewed commit of v7; see the
[official action requirements](https://github.com/actions/upload-artifact).

## Provision once

Use the supported dedicated Linux VM and Root controller described in
[`CI_RUNNER.md`](CI_RUNNER.md). Install the reviewed controller separately from
the candidate checkout. Supply the existing v7 configuration with externally
pinned Guard wheel/native/prefix, locked SDK, executor and matching conformance.
The build/package job must produce these artifacts from the **commit under test**.
This command does not build arbitrary PR code as Root or install dependencies.
It verifies installed artifact identities through the existing backend.

Pass the expected full Guard commit SHA independently from that configuration,
for example from the build job's immutable source identity. Do not derive the
expected value from the configuration it is supposed to check. A stale installed
candidate fails before any control or model episode starts. For a PR merge build,
use the merge commit's SHA rather than the PR head's SHA.

For `beta-e2e`, provision campaign, selection and policy from the existing
`profile beta-e2e` export. All twelve cells and their original budgets are required;
subset selections, changed policy, retries and alternate tasks are refused. An
approved persistent provider allowance must cover the complete nominal matrix
before inference. The command preserves existing quota history and never starts
or reconfigures a model service. Default `deterministic` requires no model endpoint.

## Execute

Run from the trusted controller checkout/environment. All paths are canonical,
state and output must be new, and both must be outside source and public assets.
State needs protected Root-owned ancestry below `/home` or `/opt`; keep its path
short (including the appended `/c`, at most 27 bytes). Output also needs protected
Root-owned ancestry. The command serializes other `ci check` jobs on that VM using
a kernel lease; manually invoked legacy commands still require operator serialization.

```sh
sudo /opt/hol-gauntlet/venv/bin/python -B -m ci.gauntlet.benchmark ci check \
  --config /opt/hol-gauntlet/public/config.json \
  --expected-config-digest "$HOL_RUNNER_CONFIG_DIGEST" \
  --expected-guard-source-sha "$HOL_GUARD_COMMIT_SHA" \
  --asset-root /opt/hol-gauntlet/public \
  --state-root /home/hgc-001 \
  --output-dir /var/lib/hol-gauntlet/outputs/check-001
```

That is the deterministic blocking check. Add `--profile beta-e2e` for the complete
live profile; schedule it manually/nightly and initially leave it outside required
PR checks. An advisory live run still returns its real failure code. Never add
`|| true` to turn corrupt evidence or incomplete cases into success.

Outputs:

- `report/result.json`, `report/junit.xml`, `report/summary.txt`, `report/manifest.json`.
- Hashed phase JSON files and invocation metadata alongside `report/`.
- Complete private backend evidence at the reported `raw_state_root`; retain it
  in restricted worker storage. The ordinary report upload does not export private
  execution state or signing material.

Upload reports on success **and failure**. Exit 0 means the selected profile's
acceptance passed; 1 means measured outcomes failed; 2 means invalid inputs,
execution/evidence or admission; 130 means cancellation. Existing destinations
are refused without overwriting them. Invalid CLI arguments or an unwritable
destination can only produce stderr/stdout and a nonzero exit, not a new artifact.
The command never retries or resumes a terminal failure. Failed task/security
outcomes remain visible while later valid cells run; incomplete cleanup, invalid
evidence and interruption stop further admission. Partial/unknown model usage is
reported as unknown, never zero. Read-only report/audit operations remain available through
the existing explicitly pinned `ci report` interface.

## Local validated invocation

From `/opt/hol-beta-controller-013` in the owned beta VM:

```sh
sudo /opt/hol-benchmark-controller-20261013/.venv/bin/python -B \
  -m ci.gauntlet.benchmark ci check \
  --config /opt/hol-cache063-matrix-inputs-20261016-002/config.json \
  --expected-config-digest 0895361a63eee14e35ee71299c711e0e3856758589925c0f9a648d365a10468b \
  --expected-guard-source-sha 9e6fc298465a0a5aad9dabe30b9fbee369b22a09 \
  --asset-root /opt --state-root /home/hg-46e981 \
  --output-dir /var/hol-ci-check-002
```

This invocation is retained evidence, not a command to replay into its existing
directories. Choose fresh paths for a subsequent run. Current product/platform
limits and beta evidence remain in [`../../../BETA_ACCEPTANCE.md`](../../../BETA_ACCEPTANCE.md).
Activation requires review and a separately authorized production change. The
example is stored outside `.github/workflows` and does not register any CI job.

Validation: the installed model-free invocation passed all six controls in
**441.678 seconds**, with zero model requests/tokens. Wrong-commit and partial
E2E selections were refused before worker admission. Final Linux regression tests
passed **139/139**, with no skips. Controller014 adds the tested live-cancellation
audit fix; all deterministic-path functions remain unchanged from controller013's
installed proof. The live orchestration is covered by contract tests against the
existing backend; this integration did not rerun a full live twelve-cell matrix.
Local evidence is under `local-evidence-20261014/ci-one-command-*` beside the
implementation checkout, including exact invocation, signed control exports,
JUnit, cleanup and zero-inference accounting.
