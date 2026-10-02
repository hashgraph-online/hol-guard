# Installed Workflow Matrix

Run with the installed native wheel's Python from the repository root:

```sh
python -m ci.native_runtime.probe_workflow_matrix --live-omp \
  --test-project /absolute/path/to/isolated-workflow-fixture \
  --expected-source-sha FULL_SHA_OF_THE_INSTALLED_BUILD \
  --output /absolute/path/to/private-evidence
```

The model defaults to `devin/swe-2`. `omp` must be on PATH. The existing isolated
test project must contain `tests/workflow.test.mjs`, `tests/zcode-multi.test.mjs`
and its already-installed local Vitest. This runner never installs dependencies,
enables Codex, grants approvals, changes user policy, or mutates the test project.
It creates a fresh disposable home, workspace and Guard state for each run.
Live protected-test proofs (`--live-omp --test-project`) require macOS. All runs
require symbolic-link creation privileges for the synthetic secret-alias case;
on Windows, enable Developer Mode or use an account with that privilege.

## Mandatory Outcomes

- Every case has a fixed expected admission outcome. Unexpectedly blocked
  positives and allowed negatives fail the run, rather than being omitted.
- Actual Pi calls must execute every required command exactly once, in order.
  Missing tools, changed commands, nonzero tools and new approvals fail the run.
- Protected Vitest calls must execute through the containment sink, preserve
  original input in presentation metadata and produce passing test output.
- Coverage includes quoted/absolute/outside reads; multi-file, clustered-option,
  piped and recursive searches; copy-file/copy-directory; mkdir/touch/mv; GitHub
  GET comparison with a quoted jq expression; Bun x/bunx and cross-project cwd.
- Synthetic secret reads/copies, secret aliases, secret directory walks,
  directory deletion, destructive chains, Git metadata writes, GitHub mutation,
  external hosts and auth-token reads must remain guarded. They never execute.

Without `--live-omp`, this verifies installed admission only, not actual host
execution. Without `--test-project`, it omits the optional contained-test suite;
do not report that run as proof of Bun/Vitest or cross-project containment.
Private admission JSON and raw Pi batch logs are written to the output directory.
The final summary distinguishes mandatory cases from actual Pi calls.
It records the installed native source SHA and rule digest. Release validation
must specify the expected SHA so stale installed code cannot qualify a new PR.

Add every newly reported regression to `workflow_matrix_cases.py` (or the
protected suite), with an explicit expected outcome, before fixing policy. Keep
security-negative pairs alongside new benign proofs. Never turn a failing case
into an optional case merely to make the release pass.
