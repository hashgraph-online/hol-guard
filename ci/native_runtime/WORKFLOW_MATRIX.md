# Installed Workflow Matrix

Run with the installed native wheel's Python from the repository root:

```sh
python -m ci.native_runtime.probe_workflow_matrix --live-omp \
  --test-project /absolute/path/to/isolated-workflow-fixture \
  --expected-source-sha FULL_SHA_OF_THE_INSTALLED_BUILD \
  --output /absolute/path/to/private-evidence
```

The model defaults to `opencode-go/deepseek-flash`. `omp` must be on PATH. The existing isolated
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
  GET comparison with a quoted jq expression; GitHub compound commands using
  sequences, AND/OR lists and pipelines; bounded numeric sleep; Git inspection
  with directory routing; Bun x/bunx and cross-project cwd. Git inspection uses
  a fresh repository inside the disposable workspace, not a user's repository.
- Synthetic secret reads/copies, secret aliases, secret directory walks,
  directory deletion, destructive chains, Git metadata writes, GitHub mutation,
  external hosts and auth-token reads must remain guarded. Safe GitHub reads
  combined with secret access, deletion or unknown execution must also remain
  guarded. Git configuration/execution overrides and unsupported routing forms
  remain guarded. Negative cases never execute.

Without `--live-omp`, this verifies installed admission only, not actual host
execution. Without `--test-project`, it omits the optional contained-test suite;
do not report that run as proof of Bun/Vitest or cross-project containment.
Private admission JSON and raw Pi batch logs are written to the output directory.
The final summary distinguishes mandatory cases from actual Pi calls.
It records the installed native source SHA and rule digest. Release validation
must specify the expected SHA so stale installed code cannot qualify a new PR.

## Native File Tools

Shell coverage alone does not qualify the host's native file tools. Also run:

```sh
python -m ci.native_runtime.probe_live_file_tools \
  --expected-source-sha FULL_SHA_OF_THE_INSTALLED_BUILD \
  --output /absolute/path/to/private-file-tool-evidence
```

This requires five actual calls in order: read, write, read, anchored edit, read.
It checks tool completion identities, exact targets, write contents, final file
contents, an unchanged seed and zero new approvals in a disposable workspace.
The model defaults to `devin/gpt-6-luna`; either runner accepts `--model`.
Neither a model's success claim nor shell file operations can replace these calls.
Repeat with `--outside-cwd` to verify the same native calls against absolute paths
in another disposable project within the verified user home. Location alone must
not trigger approval; sensitive paths and cross-scope symlink writes remain guarded.

Add every newly reported regression to `workflow_matrix_cases.py` (or the
protected suite), with an explicit expected outcome, before fixing policy. Keep
security-negative pairs alongside new benign proofs. Never turn a failing case
into an optional case merely to make the release pass.
