# Claude daemon hook bridge argv review

Original reviewed source: `8de2fb9c3c9e25b69e95c283fdad4ed4c638cc0f`.

Re-reviewed after adapter reorganization at
`586daf1f094ed5f0c7c1818a026b88f298296e3a`. The bridge differs from the
original reviewed source only in its import of `state_path_for_query`, now
from `adapters._modules.claude.claude_daemon_state`. Its executable selection,
argument construction, subprocess call, and failure behavior are unchanged.
The other two pinned sources are byte-for-byte unchanged. The manifest records
the resulting source digest; the verifier still requires both the local and
analyzed sources to match before any Sonar disposition can be applied.

| Finding | Rule | Component |
| --- | --- | --- |
| `AaFVWubqjlIsfgWZxpG_` | `pythonsecurity:S8705` | `src/codex_plugin_scanner/guard/adapters/claude_daemon_hook_bridge.py` |

The rule reports "Command Argument Injection via faulty LLM-supplied CLI
arguments" against the `subprocess.run(argv, check=False)` call in
`main`. No element of that argv is model-supplied, and nothing
derived from the reported source can become a separate argument to the child.

`argv[0]` is the native runtime path. `_native_bridge_executable` resolves it
through `native_hook_bridge_executable`, which returns a path only after
`native_runtime_status()` has verified the runtime's digest, size, owner and
mode. A frozen build resolves it through `durable_hook_runtime`, which
republishes only bytes hashing to that validated identity and re-verifies the
copy on every reuse: `_is_trusted_copy` re-reads the file, requires a regular
file of the exact recorded size owned by the current user with no group or
world write bit and the owner execute bit set, and compares its SHA-256 against
the recorded identity. Its memoization key includes size, both timestamps,
inode and device, so a replaced file is re-hashed rather than trusted. A file
planted at the durable path is therefore rejected, not executed.

`argv[1]` and `argv[2]` are the module constants `NATIVE_CLAUDE_HOOK_COMMAND`
and `CLAUDE_GUARD_DAEMON_HOOK_MARKER`. `argv[3]` is a single `json.dumps`
object that the native bridge parses as configuration; it is one argument and
cannot split into flags or options. The child is launched from an argument
list, never through a shell, so no quoting or word-splitting boundary exists.

The reported values originate from the hook command Guard's own installer wrote
into the harness settings. Any party able to change them can already replace
the hook command outright, so they are not a privilege boundary this call can
cross.

No analyzer rule, exclusion or gate threshold is changed by this disposition.
`sonar-project.properties` keeps `sonar.sources=src,rust` with no
`sonar.coverage.exclusions` and no `sonar.issue.ignore.multicriteria`, as
`tests/test_sonar_fixture_source_scope.py` requires: Guard's runtime
enforcement code stays fully in scope for the scanner.

`scripts/ci/apply_sonar_hook_bridge_review.py` applies the disposition only
while the committed source and the source SonarCloud analyzed both match the
digests pinned in `sonar-hook-bridge-argv-review.json`, and only while the
issue's key, project, rule and component are unchanged and the finding is not
a pull-request finding. It re-reads the analysis and the issue after
verification and refuses to write if either moved. The one-time workflow that
runs it uploads a `sonar-hook-bridge-review` artifact with the before/after
issue payloads, the analyzed revision and the review manifest, and is removed
once those results are verified.

Re-review this disposition if the launcher ever takes its configuration from
hook input rather than its installed command line, if the runtime identity
verification in `native_runtime_durable.py` changes, or if any argument becomes
caller- or model-supplied.
