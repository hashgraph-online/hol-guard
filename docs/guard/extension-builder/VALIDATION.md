# Extension Builder validation

Validation exercises the offline compiler, CLI dispatcher, exact literal matcher,
native contribution integration, and installed package. It does not establish the
behavior of an arbitrary upstream CLI binary or MCP server.

## Source-tree checks

Use the repository's locked development environment:

```sh
uv sync --frozen --extra dev
uv run --no-sync pytest tests/test_guard_extension_builder_*.py \
  tests/test_guard_extension_contribution.py \
  tests/test_guard_extension_trust.py \
  tests/test_guard_mcp_server_contribution.py

uv run --no-sync pytest tests/test_guard_command_*extensions.py \
  tests/test_guard_command_extension_registry.py \
  tests/test_guard_command_critical_floors.py

uv run --no-sync python tests/guard_command_decision_diff.py --check
```

The focused tests cover exported CLI and MCP metadata, malformed input, bounded
numeric decoding, annotation distrust, source-bound reviews, exact literal
invocations, root block scope, option arity, source drift, byte reproducibility,
CRLF integration, symlinks, tampering, collision detection, ownership conflicts,
expected-plan writes, rollback, and repeated-apply idempotence.

Generated CLI and MCP tests are also run in an independent source tree using the
actual native registry. The full 256-operation CLI inventory is exercised, not
silently truncated. No destructive target command or MCP tool is executed.

## Installed-wheel matrix

The [Extension Builder workflow](../../../.github/workflows/extension-builder-ci.yml)
builds a wheel and verifies it on Linux with Python 3.10 and 3.13, macOS ARM64 with
Python 3.13, and Windows with Python 3.13. Exact current results are attached to the
corresponding GitHub Actions run, rather than inferred from a previous revision.

The [installed verifier](../../../scripts/ci/verify_extension_builder_install.py)
invokes the isolated environment's executable outside the checkout. It checks
CLI and MCP generation, rebuild-based validation, identical snapshot replay,
diff, read-only planning, expected-plan-bound writes, idempotence, and the maximum
CLI inventory. Source fallback and Guard state creation are checked explicitly.

Each matrix job uploads its test report, installed-verification result, and
locked dependency export. Linux Python 3.13 also produces isolated coverage and
source-bound command-decision evidence. Artifact retention is seven days.
Artifacts identify tested bytes, not a production release or publisher signature.

Coverage is scoped to the authoring package, its CLI dispatcher, and the literal
matcher. It is not full-project coverage. Use the workflow's isolated coverage
configuration; the repository-wide default would include unrelated modules.
Windows omits only tests requiring POSIX named-pipe or mode semantics.

## Review boundaries

Unknown CLI operations retain review and unknown MCP tools inherit. Nondefault
behavior requires explicit review of the exact discovery binding. Root rows
cannot become executable-wide blocks. Literal safe variants cannot suppress
independent rules, device policy, or first-party safety floors.

Generated-source tests verify bounded syntax and exact replay without a runtime
formatter dependency. Integration tests use normal native contracts and installed
dependencies, not a replacement policy engine or disabled safety gate.

For a real contribution, run its emitted tests in the destination checkout and
add behavior cases grounded in the upstream implementation. Inspect all public
metadata, rationale, URLs, and the final diff before submitting it.
