# Extension builds without fixture churn

Command and MCP extensions remain product inputs, not disposable CI files. Their
source and descriptor paths, stable IDs, trust and opt-in behavior, packaged
catalogs, directory JSON, contributor PR templates, maintainer intake tool and
publisher attribution are unchanged. No portal migration is required.

## Build order

Cargo first uses the native source compiler as a host-only build dependency to
compile the reviewed sources and trust policy. It writes the embedded program to
`OUT_DIR`; the compiler and runtime then consume that exact program. The host
compiler uses the same source implementation, with no prior embedded default.
Malformed input still fails before a binary can be packaged.

`verify_native_command_program.py` stages the current projections at their
existing paths and then strictly checks them. It verifies the compiler's native
implementation identity, its build-time source result, the current source
compilation and the embedded program. It does this on PRs, pushes and release
builds, without a permissive pending-artifact mode or a second Cargo build.

The core CI producer shares these resources with test planning and execution.
The planner must discover the same extension inventory the tests will exercise.
Native platform jobs still build and qualify their own binaries and wheels.

## Contributor workflow

Continue submitting the canonical command/MCP source, its meaningful portable
behavior fixture and the authored external trust entry. Use the existing
extension PR template and authoring commands. Organization-owned forks retain
`scripts/intake_contribution_pr.py`; original contributor commits and attribution
are preserved. Do not add unrelated generated catalog changes to a contribution.

Maintainer automation still publishes descriptors and the public directory to
Git at the established paths. It builds the offline source compiler once and
projects its output. It does not build the runtime again, change portable
fixtures' copied trust policies, rewrite Python assertions or update crypto
vectors. A source-only main revision is buildable before this publication lands.

## Test expectations versus evidence

The growing catalog is checked for complete membership against authored sources
and trust policy. Stable API shapes and independently authored command behavior
remain reviewed expectations. Fixed cryptographic vectors keep fixed inputs;
they are not required to use the latest production catalog digest.

Current decision reports are evidence under ignored `build/guard-evidence/`, not
fixtures that must be committed after each source change. Report generation
still checks all 51,000 corpus cases against immutable inputs and independently
reviewed native groups, including the existing fail-closed signatures. Historical
implementation hashes record where those expectations originated; they do not
freeze the implementation being tested. The checked-in historical report remains
readable but is no longer the expected output of today's build.

This removes the generate/rebuild fixture cycle. It does not remove legitimate
compilation after native code or authored extension changes, reduce the corpus,
relax deadlines or bypass release/approval checks.
