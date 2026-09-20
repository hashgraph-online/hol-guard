# Recorded policy execution outcomes

A recorded decision and an acknowledgement do not prove that an action finished.
For a package command that actually returns a terminal subprocess result, Guard
can attach `policyExecutionOutcome` to its receipt. The record is explicitly
`self_attested`; it is not independent enforcement certification.

The record is available only when the final selected canonical rule has an
authenticated publication binding captured before execution. It contains:

- `schemaVersion`: `guard.policy-execution-outcome.v1`.
- `receiptId` and `completedAt`: the receipt correlation and UTC completion time.
- `outcome`: `succeeded` for exit status zero, or `failed` for a nonzero terminal result.
- `source`: `guard_subprocess`; `trust`: `self_attested`.
- `policyId`, `ruleId`, and `policyVersion`: the exact selected canonical identity;
  the version is the document's decimal revision string.
- `bundleVersion`, `bundleHash`, and `installationId`: the captured positive integer
  delivery version, canonical SHA-256 digest, and source installation.

Dry runs, decisions that prevent execution, failed process creation, legacy
sources without a complete identity, and decisions changed by another authority
produce no completion witness. A later policy change cannot relabel a completed
execution. Cached package evaluations never retain this source binding.

Receipt redaction preserves the complete fixed schema or drops it as a unit.
The record contains no command, output, local path, or package name. A receiver
must correlate the receipt and authenticated source with its intended accepted
publication before counting the self-reported completion.
