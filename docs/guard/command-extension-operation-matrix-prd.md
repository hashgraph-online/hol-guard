# PRD: Command Extension Operation Matrix Expansion

## Status

Implementation target: `release/3.0`

Delivery model: four independently reviewable pull requests, each closing exactly 100 operation tasks.

## Problem

HOL Guard command extensions already protect a useful set of destructive operations, but the current cloud-provider rules cover only a small fraction of the destructive command surface exposed by the AWS CLI, Google Cloud CLI, and Azure CLI. A command can therefore express the same high-risk intent through a nearby service or resource command and miss the provider-specific structured rule.

The gap is not a raw-string detection problem. Guard already has a canonical command parser, structured executable matchers, safe variants, policy routing, runtime approvals, receipts, memory, and synchronization. The missing layer is a validated operation matrix that feeds those existing paths without weakening false-positive controls.

## Goal

Expand the existing cloud command extensions by 400 validated destructive operation paths while preserving the current rule IDs, action classes, policy contracts, permission catalog, and runtime behavior.

The delivered matrix contains:

- 200 AWS CLI delete or terminate operations across application, identity, infrastructure, data, delivery, backup, AI, and account services.
- 100 Google Cloud CLI delete or destroy operations across control plane, IAM, Compute Engine, GKE, serverless, data, messaging, networking, and build services.
- 100 Azure CLI delete operations across resource management, identity, networking, compute, application hosting, databases, storage, messaging, monitoring, API management, analytics, and AI services.

## Non-goals

- Adding generic substring matching for words such as `delete`, `destroy`, or `terminate`.
- Executing cloud commands during tests.
- Validating credentials, accounts, projects, subscriptions, regions, or resource existence.
- Creating new policy action classes or changing default policy modes.
- Duplicating operation-specific argument validation from provider CLIs.
- Treating quoted examples, source code, grep patterns, or printed command text as execution.

## Current architecture

The cloud extension uses one structured rule per provider:

- `command.cloud.aws.resource-deletion`
- `command.cloud.gcp.resource-deletion`
- `command.cloud.azure.resource-deletion`

Each rule feeds both command inspection and runtime tool-action extraction. Safe variants suppress only the owning provider rule for documented help, preview, or request-skeleton forms. The matcher layer normalizes native Windows launcher suffixes and interspersed provider-global options.

This project keeps those contracts stable. New command paths are data in provider-specific operation-matrix modules, converted into existing `ExecutableMatcher` values through shared builders.

## User stories

1. As a developer using an agent, I want Guard to review destructive cloud commands even when the command targets a service that was not in the original small catalog.
2. As a security administrator, I want the existing provider policy and approval controls to apply consistently across the expanded operation surface.
3. As a developer inspecting syntax, I want `--help`, Azure `-h`, and AWS request-skeleton forms to remain non-executing and non-reviewable.
4. As a Windows user, I want `.exe` and `.cmd` launchers to receive the same protection as native executable names.
5. As an administrator using profiles, projects, subscriptions, regions, configurations, output flags, or future global options, I want argument placement not to bypass protection.
6. As a maintainer, I want every operation added through a declarative matrix with exact count, uniqueness, positive, safe, compound-command, and quoted-data regression coverage.

## Functional requirements

### FR-1 Declarative operation matrices

Provider command paths must live in typed immutable tuples. Each path must contain only canonical subcommand tokens. Builders must translate matrix entries into structured executable matchers.

### FR-2 Existing rule ownership

All 400 operations must remain owned by the existing provider rule IDs and action classes. This avoids permission migration, policy drift, receipt incompatibility, and catalog-identity churn.

### FR-3 AWS behavior

AWS operations must:

- Match `aws`, `aws.exe`, and `aws.cmd`.
- Tolerate documented global options before or within the service and operation path.
- Fail secure when an unknown future global option precedes a recognizable destructive operation.
- Keep `--help` and valid `--generate-cli-skeleton` values safe.
- Keep EC2 `--dry-run` safety scoped to EC2 termination only.
- Reject disabled or invalid safe forms when the final effective option re-enables execution.

### FR-4 Google Cloud behavior

Google Cloud operations must:

- Match `gcloud`, `gcloud.exe`, and `gcloud.cmd`.
- Cover stable command paths and conservative alpha and beta track forms.
- Tolerate documented project, account, configuration, impersonation, output, filtering, pagination, verbosity, and quiet options.
- Fail secure around unknown future global options.
- Keep `--help` safe without hiding a later destructive shell segment.

### FR-5 Azure behavior

Azure operations must:

- Match `az`, `az.exe`, and `az.cmd`.
- Tolerate subscription, query, output, compact output, debug, error-only, and verbose global forms.
- Fail secure around unknown future global options.
- Keep both `--help` and documented `-h` safe.
- Prevent a safe first segment from suppressing a later destructive segment.

### FR-6 False-positive boundaries

The implementation must not review:

- A command path inside `printf`, `echo`, documentation text, or a grep pattern.
- A provider help form owned by the expanded rule.
- A valid AWS request-skeleton form.
- Existing read-only describe, show, list, and inspection commands.

### FR-7 Runtime parity

Every positive operation fixture must reach:

- `inspect_command` with status `review`.
- The expected provider action class.
- The expected provider rule in rule evidence.
- The expected controlling rule.
- Runtime `extract_sensitive_tool_action_request`.

### FR-8 Delivery boundaries

Each pull request must close exactly 100 checklist tasks and remain independently testable:

1. AWS core and high-frequency services.
2. Google Cloud.
3. Azure.
4. AWS long-tail, AI, backup, and account services.

## Security invariants

- Match canonical executable and argument structure, never raw command substrings.
- A safe variant applies only to the segment and rule it actually matches.
- Unknown options cannot shift the recognized destructive path into an allow decision.
- Provider-global options may be interspersed without changing destructive intent.
- Duplicated inverse or safe options are evaluated conservatively according to effective argument order.
- Compound shell commands retain all destructive matches after safe-segment filtering.
- No cloud credential, resource identifier, API call, or live deletion is required by tests.

## Data validation

AWS operation names are checked against the installed Botocore service models used by the implementation research. Google Cloud and Azure paths are checked against their current official CLI references. Matrix tests also enforce exact batch counts and uniqueness to prevent accidental omission or duplication.

## Test strategy

Each batch adds a focused regression suite with:

- 100 base positive operation cases.
- Safe help cases for every path.
- AWS request-skeleton cases for every AWS path.
- Representative global-option placement cases.
- Native Windows launcher cases.
- Unknown future global-option cases.
- Disabled-safe-form adversarial cases.
- Compound-command isolation cases.
- Quoted-example and source-search negative cases.
- Exact count and uniqueness assertions.

Repository CI remains the final integration gate. Every pull request must also receive an independent adversarial diff review, review-thread reconciliation, and successful required checks before merge.

## Observability and maintenance

The provider extension metadata and coverage documentation must state that coverage is matrix-driven. Future additions should append exact operation paths, extend positive and safe fixtures, preserve existing action classes unless a materially different risk exists, and land in bounded batches with count and uniqueness assertions.

## Acceptance criteria

1. Exactly 400 checklist tasks are complete.
2. The AWS matrix contains 200 unique paths.
3. The Google Cloud matrix contains 100 unique paths.
4. The Azure matrix contains 100 unique paths.
5. All paths feed both inspection and runtime review through existing provider action classes.
6. Help and AWS request-skeleton safe forms remain safe.
7. Windows launcher and provider-global option variants are covered.
8. Quoted examples remain data.
9. Existing rule IDs, permissions, and policy modes remain stable.
10. All required CI checks pass and all review threads are resolved before each merge.

## Primary references

- AWS CLI command reference: https://docs.aws.amazon.com/cli/latest/reference/
- Google Cloud CLI reference: https://cloud.google.com/sdk/gcloud/reference
- Azure CLI reference: https://learn.microsoft.com/cli/azure/reference-index
