# Execution assurance 3.0 launch runbook

Status: final acceptance checklist. This runbook validates a release candidate; it does not authorize deployment or enable a production feature flag.

## Preconditions

- Candidate is built from the intended 3.0 release commit in a clean worktree.
- Python, Bun, and platform-tool versions match the repository configuration.
- Provider binaries and images are pinned by immutable digest. Never substitute a tag during verification.
- Test identities, workspaces, devices, keys, policies, receipts, and leases are synthetic and isolated from production.
- No deployment lock is bypassed and no production deploy is started by this runbook.

## Sequential Guard gates

Run in order; stop on the first failure:

```bash
uv sync --frozen --extra dev
uv run --no-sync python -m ruff check src/
uv run --no-sync python -m ruff format --check src/
uv run --no-sync basedpyright --level error
uv run --no-sync pytest -q
uv build
```

Then install the produced wheel in a clean virtual environment and execute `hol-guard --version` and `hol-guard doctor --help`. Verify the installed command resolves from that environment, not the source checkout.

## Assurance gates

1. Run provider contract and adversarial tests for local OS containment, OCI planning/evidence, Kubernetes RuntimeClass orchestration, provider recovery, and the pinned gVisor reference runtime.
2. Run policy and receipt tests covering requirement monotonicity, deny precedence, evidence framing, redaction, persistence, replay, revocation, fencing, idempotency, terminal-state conflict, and cleanup.
3. Run the all-harness hook/CLI matrix for Codex, Claude Code, Copilot CLI, Cursor, Gemini CLI, Hermes, OpenClaw, Antigravity, OpenCode, Kimi, Grok CLI, Pi, and ZCode.

Reference commands:

```bash
# hol-guard
uv run --no-sync pytest -q tests/test_guard_provider_*.py tests/test_guard_policy_*.py tests/test_guard_receipt_*.py tests/test_guard_evidence_*.py
uv run --no-sync pytest -q tests/test_guard_harness_*.py
gh workflow run guard-gvisor-reference.yml --ref <candidate-branch>
gh workflow run mdm-artifacts.yml --ref <candidate-branch> -f build_id=<candidate-sha>

# hol-points-portal
bun run test -- __tests__/guard-execution-assurance-*.test.ts __tests__/guard-execution-assurance-*.test.tsx
bun run guard:test:mdm
bun run lint
bun run typecheck
NODE_OPTIONS=--max-old-space-size=12288 bun run build
```

The `mdm-artifacts.yml` run is blocking only when its Ubuntu 22.04/24.04, macOS 14/15, and Windows Server 2022/2025 test jobs pass and both unsigned package smoke jobs pass. The gVisor run is blocking only when it executes the real `runsc` corpus; characterization of unavailable optional runtimes remains non-blocking and must be recorded as such.
4. Run the real Linux gVisor isolation corpus. Unit-test skips on unsupported hosts are not a substitute for its passing CI evidence.
5. Run the portable MDM contract matrix. Record native macOS, Windows, and Linux certification independently; portable contract evidence must not be relabeled as native certification.
6. Run the dashboard assurance contract tests, lint, typecheck, production build, migrations, APIs, and browser proof under an isolated Guard test project. Tear down containers with volumes and orphans before completion.

## Mixed-version migration and rollback

Validate these transitions with synthetic data:

- 2.x client with no assurance fields against a 3.0 service: accepted under documented compatibility defaults; never displayed as verified assurance.
- 3.0 client against legacy or capability-limited provider: capability negotiation produces a refusal or explicit lower-assurance result; never a silent downgrade.
- 3.0 receipt and lease replay: duplicate delivery is idempotent, forks are refused, and terminal state cannot regress.
- Feature disabled after 3.0 data exists: existing evidence remains readable under retention policy, new authority is not granted, and rollback does not delete audit records.

Rollback means disable routing to the new capability and restore the prior compatible application version. It does not mean deleting receipts, rewriting lineage, bypassing fencing generations, or downgrading stored assurance claims.

## Privacy and abuse checks

- Stored and rendered evidence contains digests, bounded metadata, and redacted diagnostics only.
- Raw prompts, tool arguments, environment values, provider stdout/stderr, bearer material, cookies, and host paths do not enter receipts, logs, URLs, or browser storage.
- Lease, health, ingestion, and evidence endpoints enforce tenant/workspace/device ownership, freshness, audience, signature, sequence, and idempotency.
- Metadata endpoints, DNS rebinding, Docker/container sockets, privileged mounts, and forbidden host paths remain inaccessible from isolated workloads.

## Evidence record

Record commit SHAs, immutable provider digests, exact commands, pass/fail counts, platform and architecture, CI run URLs, browser viewport, feature-flag state, migration version, and teardown result. Do not record secrets or raw workload content.

A gate is complete only when all required evidence is current for the candidate commit. Baseline or infrastructure failures must be identified with a reproducer and owner; they are not silently relabeled as passes.
