# Takeaway Prompt for the Secret Management Build

Copy this prompt into the next implementation task after reviewing the companion documents.

```text
You are implementing the Secret Management and Secret Reads initiative in HOL Guard.

Mission

Build a provider-neutral secret reference and guarded delivery path. Start with native OS secure
storage, then add one reviewed external provider through a typed contract. Keep values resident in the
local broker or selected child-process sink. Give future sponsors useful discovery, conformance and
hosted-policy surfaces without giving payment or provider responses authority over Guard decisions.

Read first

1. docs/guard/secret-management-prd.md
2. docs/guard/secret-management-todo.md
3. docs/guard/secret-management-threat-model.md
4. docs/guard/secret-management-provider-contract.md
5. docs/guard/secret-management-provider-matrix.md
6. docs/guard/secret-management-provider-contributing.md
7. docs/guard/approval-invariant.md
8. docs/guard/native-hook-data-plane-ownership.md
9. docs/guard/extensions/contributing.md
10. docs/guard/extension-builder/README.md
11. The existing files named in PRD section 4. Do not replace existing raw-read floors.

Guardrails

- New deterministic hot-path logic belongs in Rust. Python may parse arguments, render output or call the
  native runtime.
- Read the approval invariant before touching tokens, saved decisions, retry bindings, scope contracts or
  review cards. Keep Allow once and Always allow wherever a review is supported.
- Never print, log, serialize, snapshot, redact-test, telemetry-export or commit a real secret. Use
  synthetic values such as `test-value-7` and synthetic provider names and hosts.
- Do not inspect credential files, environment files, browser profiles or native credential stores while
  authoring. Use disposable fixtures and platform APIs.
- A provider manifest is data. It cannot execute a shell command, choose an arbitrary URL, allow redirects,
  send query credentials, return unbounded data, or change Guard policy.
- External providers are opt-in and inert until a local administrator enables them.
- Provider evidence can tighten a local result but can never create an allow or weaken an existing Guard
  floor. A provider outage cannot lower protection.
- Keep provider network calls off the ordinary hook path. Use a bounded worker, cache and explicit stale or
  unavailable state.
- Default materialization to environment, stdin or file descriptor. Reject agent text, arguments, URLs,
  query strings, clipboard, workspace files, shell history, receipts and telemetry.
- Bind approvals to provider, connection, canonical reference digest, version, capability, destination,
  process, workspace, purpose, policy digest and extension digest. A changed value never changes the token,
  while a changed binding requires a new decision.
- Native OS storage is the first-party default. Unsupported or headless systems return unavailable. Do not
  silently fall back to plaintext or an encrypted file.
- Sponsorship, ranking and referral attribution are presentation data. They never enter a runtime decision.

Implementation order

1. Write or update the ADRs for product boundary, approval binding, delivery sinks and self-hosted endpoint
   locality. Stop if an ADR would weaken the guardrails above.
2. Add closed JSON schemas for provider manifests and secret references. Add typed Rust contracts with
   unknown-field rejection and non-serializable secret-bearing types.
3. Add the platform store trait and native macOS, Linux and Windows backends. Keep user-secret service
   scopes separate from approval-enrollment and internal encrypted-file state.
4. Add canonical reference parsing and digesting. Reject traversal, ambiguity, control characters and
   value-bearing references.
5. Add the broker, cache and policy composition. Preserve existing environment and sensitive-file floors.
6. Add bounded delivery and `hol-guard secrets exec`. Prove cleanup on cancellation, crash, timeout,
   retry and concurrent use.
7. Add pre-tool and pre-exec hooks, post-output redaction and secret-specific review cards. Do not put
   values in hook payloads.
8. Add the provider compiler, trust binding, generated fixtures and conformance command.
9. Add one provider adapter with synthetic offline fixtures, then an installed-runtime check from a released
   Guard. Add more providers only after the same contract passes unchanged.

Required evidence for each pull request

- A focused Rust test that fails on the parent revision and passes on the change.
- A deterministic fixture with benign, protected, unavailable, malformed and changed-binding cases.
- A property or replay test for no value exposure and no approval reuse after binding changes.
- `git diff --check`, schema validation and generated projection checks where applicable.
- Focused Python tests for changed shims, with full-suite results kept separate from focused evidence.
- For a provider, manifest validation, conformance output, privacy review and exact installed Guard version.
- A public-text scan that removes local paths, credentials, private hosts, request ids and secret-like data.

Verification commands

Use the repository's pinned toolchain and the smallest matching target. Examples are illustrative and must
be adjusted to the changed crate or test file.

    cargo +1.89.0 test --locked --manifest-path rust/Cargo.toml -p guard-contracts
    cargo +1.89.0 test --locked --manifest-path rust/Cargo.toml -p guard-runtime secret
    uv run --no-sync pytest tests/<focused-test>.py
    hol-guard --version
    hol-guard extensions generate --secret-provider
    hol-guard extensions validate --secret-provider
    hol-guard command explain '<synthetic-sensitive-case>'

Use the repository-approved heavy-work launcher for expensive local work according to AGENTS.md. Do not background a required
validation command. Do not install the released CLI or connect Guard to an agent without the user's explicit
agreement. Never approve your own Guard request.

Completion gate

The work is complete only when the requested TODO item has implementation, tests, public docs, generated
artifacts and evidence. Report unsupported OS or provider states as unavailable. Record every decision made
without explicit user guidance in the final summary. Leave unrelated working-tree changes untouched.
```

The implementation owner should update the checklist item and the relevant ADR in the same pull request.
The prompt is intentionally reusable for native storage, broker, delivery, provider compiler and adapter
phases, while the TODO remains the source of ordering and acceptance detail.
