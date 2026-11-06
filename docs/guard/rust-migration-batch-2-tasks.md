# Rust Authority Migration Batch 2: Tasks T101-T200

Base branch: `main`

Invariant: supported `PostToolUse` decisions and their security-critical I/O remain Rust-authoritative. Python may coordinate non-authoritative control-plane work but may not become the semantic fallback after native failure, overload, timeout, incompatibility, or malformed output.

## PostToolUse authority

- [ ] T101 Remove Python semantic fallback from supported PostToolUse.
- [ ] T102 Return a native fail-closed response when the resident runtime is unavailable.
- [ ] T103 Return a native fail-closed response when the resident runtime is incompatible.
- [ ] T104 Return a native fail-closed response on resident overload.
- [ ] T105 Return a native fail-closed response on resident timeout.
- [ ] T106 Return a native fail-closed response on resident transport failure.
- [ ] T107 Return a native fail-closed response on malformed native output.
- [ ] T108 Return a native fail-closed response on native panic containment.
- [ ] T109 Remove Python HookReviewEngine authority from supported PostToolUse.
- [ ] T110 Preserve observe-mode semantics without Python re-evaluation.

## Native content and file I/O

- [ ] T111 Keep inline payload extraction in Rust.
- [ ] T112 Keep source-ref path classification in Rust.
- [ ] T113 Keep bounded source reads in Rust.
- [ ] T114 Keep symlink-component rejection in Rust.
- [ ] T115 Keep regular-file verification in Rust.
- [ ] T116 Keep pre/post file identity verification in Rust.
- [ ] T117 Keep source hashing in Rust.
- [ ] T118 Keep output equivalence checks in Rust.
- [ ] T119 Keep secret scanning in Rust.
- [ ] T120 Keep reviewed excerpt construction in Rust.

## Policy snapshot authority

- [ ] T121 Link guard-policy-snapshot into hol-guard-runtime.
- [ ] T122 Define the native policy snapshot wire contract.
- [ ] T123 Bind policy snapshots to monotonically increasing generations.
- [ ] T124 Bind policy snapshots to policy digests.
- [ ] T125 Bind policy snapshots to config digests.
- [ ] T126 Bind policy snapshots to the Rust rule digest.
- [ ] T127 Reject policy generation rollback.
- [ ] T128 Reject malformed policy snapshot digests.
- [ ] T129 Reject policy snapshots with incompatible schemas.
- [ ] T130 Expose active policy generation in native capabilities or health.

## Resident runtime resilience

- [ ] T131 Keep resident authentication mandatory.
- [ ] T132 Keep response binding to request IDs mandatory.
- [ ] T133 Keep request payload digest verification mandatory.
- [ ] T134 Keep response digest verification mandatory.
- [ ] T135 Keep request and response byte limits mandatory.
- [ ] T136 Keep bounded native admission under burst load.
- [ ] T137 Keep deterministic retryable overload signaling.
- [ ] T138 Keep stale queued work from being evaluated.
- [ ] T139 Keep resident panic containment.
- [ ] T140 Keep parent-liveness retirement for orphan prevention.

## Scheduler and transport boundaries

- [ ] T141 Document the remaining Python transport-only boundary.
- [ ] T142 Prove Python transport cannot alter native semantic decisions.
- [ ] T143 Prove Python transport cannot lower native action floors.
- [ ] T144 Prove Python transport cannot convert native failure into allow.
- [ ] T145 Keep non-authoritative evidence persistence off the decision path.
- [ ] T146 Bound evidence queue count.
- [ ] T147 Bound evidence queue bytes.
- [ ] T148 Bound evidence persistence retries.
- [ ] T149 Prevent SQLite stalls from blocking native decisions.
- [ ] T150 Surface degraded evidence persistence without changing decisions.

## Default runtime and rollback

- [ ] T151 Make the bundled Rust runtime the normal production path.
- [ ] T152 Remove strict-mode terminology from runtime configuration.
- [ ] T153 Remove strict-mode terminology from documentation.
- [ ] T154 Remove strict-mode terminology from tests and fixtures.
- [ ] T155 Keep only an explicit emergency disable mechanism where required.
- [ ] T156 Make invalid native mode values resolve to Rust authority.
- [ ] T157 Prevent PATH search for the native runtime.
- [ ] T158 Prevent runtime download during decision handling.
- [ ] T159 Require version-matched bundled runtime identity.
- [ ] T160 Fail closed when bundled runtime identity verification fails.

## Differential and mutation coverage

- [ ] T161 Compare Python reference and Rust PostToolUse decisions over the corpus.
- [ ] T162 Require no Rust decision to be less restrictive than the reference floor.
- [ ] T163 Cover inline safe output.
- [ ] T164 Cover inline secret output.
- [ ] T165 Cover oversized inline output.
- [ ] T166 Cover valid source references.
- [ ] T167 Cover stale source references.
- [ ] T168 Cover source-reference path substitution.
- [ ] T169 Cover source file mutation during read.
- [ ] T170 Cover malformed and duplicate-key JSON.

## Performance and capacity

- [ ] T171 Preserve warm native p95 at or below 20 ms.
- [ ] T172 Preserve cold native p95 at or below 100 ms.
- [ ] T173 Preserve native readiness at or below 250 ms.
- [ ] T174 Preserve at least 1.15x warm p95 speedup.
- [ ] T175 Preserve at least 5x cold p95 speedup.
- [ ] T176 Exercise burst admission with real resident requests.
- [ ] T177 Exercise resident overload without Python spillover.
- [ ] T178 Exercise client abort behavior.
- [ ] T179 Exercise slow-client behavior.
- [ ] T180 Exercise resident restart and recovery behavior.

## Release and packaging

- [ ] T181 Build native wheels for every supported platform tag.
- [ ] T182 Verify embedded runtime hashes.
- [ ] T183 Verify native runtime manifest size and shape.
- [ ] T184 Verify source SHA binding.
- [ ] T185 Verify package version binding.
- [ ] T186 Verify rule digest binding.
- [ ] T187 Verify native runtime platform target binding.
- [ ] T188 Reject duplicate or unexpected wheel entries.
- [ ] T189 Keep the release artifact set exact.
- [ ] T190 Verify installed wheel execution against the real binary.

## CI, review, and delivery

- [ ] T191 Add an always-on Rust authority ownership gate.
- [ ] T192 Expand path triggers to all production hook ingress files.
- [ ] T193 Expand path triggers to daemon scheduler and transport files.
- [ ] T194 Expand path triggers to policy and store files that affect decisions.
- [ ] T195 Run real-binary integration rather than unit-only proof.
- [ ] T196 Run adversarial native failure and overload tests.
- [ ] T197 Run Security Gates and CodeQL.
- [ ] T198 Address every actionable review comment.
- [ ] T199 Require all review threads resolved.
- [ ] T200 Merge only after CI/CD and adversarial review pass.
