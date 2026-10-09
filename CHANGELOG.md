# Changelog

All notable changes to HOL Guard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Older releases are preserved in the [changelog archive](docs/changelog-archive.md).

## Unreleased

### Fixed
* **daemon:** retire a same-install daemon left running across an in-place upgrade that changes only the native runtime. The daemon pins its runtime fingerprint at start and reports its install root in authenticated health details, so the upgraded CLI can neither adopt nor relabel the previous generation; the runtime manifest joins that fingerprint, and the managed OMP and Pi extensions request one bounded recovery when readiness reports `native_policy_not_ready`, then retry once without further recovery. Admission, native fail-closed behavior, and current-daemon adoption are unchanged.
* **approval:** native authenticated SQLite and inline lookup qualify exact artifact-context grants for reapproval reuse. Generic hooks and harness-start consumers preserve qualification across atomic claims and revalidation; retained generic grants must match the fresh authenticated grant fields after claiming, excluding global authority and integrity ledger counters changed by unrelated approvals, while consumed one-shot grants retain their claim proof. Final native decision contracts accept qualified reapproval claims. Changed artifacts, incomplete directory identities, invalid integrity, revoked retained grants, and terminal restrictions remain enforced.
* **launch:** compute launch argv and canonical authority digests in Rust instead of emitting unbound sentinels; hash verification material once, retaining fail-closed encoding checks; bind previews and execution to the selected store Guard home, including explicit prompt transport. Qualified installed-wheel OMP launches and managed-extension reads retain native content and context verification. Launch approvals issued with the former unbound digests require fresh approval after upgrading.
* **tests:** isolate the cloud graph snapshot-without-workspace fixture from host Node and repository cwd using an owned launcher, retaining real native launch identity, original graph assertions, and unchanged deadlines.
* **gauntlet:** match the pinned native edit grammar's horizontal header padding while retaining byte-identical edit input, exact reviewed targets, and rejection of ambiguous or changed paths; explicitly advertise parallel native-tool capability without forcing model calls.
* **ci:** stream full command-corpus worker reports into owned result groups instead of retaining duplicate case-ID lists; preserve all three partitions, worker concurrency, original oracles, and time and memory limits.
* **contracts:** complete canonical external trust bindings for CodeSage, VaultSync, Omairc, FetchSandbox MCP, and Setup Doctor MCP after retiring the derived repository trust cache; retain full-catalog ownership validation and opt-in review boundaries.
* **ci:** create the managed-resident integration fixture's Guard home with private permissions before publishing signed snapshots, so real handoff and retained-client checks reach their intended lifecycle paths without weakening native directory ownership checks.
* **ci:** bind manual Sonar analysis to the exact checkout and its unique open same-repository pull request instead of overwriting main; reject stale or mismatched server analysis and enforce the complete standard quality gate within the existing shared polling budget.
* **ci:** let the opted-in Windows release producer preserve successful scheduled or manual main builds in the existing trusted host cache; keep PRs, other non-push jobs, cache identity, current-source artifact verification, and build deadlines unchanged.
* **ci:** make the authenticated native recovery fixture's accepted socket blocking on Unix before its unchanged read deadline, preserving authentication rejection and recovery checks without scheduler-dependent `WouldBlock` races or diagnostic-text assertions.
* **ci:** bind approval-reuse regressions to the canonical provisioned native context fixture after fixture modularization, retaining all native decision, error-envelope, and claim checks without a duplicate fixture or compatibility alias.
* **policy:** accept schema-permitted fractional UTC timestamps on Python 3.10 while preserving all nine digits; retain calendar validation, including leap-day rejection, and compare restrictive expiry changes at full nanosecond precision without Python-version-dependent parsing.
* **contracts:** add the missing authored external trust binding for the canonical Showtime command source; retain complete-catalog ownership checks during wheel builds.
* **packages:** preserve exact Git revision and credential-bearing source identity in private native execution IPC while keeping public output redacted; retain package-source environment names so alternate-index reinstalls still require review.
* **hooks:** preserve the selected Guard home during approval reconstruction and live revalidation instead of starting package parsing in an unrelated default-home resident.
* **hooks:** constrain package-review RPCs by the original absolute hook deadline and any earlier explicit timeout, including resident-capacity waits and the native request budget.
* **native:** hash executable contents with the existing hardware-aware SHA-256 backend while retaining fresh reads, file-descriptor identity checks, and replacement detection; no content cache is introduced.
* **hooks:** carry the original hook deadline through native review, failure-record SQL operations, and late-result fail-safe rendering, preserving earlier inherited deadlines and restoring the caller's context.
* **tests:** isolate native cwd fixtures across repeated CI runs and assert protected-call denials and Kubernetes hook exit codes rather than incidental review wording or source indentation.
* **ci:** provision real checkout-built native runtime and compiler executables once for both Windows updater Python versions, using a supported Python 3.12 bootstrap and source-bound current-attempt artifacts instead of rebuilding in each consumer; retain explicit `.exe` selectors and fail-closed MCP identity checks.
* **packages:** share `uvx` option arity rules for executable and dependency selection, including Python/index/constraint short aliases; preserve executable argument boundaries. Keep here-strings distinct from heredocs so `<<<` cannot hide subsequent package commands.
* **ci:** fail projection preparation after a bounded five-minute subprocess timeout instead of leaving coverage shards waiting indefinitely.
* **packages:** review the distribution selected by `uvx --from` and dependencies selected by `--with` or `-w`, without treating tool arguments as package options; forward the selected Guard home when normalizing action envelopes.
* **packages:** preserve exact archive URLs and command tokens on the private resident-to-SDK transport so acquisition retains credentials, query parameters, and fragments; keep public projections sanitized and command tokens redacted.
* **packages:** retain alternate-index environment variable names when redacting their URL values so same-version installs still require review; classify named editable VCS dependencies as remote sources, not local workspace projects.
* **packages:** parse compound installs containing quoted or unquoted heredocs without crashing the resident; use a regex engine that supports heredoc quote backreferences.
* **packages:** `uvx --with-requirements` and `--with-editable` now consume their dependency operands without replacing the executable package target, including `--option=value` forms.
* **packages:** redact URL-bearing package-command tokens, including SSH sources and registry environment assignments, to prevent credential disclosure.
* **packages:** honor the selected Guard home through hook normalization, request extraction, MCP requests, contained execution and package shims; remove duplicate resident parser retries.
* **packages:** split native parsing and package regression fixtures into cohesive modules while retaining resident-only authority and the existing behavioral coverage.
* **ci:** reconcile complete source-derived command and directory projections before native coverage shards; require explicit external bindings for published identities instead of retaining stale artifact-overlay descriptors.
* **ci:** keep isolated wheel projection builds free of runtime validation dependencies; prepare and validate directory projections in the coverage environment.
* **windows:** restore native hook verdicts and runtime receipts by returning complete launch identities on non-Unix platforms. Missing identity fields previously raised `KeyError` and replaced the real verdict with `native_hook_worker_exception`.
* **windows:** share shell-command parsing and labeled argv digests with Unix, and align cwd home expansion and extended-path handling with Python. Unsupported identities remain unverified and non-reusable; malformed commands and non-string arguments fail closed.
* **security:** update the pinned CI agent fixture to Sharp 0.35.5 and its patched libvips bundles, addressing GHSA-wq5f-xc86-pv6w without changing the pinned agent versions.
* **ci:** move package-policy precedence regressions into a focused module, isolate the stale-bundle case from the runner's npm installation, and remove source-text analytics assertions while retaining behavioral coverage.
* **ci:** reuse each coverage shard's matching native source compiler for wheel builds while retaining projection and packaged-resource validation; remove incidental workflow assertions and the obsolete 4 MiB fixture-size precondition while preserving native matcher-node and input-byte rejection checks.
* **extensions:** preserve AgentBridge short-help exemptions with option-arity checks and retain the reviewed native rules' community opt-in activation and risk labels.
* **ci:** require the full validation lane for command-protection sources, descriptors, authoring manifests, and MCP policy; retain the metadata lane for extension listings and portable fixtures, with deletions and type changes escalating.
* **ci:** run fresh full-target Rust workspace and coverage gates with checksum-pinned nextest and optimized test builds while retaining debug assertions, overflow checks, bounded concurrency, and zero retries; import the successful current-attempt strict Clippy report into Sonar instead of recompiling it, rejecting stale or mismatched report identities.
* **ci:** print rendered Clippy diagnostics on a failing strict workspace check without changing its exit status or publishing a failed report; replace obsolete Rust coverage command assertions with stale-report and test-failure checks.
* **native:** identify the timed-out transport phase in existing opt-in diagnostic logs without changing launch-identity failure categories, runtime deadlines, or fail-closed decisions.
* **native:** retain opt-in finite-label resident phases in an owner-private shared file capped at 64 KiB, independent of helper lifetimes; drain helper stderr into at most 64 validated rows in memory, reject unsafe files and fragmented private lines, join helper readers on retirement, and preserve production output, deadlines, and fail-closed decisions.
* **ci:** enforce each daemon workload client's declared concurrency with concurrently primed bounded producers, retaining aggregate load, all requests, and existing latency/fairness gates.
* **ci:** let default-branch CodeQL analyses finish instead of automatically canceling an overlay-base build and poisoning the shared overlay status cache; retain cancellation of obsolete PR analyses and the full scan/query scope.
* **daemon:** reuse one connection scope for a hook's managed-install lookup and fallback listing, avoiding duplicate SQLite schema setup while preserving independent current transactions, private-mode repair, outbox commits, and fail-closed read errors.
* **ci:** enable existing test diagnostic markers before session resident prewarming so timeout logs can contain Rust phases; preserve immutable pool environments and production behavior.
* **ci:** retain the running workflow revision's wheel-size checker and unchanged budgets outside immutable release-source checkouts, enforcing the same gate for historical repairs and native artifacts.
* **ci:** verify checksum-pinned nextest downloads on Python 3.10 with bounded streaming SHA-256 reads, and bound its version probe.
* **ci:** make absent managed stores explicit before opening a connection scope, preserving existing hook decisions while allowing the optional-store type check to pass.
* **ci:** collect pytest once for the shard plan and complete protected test inventory, retaining markers, corpus and source metrics before scheduling-only nodes are excluded; run the remaining static quality checks independently of native artifact production.
* **ci:** remove obsolete fake-Cargo workflow command tests after the real pinned nextest cutover; retain required-aggregate failure checks and complete native test execution.
* **ci:** preserve canonical lockfile format and release-version annotations, and keep unchanged workload/status/configured-proof timing contracts in required isolated lanes.
* **ci:** detect musl Python hosts from their build triplet when GNU-symbol libc detection is empty; retain the pinned archive checksums and bounded nextest version probe.
* **packages:** preserve approved signed archive URLs in separately validated native private metadata; keep queries and userinfo out of public intents, artifacts, receipts, and reasons, and reject missing or mutated private sources before execution.

### Features
* **policy:** the resident is the sole approval-reuse decision authority. Python no longer recomputes reuse when the resident is unavailable; callers preserve the current evaluation without claiming a saved approval. Malformed decision fields and mismatched response envelopes are rejected.
* **policy:** approval reuse rejects non-JSON action objects and verifies the canonical request digest. A resident failure after an atomic claim preserves the freshly recomputed action, never a stale allow; unavailable residents honor the existing circuit cooldown.
* **policy:** sensitive stdio reads share one two-second approval-reuse budget across claims and policy refreshes; exhausted deadlines cannot dispatch another reuse request or grant a claim.
* **policy:** the saved-package-approval claim now resolves inside the resident. The `apply_stored_package_policy` operation ships the evaluation, artifact and store path to `evaluate_apply_stored_package_policy`, which reuses the ported `resolve_stored_package_policy_override` and returns the evaluation unchanged when the store holds no usable saved approval. The previous `commands_hook_native_eval` bridge re-entered the Python override; it now routes through `apply_stored_package_policy_native` and, on transport failure, returns the evaluation unchanged — the resident's own no-saved-approval terminal — rather than re-running the Python override.
* **runtime:** package-intent parsing now uses the resident as its sole authority, with no Python evaluator fallback. The Python adapter submits command text and the selected Guard home; unavailable or malformed native responses return `None`. Native parsing supports `uvx`, leading environment assignments, and launch-context evidence. URL-bearing tokens are redacted as `[REDACTED_URL]`, except validated JavaScript Git source spellings retain sanitized repository identity without credentials or query values; recognized source-environment assignments retain their names with redacted values. `--path` operands are redacted as `<local-path>`. Package-intent regression fixtures require an explicitly configured runtime and enrolled Guard home.

* **sync:** the resident reads OAuth credentials through the scoped secret authority. The `oauth_local_credentials` payload holds metadata only (`credentials_ref` + `credentials_sha256`), so the secret behind that ref is now resolved and verified before a sync starts — against the same fingerprints the Python store writes (scrypt, plus the legacy `pbkdf2-sha256$` and bare sha256 forms), implemented in Rust so the resident can reproduce them byte-for-byte. A record whose secret no longer matches its fingerprint now reads as `degraded` instead of being trusted, and a normally-provisioned store — which never inlines secret material — can start native sync.
* **mcp:** proxy the MCP server transport through a persistent native session when the resident advertises `mcp-stdio-session-v1`. The resident spawns the scrubbed child, owns newline JSON-RPC framing and cross-correlation, and tears down the process group; Python keeps the client stream and `tools/call` verdict authority. A reachable resident that fails to open a session is terminal — Python never substitutes its own subprocess.
* **policy:** native policy-decision lookup owns the complete guard store read in Rust, including once-only approvals, authority-kind claims, and one-shot remote consumption; unavailable native authority stops the lookup rather than falling back to Python selection.
* **mcp:** the resident owns the tools/list boundary — `_canonical_tool_catalog_entry`, `_normalized_tools_catalog_page`, and `_tool_catalog_fingerprint` delegate to the new `mcp_tool_catalog_fingerprint` context-digest kind. Rust canonicalizes each advertised entry (name-strip, `input_schema`→`inputSchema`, `output_schema`→`outputSchema`), rejects malformed pages (non-dict item, blank/non-trimmed/duplicate name, unserializable payload), and emits the sha256 fingerprint over `{state, tools(sorted), version}`. `validate_context_tokens` now treats byte-identical opaque tokens — including the `guard-context-unbound:*` sentinel — as unchanged instead of `approval_reuse_content_changed`.
* **mcp:** the resident owns MCP call-argument display safety — `_safe_mcp_arguments`/`_safe_mcp_params`/`_mcp_arguments_digest`/`_launch_target` and the stdio `_redact_json` traffic recorder delegate to `mcp_arguments_projection`/`mcp_redact_json` context-digest ops; Python keeps no fallback masking path.
* **sync:** port the Guard-Cloud sync transport into the resident — OAuth credential read, ES256 DPoP proof signing (ring PKCS#8→r||s JWT), issuer/sync-endpoint origin allowlisting, and the bounded `ureq` retry state machine (DPoP nonce fast-path, 429 waits, gateway retries, one longer-timeout retry). `GuardSyncRequest` carries the `retry_context` side-channel so nonce/timeout retries re-sign proofs without re-reading credentials. Token refresh and bundle-sync orchestration remain Python-owned until the secret-store write path is ported; an expired cached token resolves to the authorization-expired `ask` rather than a silent local-only downgrade, and `supply-chain-cloud-transport-v1` is not yet advertised so production evaluation keeps routing through the Python refresh path.

### Bug Fixes

* **policy:** approval-reuse runtime discovery and capability probes consume the same deadline as the resident request; discovery cannot restart the per-call budget, and an expired request is not dispatched after serialization.
* **hooks:** normalize Hermes `pre_tool_call` and `post_tool_call` events through the shared hook event parser. An unavailable worker must block a protected pre-tool call instead of treating it as an observational lifecycle event and returning allow.
* **hooks:** route structured `--json` responses and remaining Grok/ZCode verdict emit paths through the shared exit-code authority, removing the competing response-layer table. Envelope-driven pre-execution and approval verdicts, including `PermissionRequest`, exit `0`; post-execution violations and rc-driven harness denials remain nonzero.
* **native:** the context-digest transport now establishes the resident's on-disk prerequisite (the owner-private `policy-verifier.key` under `<guard-home>/native-runtime/`) before shipping a request, the way every native launch/session caller already did. Launch and executable identities became resident-owned, so a guard home that had never been provisioned — a fresh deployment, or a test home carrying a seeded key — failed closed on `native_runtime_launch_identity_unavailable`, `native_mcp_launch_environment_unavailable`, and `native_package_context_digest_unavailable`. An existing key file is accepted as satisfied without opening a store; only a missing key is provisioned, once per home per process.
* **native:** a digest request that arrives while the pool has no parked resident client is granted a cold-start allowance on top of the steady-state budget. The pooled resident is spawned lazily, and a contended runner can spend several hundred milliseconds faulting a 20 MB binary in before it answers; charging that startup to the 500 ms degradation budget made launch-identity and package-context callers — which have no fallback — fail closed on a resident that was merely still starting, or one that a killed process had taken with it. The allowance tracks the pool instead of remembering past answers, so it is granted again whenever the resident has to be spawned (fresh process, retired client, killed resident) and never in steady state.
* **native:** the `*_unavailable` errors the context-digest wrappers raise now carry the transport's reason (`native_context_digest_unsupported`, `..._prerequisite_unavailable`, `..._request_too_large`, `..._result_invalid`, `native_overloaded`, or the resident client's own code such as `native_client_timed_out`). A bare "unavailable" could not distinguish a missing runtime from an unprovisionable guard home, an oversized request, a slow spawn, or a malformed answer.
* **native:** a context-digest request whose deadline ran out — the client's `native_client_timed_out` or the resident's own `native_client_deadline_exceeded` — is retried once with twice the cold-start allowance. The pooled resident serves one request at a time, so a sibling's long RPC could consume the steady-state budget and fail a request that was neither slow nor dead, and the resident's own bound (which the request carries) must not make the retry hopeless. Only a request that has already failed pays for the retry; every other failure still fails after a single attempt, and the reason names the transport, the attempt count and the budget that actually failed.
* **native:** a package-intent parse now sends the caller's `PATH` to the resident. The resident is long-lived, so its own `PATH` is the one it was spawned with; a manager it cannot resolve (`npx` from a test or tool directory) made the TypeScript launch evidence incomplete and sent a contained typecheck back to review even though the caller resolved the manager fine.
* **native:** a resident that answers a context-digest request with its own error envelope is now reported by that code — and recorded against the resilience breaker — instead of being flattened into `native_context_digest_result_invalid`. An envelope outside the contract keeps its code in the rejection reason, and a rejected result names the contract clause that rejected it with the offending keys, so a foreign frame, a stale frame and a truncated read are no longer indistinguishable.

## [3.36.1](https://github.com/hashgraph-online/hol-guard/compare/v3.36.0...v3.36.1) (2026-10-09)


### Bug Fixes

* **ci:** reject missing authored trust before preparation ([4ca519d](https://github.com/hashgraph-online/hol-guard/commit/4ca519d37aeb890d0834a010143db3c07d913761))
* honor verified exact approval for native OMP launch ([#3778](https://github.com/hashgraph-online/hol-guard/issues/3778)) ([8eb477e](https://github.com/hashgraph-online/hol-guard/commit/8eb477ede17aec341998c26a2ced6f248f514849))
* **release:** compare cached and cold builds under the same compiler wrapper ([#3786](https://github.com/hashgraph-online/hol-guard/issues/3786)) ([1f6bb79](https://github.com/hashgraph-online/hol-guard/commit/1f6bb79f1d47c19156ce642e7626dc6304a78ac6))
* **runtime:** keep hooks working when two Guard installs share a home ([#3791](https://github.com/hashgraph-online/hol-guard/issues/3791)) ([0eac18e](https://github.com/hashgraph-online/hol-guard/commit/0eac18eb043ebd814ca6daeeaf29880c75864b73))


### Performance Improvements

* **release:** cross-compile Intel macOS binaries on Apple silicon ([#3783](https://github.com/hashgraph-online/hol-guard/issues/3783)) ([08a84ee](https://github.com/hashgraph-online/hol-guard/commit/08a84ee34f5d004fec3babf3a39f1df224391745))

## [3.36.0](https://github.com/hashgraph-online/hol-guard/compare/v3.35.0...v3.36.0) (2026-10-08)


### Features

* **mcp:** support direct-command launcher and add run MCP contribution ([#3325](https://github.com/hashgraph-online/hol-guard/issues/3325)) ([76fe4b0](https://github.com/hashgraph-online/hol-guard/commit/76fe4b080192ac8bb5deb4a9c3fba9d633725fcb))


### Bug Fixes

* **extensions:** bind the run MCP contribution to the external trust class ([#3784](https://github.com/hashgraph-online/hol-guard/issues/3784)) ([c3d8209](https://github.com/hashgraph-online/hol-guard/commit/c3d8209a745c75466f39bc79da3c86498a63d64c))
* **gauntlet:** bind native edit grammar and preserve bounded corpus memory ([#3776](https://github.com/hashgraph-online/hol-guard/issues/3776)) ([8ae4da5](https://github.com/hashgraph-online/hol-guard/commit/8ae4da5456f968f7879bcaa1a154597a9145977a))
* **guard:** allow relative cd into the workspace, piped git reads and pipe-through cat ([#3780](https://github.com/hashgraph-online/hol-guard/issues/3780)) ([25b661b](https://github.com/hashgraph-online/hol-guard/commit/25b661b80c743cb73378a78bab4689dbbbda68a6))
* **guard:** offer and honor exact-action Always on daemon native reviews ([#3772](https://github.com/hashgraph-online/hol-guard/issues/3772)) ([429e8f8](https://github.com/hashgraph-online/hol-guard/commit/429e8f81690d84ba2b8d52657f80113e4bcb5c9d))
* **update:** refresh managed hook clients and keep settings scoped to --guard-home ([#3764](https://github.com/hashgraph-online/hol-guard/issues/3764)) ([9b71e1a](https://github.com/hashgraph-online/hol-guard/commit/9b71e1a7207cc12320bad120a1f4412a46fefd8f))
* **update:** retry native resident retirement before failing the update ([#3781](https://github.com/hashgraph-online/hol-guard/issues/3781)) ([e0d10a6](https://github.com/hashgraph-online/hol-guard/commit/e0d10a656a52c25a0209fec145c8964005c1b058))


### Performance Improvements

* **release:** content-addressed release compilation and one build graph ([#3782](https://github.com/hashgraph-online/hol-guard/issues/3782)) ([db079dd](https://github.com/hashgraph-online/hol-guard/commit/db079ddd7a823b0588fd898ea4643dd3dd76d860))

## [3.35.0](https://github.com/hashgraph-online/hol-guard/compare/v3.34.1...v3.35.0) (2026-10-08)


### Features

* **gauntlet:** run catalog cases in parallel with --jobs ([#3765](https://github.com/hashgraph-online/hol-guard/issues/3765)) ([5f1ca7c](https://github.com/hashgraph-online/hol-guard/commit/5f1ca7cdeb81d3301ee2f630757be6acd7fef5b5))
* **gauntlet:** run the native Luna route at medium effort by default ([#3767](https://github.com/hashgraph-online/hol-guard/issues/3767)) ([4e0234d](https://github.com/hashgraph-online/hol-guard/commit/4e0234d3876035d44aa7c41535c2bd0a8ddf7265))
* **guard:** prove Wrangler version, help and whoami reads benign ([#3774](https://github.com/hashgraph-online/hol-guard/issues/3774)) ([632a120](https://github.com/hashgraph-online/hol-guard/commit/632a1202dacee3bc787fbcd3779aea9cf4d5aab2))


### Bug Fixes

* **ci:** reuse native source compiler for shard wheel builds ([#3701](https://github.com/hashgraph-online/hol-guard/issues/3701)) ([fb3af28](https://github.com/hashgraph-online/hol-guard/commit/fb3af285669014676038e6e1266626a0e9f5756a))
* **gauntlet:** run the native Luna route on Windows ([#3759](https://github.com/hashgraph-online/hol-guard/issues/3759)) ([d52e029](https://github.com/hashgraph-online/hol-guard/commit/d52e0295a73a62fdce59e83d26b6c763ce2bd80b))
* **guard:** contain test runs wrapped in a workspace cd or output filter ([#3775](https://github.com/hashgraph-online/hol-guard/issues/3775)) ([44d5a31](https://github.com/hashgraph-online/hol-guard/commit/44d5a319cdeb2edf461b2319a995313a5356feca))
* **guard:** stop asking approval for bounded waits and read-only probes ([#3773](https://github.com/hashgraph-online/hol-guard/issues/3773)) ([d992303](https://github.com/hashgraph-online/hol-guard/commit/d992303ed65c36c928e0147449bc56cabbe14d6d))
* **windows:** restore the native build and parallel Gauntlet workers ([#3771](https://github.com/hashgraph-online/hol-guard/issues/3771)) ([a8c8c3c](https://github.com/hashgraph-online/hol-guard/commit/a8c8c3cdafbe0e3fd13e6a7d039baeb55ca99195))


### Performance Improvements

* **release:** compile in parallel and start Desktop signing sooner ([87a5329](https://github.com/hashgraph-online/hol-guard/commit/87a532952ab75ea87d04ebd05489c9de5c71131f))

## [3.34.1](https://github.com/hashgraph-online/hol-guard/compare/v3.34.0...v3.34.1) (2026-10-08)


### Bug Fixes

* **guard:** bind approval scope sweeps to the decided action ([#3758](https://github.com/hashgraph-online/hol-guard/issues/3758)) ([f4de331](https://github.com/hashgraph-online/hol-guard/commit/f4de331ce6ed5df4f85e421d146364a4700a6406))

## [3.34.0](https://github.com/hashgraph-online/hol-guard/compare/v3.33.0...v3.34.0) (2026-10-08)


### Features

* add external opt-in Kranz MCP coverage ([#3739](https://github.com/hashgraph-online/hol-guard/issues/3739)) ([efd99ad](https://github.com/hashgraph-online/hol-guard/commit/efd99ad5afcac604636bbad4a7f90e4f20e126c9))
* **extensions:** add a proposed Google Workspace extension pack ([#3716](https://github.com/hashgraph-online/hol-guard/issues/3716)) ([b2ee37b](https://github.com/hashgraph-online/hol-guard/commit/b2ee37b9f80d8ca11dfb309d3f301259bbc756e5))
* **extensions:** add community-maintained command.omairc coverage ([#3002](https://github.com/hashgraph-online/hol-guard/issues/3002)) ([195f204](https://github.com/hashgraph-online/hol-guard/commit/195f2042d267d1b071b7a8a4e8e5bac5ca11bae5))
* **extensions:** add opt-in Gmail MCP coverage ([#3757](https://github.com/hashgraph-online/hol-guard/issues/3757)) ([81ed0d4](https://github.com/hashgraph-online/hol-guard/commit/81ed0d4418bd2a92de950e43d06f337aec2b8f1f))
* **extensions:** add publisher listing for mcp.agenthub ([#3741](https://github.com/hashgraph-online/hol-guard/issues/3741)) ([bd063ed](https://github.com/hashgraph-online/hol-guard/commit/bd063edcea3e4d322d3148495642ef083b7ebba5))
* **extensions:** cover versioned gws services and Drive v2 routes ([#3756](https://github.com/hashgraph-online/hol-guard/issues/3756)) ([c39507c](https://github.com/hashgraph-online/hol-guard/commit/c39507c9db61bcfde22b8b81013c3d4d3ab6c6aa))
* **gauntlet:** run Luna high through an Oh My Pi ChatGPT login ([#3753](https://github.com/hashgraph-online/hol-guard/issues/3753)) ([67ad28d](https://github.com/hashgraph-online/hol-guard/commit/67ad28dd533e85897dcdf69a7001562b3a638a96))
* **mcp:** add FableCut MCP server contribution ([#3746](https://github.com/hashgraph-online/hol-guard/issues/3746)) ([cbb94dd](https://github.com/hashgraph-online/hol-guard/commit/cbb94dd571963937ad6cbf1306df5112d2a75b13))


### Bug Fixes

* **extensions:** add missing trust bindings for five merged contributions ([#3755](https://github.com/hashgraph-online/hol-guard/issues/3755)) ([a182221](https://github.com/hashgraph-online/hol-guard/commit/a1822212398caa870b2eaedf4f0afa08548cfdf2))
* **extensions:** retire the tracked aggregate trust map ([39341fa](https://github.com/hashgraph-online/hol-guard/commit/39341fa7ca5f3fd85782d7e79cff60791879170b))
* **gauntlet:** accept Windows spellings of the Watch fixture cwd ([#3743](https://github.com/hashgraph-online/hol-guard/issues/3743)) ([0bfbc1f](https://github.com/hashgraph-online/hol-guard/commit/0bfbc1f1a3ff3ed8245065c0ea36cf0e2a8d2ce9))
* **guard:** let the first prompt in a new workspace wait for policy to load ([#3752](https://github.com/hashgraph-online/hol-guard/issues/3752)) ([cf98a2f](https://github.com/hashgraph-online/hol-guard/commit/cf98a2fda9702dab94064071b4443174dc8d3270))


### Documentation

* **extensions:** add reviewed x-reader publisher listing metadata ([#3747](https://github.com/hashgraph-online/hol-guard/issues/3747)) ([e5df801](https://github.com/hashgraph-online/hol-guard/commit/e5df801303bd303840ffb6f034730ac73afda320))

## [3.33.0](https://github.com/hashgraph-online/hol-guard/compare/v3.32.0...v3.33.0) (2026-10-08)


### Features

* add Syngraphe publisher listing ([#3451](https://github.com/hashgraph-online/hol-guard/issues/3451)) ([4a44336](https://github.com/hashgraph-online/hol-guard/commit/4a4433637b1ce1de9daa69f49be5069b8c312772))
* **extensions:** add opt-in gws command risk rules ([b319f2f](https://github.com/hashgraph-online/hol-guard/commit/b319f2f71061fafcf9f8fdd442a870b2fc00bb07))
* **extensions:** add shellroute command safety extension ([#2927](https://github.com/hashgraph-online/hol-guard/issues/2927)) ([8150b24](https://github.com/hashgraph-online/hol-guard/commit/8150b24e9889b286649a4a1e9e6f5766ccfd463f))
* **guard:** RTM-032 — package_intent_parser resident-sole-authority ([#3659](https://github.com/hashgraph-online/hol-guard/issues/3659)) ([7e5d938](https://github.com/hashgraph-online/hol-guard/commit/7e5d938160ac12f2471aa72fa9634333937caad6))
* **guard:** RTM-032 — resident approval_reuse_decide as sole reuse authority ([#3658](https://github.com/hashgraph-online/hol-guard/issues/3658)) ([27ebfae](https://github.com/hashgraph-online/hol-guard/commit/27ebfaee6562cc3273f2a6be7988da0c4da17f61))


### Bug Fixes

* **ci:** restore native test setup and Gauntlet task scheduling ([63a0006](https://github.com/hashgraph-online/hol-guard/commit/63a000612de06071f372db8d362b27dd60e642b3))
* **extensions:** add the shellroute external trust binding ([#3745](https://github.com/hashgraph-online/hol-guard/issues/3745)) ([c55054d](https://github.com/hashgraph-online/hol-guard/commit/c55054dd3df66e5f2314d65e967efcfc32cdb302))
* **gauntlet:** keep Windows fixtures byte-exact and redact forward-slash drive paths ([#3731](https://github.com/hashgraph-online/hol-guard/issues/3731)) ([cb20572](https://github.com/hashgraph-online/hol-guard/commit/cb20572ef692a6e57c3ab1c669226b10c37c1e09))
* **guard:** accept exact Windows drive paths as cd and git -C targets ([#3728](https://github.com/hashgraph-online/hol-guard/issues/3728)) ([e258f28](https://github.com/hashgraph-online/hol-guard/commit/e258f28ae9bb49bae931e4f77065fa24d1f36cef))
* **guard:** compile archive containment on ARM64 musl ([daa92f0](https://github.com/hashgraph-online/hol-guard/commit/daa92f0b2bd468048047fd8c8e5b6ab8d95e9e7b))
* **guard:** drain leases of exited Windows clients so resident stop does not fail ([#3725](https://github.com/hashgraph-online/hol-guard/issues/3725)) ([553b8f7](https://github.com/hashgraph-online/hol-guard/commit/553b8f70cc9d0d5e539eb52da6267d1492de2c8d))
* **guard:** let resident-stop reach live Windows residents and retire dead ones ([#3735](https://github.com/hashgraph-online/hol-guard/issues/3735)) ([a59ab66](https://github.com/hashgraph-online/hol-guard/commit/a59ab66c59e3001066f7682398bf5b6b8531e67e))
* **guard:** publish independent managed authority posture ([#3738](https://github.com/hashgraph-online/hol-guard/issues/3738)) ([498b428](https://github.com/hashgraph-online/hol-guard/commit/498b4287287ff53c5108bc878444cea92e8583fe))
* **guard:** trust Windows git by Program Files location instead of environment variables ([#3724](https://github.com/hashgraph-online/hol-guard/issues/3724)) ([fdeb257](https://github.com/hashgraph-online/hol-guard/commit/fdeb257ed1b3997ed3e10ed5a9717fc9ba557887))
* **runtime:** hand the home over from an orphaned older resident ([#3732](https://github.com/hashgraph-online/hol-guard/issues/3732)) ([4f9b8e4](https://github.com/hashgraph-online/hol-guard/commit/4f9b8e4a4fa1934756cd5f7ac9321905cf6621cf))


### Documentation

* **runtime:** remove obsolete review and slice notes ([#3736](https://github.com/hashgraph-online/hol-guard/issues/3736)) ([7855c58](https://github.com/hashgraph-online/hol-guard/commit/7855c580359056eea9c94ec8c88e842bdbd49571))

## [3.32.0](https://github.com/hashgraph-online/hol-guard/compare/v3.31.0...v3.32.0) (2026-10-07)


### Features

* **extensions:** add command.showtime command source ([#3302](https://github.com/hashgraph-online/hol-guard/issues/3302)) ([b4f8c7f](https://github.com/hashgraph-online/hol-guard/commit/b4f8c7ff0a10ef1273098ea1cd12d8b92a7197fb))
* **gauntlet:** run the Guard Gauntlet on Windows hosts ([#3727](https://github.com/hashgraph-online/hol-guard/issues/3727)) ([454430f](https://github.com/hashgraph-online/hol-guard/commit/454430f81b4a7e0b09bf0952ff5188957a838d95))
* **review:** show saved business requests in local review ([f2f76d6](https://github.com/hashgraph-online/hol-guard/commit/f2f76d675754019ec7f7a4b77aeb3483fca00c34))


### Bug Fixes

* **guard:** keep existing workspaces admitted while a new workspace policy publishes ([#3726](https://github.com/hashgraph-online/hol-guard/issues/3726)) ([5bd1d9a](https://github.com/hashgraph-online/hol-guard/commit/5bd1d9a7be16033c66ec9fc09e982bee3d2f84c8))
* **guard:** review Windows source reads through a handle-bound path walk instead of blocking every read ([#3718](https://github.com/hashgraph-online/hol-guard/issues/3718)) ([d6302f6](https://github.com/hashgraph-online/hol-guard/commit/d6302f6681ba99ee5de19fd178584d2e47c9f473))

## [3.31.0](https://github.com/hashgraph-online/hol-guard/compare/v3.30.0...v3.31.0) (2026-10-07)


### Features

* **extensions:** add publisher listing for command.routed ([#3722](https://github.com/hashgraph-online/hol-guard/issues/3722)) ([8d66089](https://github.com/hashgraph-online/hol-guard/commit/8d66089668cfe911c8c87591532894e4628fd145))


### Bug Fixes

* **guard:** keep the Windows policy-integrity key in the local vault ([#3717](https://github.com/hashgraph-online/hol-guard/issues/3717)) ([f7e1dcb](https://github.com/hashgraph-online/hol-guard/commit/f7e1dcb31d1bf686bb1c2a4d0586a04db3f1d75f))


### Performance Improvements

* **packaging:** shrink native wheels and enforce package size budgets ([6b450a2](https://github.com/hashgraph-online/hol-guard/commit/6b450a2a93a880fb77e293fc42c27bd37b421614))

## [3.30.0](https://github.com/hashgraph-online/hol-guard/compare/v3.29.0...v3.30.0) (2026-10-07)


### Features

* **contributions:** add lattice-talk MCP server (external opt-in) ([#3049](https://github.com/hashgraph-online/hol-guard/issues/3049)) ([720adae](https://github.com/hashgraph-online/hol-guard/commit/720adaecaf979d4b5694cd24a080bb87cddd3b16))
* **extensions:** add AgentHub MCP server contribution ([#3455](https://github.com/hashgraph-online/hol-guard/issues/3455)) ([d2748c0](https://github.com/hashgraph-online/hol-guard/commit/d2748c0d7c570359d08947754679408de336705e))
* **extensions:** add ClipUGC MCP server contribution ([#3287](https://github.com/hashgraph-online/hol-guard/issues/3287)) ([314b1b5](https://github.com/hashgraph-online/hol-guard/commit/314b1b577ff1f8c8b31fffe16a7fbdac43cab57d))
* **extensions:** add enola MCP server contribution ([#3210](https://github.com/hashgraph-online/hol-guard/issues/3210)) ([1f608ca](https://github.com/hashgraph-online/hol-guard/commit/1f608ca5214ca4781119b14d9de6b645a43f71fc))
* **extensions:** add Home Assistant MCP (Vome) server contribution ([#3420](https://github.com/hashgraph-online/hol-guard/issues/3420)) ([1be8696](https://github.com/hashgraph-online/hol-guard/commit/1be869648c1494f57ecc7f8f0accb4b65e087dcf))
* **extensions:** add opt-in Salesforce sf data command rules ([#3706](https://github.com/hashgraph-online/hol-guard/issues/3706)) ([8d3a88a](https://github.com/hashgraph-online/hol-guard/commit/8d3a88a8d55d91e02fc53eee146453e32c4483b6))
* **extensions:** add publisher listing for mcp.authyouragent ([#3707](https://github.com/hashgraph-online/hol-guard/issues/3707)) ([3fed4a6](https://github.com/hashgraph-online/hol-guard/commit/3fed4a6de83766ead611477b86815bce536d4f3e))
* **extensions:** add Theourgia command protection extension ([#3320](https://github.com/hashgraph-online/hol-guard/issues/3320)) ([980c427](https://github.com/hashgraph-online/hol-guard/commit/980c42751d34296681fb0768e192d9b6b359e247))
* **extensions:** add Xahau MCP and Evernode MCP server contributions ([#3310](https://github.com/hashgraph-online/hol-guard/issues/3310)) ([099cfa7](https://github.com/hashgraph-online/hol-guard/commit/099cfa7b730af6cd02006189cf37fad667430654))
* **extensions:** add XRPL Muse Skill command source ([#3482](https://github.com/hashgraph-online/hol-guard/issues/3482)) ([1d569c9](https://github.com/hashgraph-online/hol-guard/commit/1d569c93a52497635dce82dfeca1d650f39c885a))
* **extensions:** review Kranz CLI mutations ([#3188](https://github.com/hashgraph-online/hol-guard/issues/3188)) ([1c8a492](https://github.com/hashgraph-online/hol-guard/commit/1c8a49214d965d3e666e9fcf28fe1fef94a94418))
* **gauntlet:** pin a reasoning effort for live inference ([#3687](https://github.com/hashgraph-online/hol-guard/issues/3687)) ([1f05f1b](https://github.com/hashgraph-online/hol-guard/commit/1f05f1b5007d674da1fe774039ebe1a0562a6040))
* **guard:** add kim command safety extension ([#2895](https://github.com/hashgraph-online/hol-guard/issues/2895)) ([e7b754c](https://github.com/hashgraph-online/hol-guard/commit/e7b754c5d4b2f7d927312eccb9a712ecfc09118e))
* **guard:** add Routed command safety extension ([#3084](https://github.com/hashgraph-online/hol-guard/issues/3084)) ([8d06d15](https://github.com/hashgraph-online/hol-guard/commit/8d06d1554d73a73601eff3c920941af6f644df93))
* **guard:** add tether memory MCP server contribution ([#2843](https://github.com/hashgraph-online/hol-guard/issues/2843)) ([af9ba3b](https://github.com/hashgraph-online/hol-guard/commit/af9ba3bf6f244d2f80326baeaf23c9b085f5a0dc))
* **guard:** implement command.repopy safety extension ([#2988](https://github.com/hashgraph-online/hol-guard/issues/2988)) ([6ab3a9c](https://github.com/hashgraph-online/hol-guard/commit/6ab3a9c78cc499eee6877cdb63bad99068510743))
* **identity:** retain and revoke registered Google accounts ([d67319e](https://github.com/hashgraph-online/hol-guard/commit/d67319e4c55beda724eabf4089410ba2a929bc0a))
* **mcp:** add MusicContext MCP server contribution ([#3683](https://github.com/hashgraph-online/hol-guard/issues/3683)) ([a160cf2](https://github.com/hashgraph-online/hol-guard/commit/a160cf26315d7e4044e7c0063911c6a2f8fa412c))
* **runtime:** retain cumulative business budgets in native policy ([f41963d](https://github.com/hashgraph-online/hol-guard/commit/f41963d73a3362078406da677286b429b9963901))


### Bug Fixes

* **artifacts:** publish snapshots using returned release IDs ([#3715](https://github.com/hashgraph-online/hol-guard/issues/3715)) ([635c949](https://github.com/hashgraph-online/hol-guard/commit/635c94973161b9cafd8341c442c845e13305cdc7))
* **ci:** generate extension artifacts from current sources ([639eb51](https://github.com/hashgraph-online/hol-guard/commit/639eb511df5a0b521d2f99a7109638dc4c7a0044))
* **extensions:** convert AgentBridge to a command source and stage missing trust bindings ([#3709](https://github.com/hashgraph-online/hol-guard/issues/3709)) ([51a80bc](https://github.com/hashgraph-online/hol-guard/commit/51a80bc34eba9f9a220b2b60df70a8fabe0fcd43))
* **extensions:** generate the shared trust map from reviewed bindings ([fe92b6a](https://github.com/hashgraph-online/hol-guard/commit/fe92b6a4f72d70515802cf9294ec74ec31c52115))
* **extensions:** omit ambiguous operation examples ([#3708](https://github.com/hashgraph-online/hol-guard/issues/3708)) ([74487b9](https://github.com/hashgraph-online/hol-guard/commit/74487b93b8dbeccdd378d3f70f6b510ba95720e0))
* **extensions:** publish generated artifacts after merge ([#3695](https://github.com/hashgraph-online/hol-guard/issues/3695)) ([4cbc714](https://github.com/hashgraph-online/hol-guard/commit/4cbc714b6ad6153c55d53f6a71f0a36357455307))
* **extensions:** publish snapshots when draft tags do not exist yet ([dccfce7](https://github.com/hashgraph-online/hol-guard/commit/dccfce76b71ae464fd1d1449dd4a74a972fc54c9))
* **extensions:** send claim notices for source-only command contributions ([#3703](https://github.com/hashgraph-online/hol-guard/issues/3703)) ([43b5b69](https://github.com/hashgraph-online/hol-guard/commit/43b5b693b18c62172547ee00c2eaa0f66eefb4b6))
* **gauntlet:** accept inert bash defaults in Watch fixtures ([#3711](https://github.com/hashgraph-online/hol-guard/issues/3711)) ([bd98880](https://github.com/hashgraph-online/hol-guard/commit/bd988807388a6ae33dd166dde1e2cbde3075573d))
* **gauntlet:** require fixture output and metadata proofs for tool coverage cases ([3a9450d](https://github.com/hashgraph-online/hol-guard/commit/3a9450d44e99402de1c033f8bffdd84bc85818bc))
* **grok:** remove orphaned Guard hooks during repair ([#3704](https://github.com/hashgraph-online/hol-guard/issues/3704)) ([688a1cb](https://github.com/hashgraph-online/hol-guard/commit/688a1cb1f66cc589dba6b579c902da653cd37ceb))
* **omp:** recover readiness after daemon replacement ([#3688](https://github.com/hashgraph-online/hol-guard/issues/3688)) ([fece86d](https://github.com/hashgraph-online/hol-guard/commit/fece86d699bcca986871640b7f3dbc5b0a5275ca))
* **release:** retry temporarily absent registry metadata ([bd161de](https://github.com/hashgraph-online/hol-guard/commit/bd161def907c6d08ee8d1483b4d81919619341b0))

## [3.29.0](https://github.com/hashgraph-online/hol-guard/compare/v3.28.0...v3.29.0) (2026-10-07)


### Features

* **extensions:** add answerLoops command protection extension ([#3478](https://github.com/hashgraph-online/hol-guard/issues/3478)) ([06af212](https://github.com/hashgraph-online/hol-guard/commit/06af21296255accdbf9cd7256b610acf0150a688))
* **guard:** prepare verified Google send requests for native review ([#3562](https://github.com/hashgraph-online/hol-guard/issues/3562)) ([c25b6dd](https://github.com/hashgraph-online/hol-guard/commit/c25b6dd4f206dedfa482e48aa6a696c869397fdd))


### Bug Fixes

* **ci:** sync native approval error allowlists ([924bfea](https://github.com/hashgraph-online/hol-guard/commit/924bfea7df0904aefa57e460bddbe9a6aadc9b13))
* **extensions:** stage answerloops external trust binding ([#3681](https://github.com/hashgraph-online/hol-guard/issues/3681)) ([442d364](https://github.com/hashgraph-online/hol-guard/commit/442d36498e70285859263ff6f9548c69899e5de8))
* **guard:** redact cargo local paths in resident package intents ([#3682](https://github.com/hashgraph-online/hol-guard/issues/3682)) ([36358e4](https://github.com/hashgraph-online/hol-guard/commit/36358e42455bb5ff0ac19bc105cc56a3d0579772))

## [3.28.0](https://github.com/hashgraph-online/hol-guard/compare/v3.27.1...v3.28.0) (2026-10-07)


### Features

* **guard:** install and recover native business policy documents ([48e0df3](https://github.com/hashgraph-online/hol-guard/commit/48e0df3504ab6f9ad1615837f9ff0417edf50a16))


### Bug Fixes

* **ci:** run continuation timing in its required isolated lane ([384e8dd](https://github.com/hashgraph-online/hol-guard/commit/384e8dd7df1ecc79806c2f01de6f6917e475ebcd))
* **claude:** guard Grep searches and defer permission dialogs ([48ed9a6](https://github.com/hashgraph-online/hol-guard/commit/48ed9a63d17f9ef715447e848e125ec8d8944ebb))
* **dashboard:** rank pattern search by match strength and risk severity ([#3671](https://github.com/hashgraph-online/hol-guard/issues/3671)) ([7ac9f7c](https://github.com/hashgraph-online/hol-guard/commit/7ac9f7ced50496fea40d0265a5af6b65d41dbddc))
* **guard:** exercise signed Desktop proxy during runtime qualification ([#3676](https://github.com/hashgraph-online/hol-guard/issues/3676)) ([0a27f80](https://github.com/hashgraph-online/hol-guard/commit/0a27f80067ce55705ba7ea17ce64026df05bfd58))
* **hooks:** review literal shell scripts and retain terminal native denies ([#3669](https://github.com/hashgraph-online/hol-guard/issues/3669)) ([d2af463](https://github.com/hashgraph-online/hol-guard/commit/d2af463d5d5d588693ab9f0099ee2a50a014522c))
* **updates:** detect promoted Desktop Core bundles ([#3670](https://github.com/hashgraph-online/hol-guard/issues/3670)) ([eb7d9e1](https://github.com/hashgraph-online/hol-guard/commit/eb7d9e186f4d6e2f39a170643bebaabac9f91a09))


### Performance Improvements

* **ci:** restore fast pull request critical path ([#3651](https://github.com/hashgraph-online/hol-guard/issues/3651)) ([b53ac1d](https://github.com/hashgraph-online/hol-guard/commit/b53ac1da1c360ef38d665da245f40cf990c997cf))

## [3.27.1](https://github.com/hashgraph-online/hol-guard/compare/v3.27.0...v3.27.1) (2026-10-06)


### Bug Fixes

* **omp:** resume cold prompts and ship the current Protection Center ([#3633](https://github.com/hashgraph-online/hol-guard/issues/3633)) ([111218d](https://github.com/hashgraph-online/hol-guard/commit/111218db99545f1a1f4968e7ce64ac49be129460))

## [3.27.0](https://github.com/hashgraph-online/hol-guard/compare/v3.26.0...v3.27.0) (2026-10-06)


### Features

* **ci:** add trusted change planner and shadow required aggregate ([#3610](https://github.com/hashgraph-online/hol-guard/issues/3610)) ([a200dfe](https://github.com/hashgraph-online/hol-guard/commit/a200dfef03627ea721d3f7de1968bb453f8cfdbe))
* **extensions:** add command protection for blkcp ([#3062](https://github.com/hashgraph-online/hol-guard/issues/3062)) ([82ad7e7](https://github.com/hashgraph-online/hol-guard/commit/82ad7e783ef50f274ca897d31273268ba451f2e3))
* **guard:** RTM-023 — native MCP child-I/O ownership + tools/list catalog boundary ([#3613](https://github.com/hashgraph-online/hol-guard/issues/3613)) ([e90c7af](https://github.com/hashgraph-online/hol-guard/commit/e90c7afd6df9a743d17cff4880f4ccf7116ef4e1))
* **guard:** RTM-030 — resident apply_stored_package_policy op ([#3653](https://github.com/hashgraph-online/hol-guard/issues/3653)) ([14bb586](https://github.com/hashgraph-online/hol-guard/commit/14bb58629a7c96e708900cdba7ab499650347ad3))
* **guard:** RTM-030a — resident guard-sync transport (OAuth read, DPoP, ureq HTTPS) ([#3634](https://github.com/hashgraph-online/hol-guard/issues/3634)) ([c5f9fc2](https://github.com/hashgraph-online/hol-guard/commit/c5f9fc2ed3e0c8ea86fc10ad3013da6073ec0864))
* **guard:** RTM-030b-1 — resident OAuth credential authority (scoped secret resolution + fingerprint parity) ([#3645](https://github.com/hashgraph-online/hol-guard/issues/3645)) ([59c5522](https://github.com/hashgraph-online/hol-guard/commit/59c5522707358bd2d3007b694832adad6954b8e0))
* **mcp:** add external AsDecided server contribution ([#3579](https://github.com/hashgraph-online/hol-guard/issues/3579)) ([55b126e](https://github.com/hashgraph-online/hol-guard/commit/55b126e595bd8d5eb813266b75ebad64625352b0))
* **mcp:** own persistent MCP child lifecycle in the native runtime ([#3564](https://github.com/hashgraph-online/hol-guard/issues/3564)) ([66eef10](https://github.com/hashgraph-online/hol-guard/commit/66eef10214353cee32e872b176c39abb4d592449))


### Bug Fixes

* **approval:** restore disabled gate setup and accurate review labels ([#3621](https://github.com/hashgraph-online/hol-guard/issues/3621)) ([24032f8](https://github.com/hashgraph-online/hol-guard/commit/24032f8b4f2b94c0073d83a3f6768591ac6d2096))
* **ci:** allow skipped change planner in required aggregate on push ([#3628](https://github.com/hashgraph-online/hol-guard/issues/3628)) ([98cd7b3](https://github.com/hashgraph-online/hol-guard/commit/98cd7b3bb9cfb13c5e9754bcdb89aa84da9f3d9f))
* **ci:** repair product regressions breaking main test suite ([#3641](https://github.com/hashgraph-online/hol-guard/issues/3641)) ([5895c06](https://github.com/hashgraph-online/hol-guard/commit/5895c0612e0b29b4597df6a11f48163ee87d0356))
* **ci:** treat skipped change planner as expected on push runs ([#3625](https://github.com/hashgraph-online/hol-guard/issues/3625)) ([ce487e5](https://github.com/hashgraph-online/hol-guard/commit/ce487e5238732e26d1fe85adde97edcc8716339c))
* **guard:** empty availability response is not a deny + cover exit-code mapper ([#3654](https://github.com/hashgraph-online/hol-guard/issues/3654)) ([e2cf4e2](https://github.com/hashgraph-online/hol-guard/commit/e2cf4e2fc0b1598782e7d5a569cb89b9cfcd4b9e))
* **guard:** fail closed for Hermes pre-tool worker errors ([#3661](https://github.com/hashgraph-online/hol-guard/issues/3661)) ([06493b6](https://github.com/hashgraph-online/hol-guard/commit/06493b6e3280849dd17f401eeebe372a9af98f03))
* **guard:** fail-closed rc when native hook authority unavailable + relax archive timing flake ([#3647](https://github.com/hashgraph-online/hol-guard/issues/3647)) ([2755b3c](https://github.com/hashgraph-online/hol-guard/commit/2755b3cd3cd372ec8a08a962de2cc4213d73d49a))
* **omp:** prepare Guard protection before reviewing prompts ([ab20104](https://github.com/hashgraph-online/hol-guard/commit/ab20104e095c2ff9e20ba1abdc982640dc4b2c3a))
* **zcode:** install hooks on both ZCode config surfaces ([#3605](https://github.com/hashgraph-online/hol-guard/issues/3605)) ([aac53a8](https://github.com/hashgraph-online/hol-guard/commit/aac53a8989e33a6405d174b80206231826554fa4))

## [3.25.2](https://github.com/hashgraph-online/hol-guard/compare/v3.25.1...v3.25.2) (2026-10-05)


### Bug Fixes

* **ci:** raise native source envelope budget to 8 MiB ([#3583](https://github.com/hashgraph-online/hol-guard/issues/3583)) ([7a175a9](https://github.com/hashgraph-online/hol-guard/commit/7a175a9b33d3c219b9a8bfc165d2409e72fc4525))
* **ci:** repair portable regressions and stale acceptance gates ([#3568](https://github.com/hashgraph-online/hol-guard/issues/3568)) ([bc11643](https://github.com/hashgraph-online/hol-guard/commit/bc1164301cf5b85e6b1927e9a05c27c2968381d0))
* **native:** stop hard-blocking commands Guard cannot fully attribute ([6d09164](https://github.com/hashgraph-online/hol-guard/commit/6d091642f4d428631c1901ac7016543ffe341086))

## [3.25.1](https://github.com/hashgraph-online/hol-guard/compare/v3.25.0...v3.25.1) (2026-10-05)


### Bug Fixes

* **updates:** discover stable Core releases across minor versions ([4445c90](https://github.com/hashgraph-online/hol-guard/commit/4445c906db6e1aa99a3a2d68f307dce36f34a140))

## [3.25.0](https://github.com/hashgraph-online/hol-guard/compare/v3.24.2...v3.25.0) (2026-10-05)


### Features

* **extensions:** add faf-cli command source ([#3397](https://github.com/hashgraph-online/hol-guard/issues/3397)) ([2c80356](https://github.com/hashgraph-online/hol-guard/commit/2c80356b91a2524424ef933cf285e010542aa22e))


### Bug Fixes

* **gauntlet:** attempt both cleanup steps and retain private diagnostics ([5bcdd20](https://github.com/hashgraph-online/hol-guard/commit/5bcdd201cd1b4c353cc62a498a239e8d50c73eaa))
* **grok:** keep protection settings across vendor configuration refreshes ([1aa2864](https://github.com/hashgraph-online/hol-guard/commit/1aa2864566ba9dc9a9b477e9a32a0012cd2becee))
* **guard:** record silent blocked reviews in the inbox ([7387edc](https://github.com/hashgraph-online/hol-guard/commit/7387edc4eed5e7f03b1cc046eb917521e990941e))
* **hooks:** retry transient native control admission within hook deadlines ([8d0e0dd](https://github.com/hashgraph-online/hol-guard/commit/8d0e0dd491f2f37d69fc6607d3a838738e5f562e))
## [3.24.2](https://github.com/hashgraph-online/hol-guard/compare/v3.24.1...v3.24.2) (2026-10-04)


### Bug Fixes

* **scanner:** add bounded context checks and a contributor review pathway ([#3553](https://github.com/hashgraph-online/hol-guard/issues/3553)) ([6eb834e](https://github.com/hashgraph-online/hol-guard/commit/6eb834e4f45617cddd7cae7f9db1c1e055dc440f))

## [3.24.1](https://github.com/hashgraph-online/hol-guard/compare/v3.24.0...v3.24.1) (2026-10-04)


### Bug Fixes

* **guard:** preserve native hook readiness during ordinary traffic ([f92aeef](https://github.com/hashgraph-online/hol-guard/commit/f92aeef96a212e1697d44f160565f161cf757ca5))
* **zcode:** validate saved hook preferences on reinstall ([757bdf3](https://github.com/hashgraph-online/hol-guard/commit/757bdf345b04882b381e8bde2c56188188aa4f4b))

## [3.24.0](https://github.com/hashgraph-online/hol-guard/compare/v3.23.1...v3.24.0) (2026-10-04)


### Features

* **command:** add cs (Claude Sessions) command extension ([#3511](https://github.com/hashgraph-online/hol-guard/issues/3511)) ([ecdfab1](https://github.com/hashgraph-online/hol-guard/commit/ecdfab1aebb69f382f605aefb35cc588330bf3fa))
* **guard:** add VTTForge command-safety extension ([#2876](https://github.com/hashgraph-online/hol-guard/issues/2876)) ([1e6bff8](https://github.com/hashgraph-online/hol-guard/commit/1e6bff8a553615f4a1327d85c471d90917cebe06))
* **policy:** bind native business rules to authenticated snapshots ([a4af3bd](https://github.com/hashgraph-online/hol-guard/commit/a4af3bdb8b89fa0797fa480c7699408b650667fa))
* **review:** bind private business input to native snapshots ([01ecf80](https://github.com/hashgraph-online/hol-guard/commit/01ecf808fc4c36bc306a8814ab9153b8ee13448b))


### Bug Fixes

* **ci:** initialize native proofs before concurrent warm-up ([#3538](https://github.com/hashgraph-online/hol-guard/issues/3538)) ([9283b85](https://github.com/hashgraph-online/hol-guard/commit/9283b853e0f6148bfd3aa3ae7f58eaac0484998d))
* **ci:** keep PR quality strict and move extended soaks off the critical path ([#3532](https://github.com/hashgraph-online/hol-guard/issues/3532)) ([71a4d31](https://github.com/hashgraph-online/hol-guard/commit/71a4d31857216e9796821ceb2f4723078b12e4e5))
* **policy:** require review for writes through hard-linked files ([fc16f1d](https://github.com/hashgraph-online/hol-guard/commit/fc16f1d8bd0579443c5ce979dbadfcc111de19ed))
* **zcode:** install hooks into current CLI settings ([708b323](https://github.com/hashgraph-online/hol-guard/commit/708b32307c4f75e1b121045d2718564b0ab70911))

## [3.23.1](https://github.com/hashgraph-online/hol-guard/compare/v3.23.0...v3.23.1) (2026-10-04)


### Bug Fixes

* **runtime:** align verified-home copies and resolved read evidence ([#3534](https://github.com/hashgraph-online/hol-guard/issues/3534)) ([7399202](https://github.com/hashgraph-online/hol-guard/commit/7399202ef348a022faa364d648f9a2bc95a95a87))

## [3.23.0](https://github.com/hashgraph-online/hol-guard/compare/v3.22.0...v3.23.0) (2026-10-04)


### Features

* **native:** prove bounded git worktree creation ([#3502](https://github.com/hashgraph-online/hol-guard/issues/3502)) ([7e5da94](https://github.com/hashgraph-online/hol-guard/commit/7e5da94c9c72e4bf6ac1d9b5843e5fda509dbc66))


### Bug Fixes

* **ci:** parallelize required Rust checks and correct PR fixture attribution ([#3524](https://github.com/hashgraph-online/hol-guard/issues/3524)) ([846fe97](https://github.com/hashgraph-online/hol-guard/commit/846fe97cb2445bbf6e73a05d6c540e8470fc6904))
* **gauntlet:** preserve owned cleanup proof after timeout ([#3526](https://github.com/hashgraph-online/hol-guard/issues/3526)) ([5ba252e](https://github.com/hashgraph-online/hol-guard/commit/5ba252eaea5cb1b7814beee90059beccecbc150d))
* **native:** allow bounded directory reads in agent workflows ([9dc21be](https://github.com/hashgraph-online/hol-guard/commit/9dc21be38d4266faf197a474e0f9f5dc50e1577f))

## [3.22.0](https://github.com/hashgraph-online/hol-guard/compare/v3.21.1...v3.22.0) (2026-10-04)


### Features

* **command:** decode bounded Gmail plain-text transfer bodies ([78aa871](https://github.com/hashgraph-online/hol-guard/commit/78aa8717f03c28ffb4bd785ede935296ebc8ce2e))
* **command:** decode bounded Gmail send wire input ([9084d77](https://github.com/hashgraph-online/hol-guard/commit/9084d774d0526f18498a047dc1b8988368a65428))
* **command:** extract private bounded plain Gmail inputs ([f920d9c](https://github.com/hashgraph-online/hol-guard/commit/f920d9c4388d2ab9aad39693e87c9a747628bd18))
* **command:** prepare pinned gws Gmail sends through native parser ([b082d0f](https://github.com/hashgraph-online/hol-guard/commit/b082d0f15582545622031e298d89fbb1ba399f74))
* **extensions:** add snoboard command source ([#3468](https://github.com/hashgraph-online/hol-guard/issues/3468)) ([356f15f](https://github.com/hashgraph-online/hol-guard/commit/356f15f7372d34aafdd33c5a92013fd7874f843f))


### Bug Fixes

* **ci:** format required-nullable Rust contract validation ([#3520](https://github.com/hashgraph-online/hol-guard/issues/3520)) ([72ee89a](https://github.com/hashgraph-online/hol-guard/commit/72ee89a2c455c29a7f3e01b8e08a5c4dd7087fdb))
* **ci:** prepare source-only extensions without main-sync churn ([#3517](https://github.com/hashgraph-online/hol-guard/issues/3517)) ([888316f](https://github.com/hashgraph-online/hol-guard/commit/888316f57ba1dbbd4d064852f2c2ff0ed2da9e28))
* **ci:** preserve strict identity decoding in Sonar analysis ([#3515](https://github.com/hashgraph-online/hol-guard/issues/3515)) ([d2db0e9](https://github.com/hashgraph-online/hol-guard/commit/d2db0e9d3fdc1661f3f524542b05b49a75d2a7b7))
* **dashboard:** preserve keyboard cancellation in approval dialogs ([bbad78a](https://github.com/hashgraph-online/hol-guard/commit/bbad78a40cafc40c052f881feb8cfe8f662565e1))
* **grok:** preserve prompt blocks when review is unavailable ([#3519](https://github.com/hashgraph-online/hol-guard/issues/3519)) ([078ece1](https://github.com/hashgraph-online/hol-guard/commit/078ece1c24f2dc7bf99ad51a7ca82a07dabf031c))
* **pi:** retry workspace readiness after daemon recovery ([06fea1c](https://github.com/hashgraph-online/hol-guard/commit/06fea1c0878cd45982d3aa71502fb9ac6a86c8bf))
* **runtime:** allow read-only documents in supported skill roots ([#3522](https://github.com/hashgraph-online/hol-guard/issues/3522)) ([9ba2a9e](https://github.com/hashgraph-online/hol-guard/commit/9ba2a9e20c8a9fc9d59991aeb9d817a32f060a65))
* **runtime:** contain inline Python with isolation flags ([1fb6aff](https://github.com/hashgraph-online/hol-guard/commit/1fb6aff0c268577189ee6ad94c7c68cb28ab7c58))

## [3.21.1](https://github.com/hashgraph-online/hol-guard/compare/v3.21.0...v3.21.1) (2026-10-04)


### Bug Fixes

* **pi:** recover stale daemon identity ([#3500](https://github.com/hashgraph-online/hol-guard/issues/3500)) ([3ca85b2](https://github.com/hashgraph-online/hol-guard/commit/3ca85b240b1e9c71f5263aec95e6c07738b96f02))

## [3.21.0](https://github.com/hashgraph-online/hol-guard/compare/v3.20.2...v3.21.0) (2026-10-04)


### Features

* **command:** freeze prepared business input bytes ([c6b5749](https://github.com/hashgraph-online/hol-guard/commit/c6b57497de34565a5318ae153eb7f1251bb9b6a2))
* **contracts:** define bounded business action facts ([7306881](https://github.com/hashgraph-online/hol-guard/commit/73068818f352de9d7ebf85a177434fce0322b9b2))
* **policy:** add bounded business selector predicates ([b09ff5a](https://github.com/hashgraph-online/hol-guard/commit/b09ff5a4988644c689519a181358c2f7134dee74))


### Bug Fixes

* **dashboard:** move the connector search out of the section header ([#3488](https://github.com/hashgraph-online/hol-guard/issues/3488)) ([69accc5](https://github.com/hashgraph-online/hol-guard/commit/69accc5babed58104c9e0c0f26f0dc62db224c4c))
* **desktop:** regenerate native projections before feed packaging ([#3494](https://github.com/hashgraph-online/hol-guard/issues/3494)) ([5a1f99e](https://github.com/hashgraph-online/hol-guard/commit/5a1f99e20b14ec15f3f517df8ad8acbdafeaf979))


### Performance Improvements

* **runtime:** reuse the store connection for verified control projections ([cdd69ea](https://github.com/hashgraph-online/hol-guard/commit/cdd69eaa9af0b5652172c8121d9d68a0279fd1fa))

## [3.20.2](https://github.com/hashgraph-online/hol-guard/compare/v3.20.1...v3.20.2) (2026-10-04)


### Bug Fixes

* **hooks:** avoid Grok startup delays and report Gauntlet tail latency ([#3487](https://github.com/hashgraph-online/hol-guard/issues/3487)) ([bf67da1](https://github.com/hashgraph-online/hol-guard/commit/bf67da1cdbb98362baf2d175d57effbd5f4753e2))
* **runtime:** read the runtime snapshot through one store connection ([c42bae7](https://github.com/hashgraph-online/hol-guard/commit/c42bae78771c2777bf45ed517f3c173dbd1e8844))

## [3.20.1](https://github.com/hashgraph-online/hol-guard/compare/v3.20.0...v3.20.1) (2026-10-04)


### Bug Fixes

* **ci:** make Guard Gauntlet qualification optional ([#3481](https://github.com/hashgraph-online/hol-guard/issues/3481)) ([2c8ca84](https://github.com/hashgraph-online/hol-guard/commit/2c8ca84b4a3258d93da13b4d1e34adb1dbc5f190))
* **gauntlet:** route live inference and stop interrupted agents ([b6bc490](https://github.com/hashgraph-online/hol-guard/commit/b6bc4909dbef8583ad436394bb1088c7fddfe8d5))
* **release:** make deferred PyPI publication resumable ([7e01720](https://github.com/hashgraph-online/hol-guard/commit/7e017209c63040156bdbb56b6a70cb6accd9c3e7))
* **release:** use current tooling for deferred notes ([52cfe6e](https://github.com/hashgraph-online/hol-guard/commit/52cfe6eae4fd92972cfe0668fcf89c196ec12c52))


### Performance Improvements

* **packaging:** shrink source archives and native wheels ([d61a7fe](https://github.com/hashgraph-online/hol-guard/commit/d61a7fefe4f0fc1637a2189dbc75a27c9072828a))

## [3.20.0](https://github.com/hashgraph-online/hol-guard/compare/v3.19.0...v3.20.0) (2026-10-04)


### Features

* **gauntlet:** qualify Guard with real agents and observed outcomes ([#3463](https://github.com/hashgraph-online/hol-guard/issues/3463)) ([8ace3b7](https://github.com/hashgraph-online/hol-guard/commit/8ace3b7cc2b5317f9c056517e4c197d36afbcb69))


### Bug Fixes

* **extensions:** generate command projections during package builds ([#3479](https://github.com/hashgraph-online/hol-guard/issues/3479)) ([d6649a3](https://github.com/hashgraph-online/hol-guard/commit/d6649a31c53e1d68f45904ebd7f0a15e950d4bbf))
* **mcp:** use valid package-launcher syntax in catalog examples ([513504a](https://github.com/hashgraph-online/hol-guard/commit/513504aab762567269a1994020c44bca0db70c5c))
* **runtime:** allow bounded agent workflows and contained test workers ([ca97e85](https://github.com/hashgraph-online/hol-guard/commit/ca97e85322894da6957d61a1de1f851f2c48bad0))

## [3.19.0](https://github.com/hashgraph-online/hol-guard/compare/v3.18.2...v3.19.0) (2026-10-03)


### Features

* **mcp:** add ContribOS MCP server contribution ([#3472](https://github.com/hashgraph-online/hol-guard/issues/3472)) ([e10177b](https://github.com/hashgraph-online/hol-guard/commit/e10177b7fc2533cf150327eeb893882a5f6392f4))


### Bug Fixes

* **guard:** classify auth context and batch Git filter proofs ([#3471](https://github.com/hashgraph-online/hol-guard/issues/3471)) ([7a63cf2](https://github.com/hashgraph-online/hol-guard/commit/7a63cf2a3068b52b6d869e90573d4e8aa2f688dd))
* prove exact recursive grep exclusions safely ([#3467](https://github.com/hashgraph-online/hol-guard/issues/3467)) ([536aa27](https://github.com/hashgraph-online/hol-guard/commit/536aa27b678c2c0b33bf55e7ced0d874329529e5))

## [3.18.2](https://github.com/hashgraph-online/hol-guard/compare/v3.18.1...v3.18.2) (2026-10-03)


### Bug Fixes

* **ci:** make partial reruns reuse verified successful coverage ([#3454](https://github.com/hashgraph-online/hol-guard/issues/3454)) ([797c3f3](https://github.com/hashgraph-online/hol-guard/commit/797c3f3cec45c8e201a711c9cb58c27fa1a14104))
* **ci:** skip Gitar jobs for closed pull requests ([9260647](https://github.com/hashgraph-online/hol-guard/commit/9260647758487a12381fbec31d53b65dd8106340))
* preserve safe stderr-sink workflows and qualify native readiness ([#3462](https://github.com/hashgraph-online/hol-guard/issues/3462)) ([1592681](https://github.com/hashgraph-online/hol-guard/commit/1592681038145546cb3d709129f282e36a3c3f2c))
* **skills:** keep negative fixture out of skill discovery ([#3460](https://github.com/hashgraph-online/hol-guard/issues/3460)) ([0a95303](https://github.com/hashgraph-online/hol-guard/commit/0a95303c35103a36441b9fd72491f163a0dba962))


### Performance Improvements

* **ci:** remove repeated ownership analysis without caching stale verdicts ([#3456](https://github.com/hashgraph-online/hol-guard/issues/3456)) ([946ca9e](https://github.com/hashgraph-online/hol-guard/commit/946ca9efc178c33a33d969e8129e1ee7f855cf79))

## [3.18.1](https://github.com/hashgraph-online/hol-guard/compare/v3.18.0...v3.18.1) (2026-10-03)


### Bug Fixes

* **ci:** preserve actionable causes of native capacity failures ([#3453](https://github.com/hashgraph-online/hol-guard/issues/3453)) ([ab2abaa](https://github.com/hashgraph-online/hol-guard/commit/ab2abaab062236c7500a2786bf7c25240df7276d))
* **ci:** stop migration churn and reject broken contracts before fan-out ([#3450](https://github.com/hashgraph-online/hol-guard/issues/3450)) ([39b3a1b](https://github.com/hashgraph-online/hol-guard/commit/39b3a1bdb6128351a3160424b28578e7da9a35aa))
* **commands:** compose safe segments with extension approvals ([#3434](https://github.com/hashgraph-online/hol-guard/issues/3434)) ([ae4f747](https://github.com/hashgraph-online/hol-guard/commit/ae4f7470d09c948d1b7944542d352e0225b9a4e8))
* compose routine commands and native home file writes safely ([#3437](https://github.com/hashgraph-online/hol-guard/issues/3437)) ([2874d88](https://github.com/hashgraph-online/hol-guard/commit/2874d886c1f398d6e7058b692bd863e6f7619ada))
* **runtime:** quiesce native residents during package updates ([#3438](https://github.com/hashgraph-online/hol-guard/issues/3438)) ([27faf19](https://github.com/hashgraph-online/hol-guard/commit/27faf19ff2d906f8076a6277948549c8e8fcd9a4))
* **tests:** defer extension-directory render check in PR context ([#3382](https://github.com/hashgraph-online/hol-guard/issues/3382)) ([155f175](https://github.com/hashgraph-online/hol-guard/commit/155f175fa0cf67b2441c0e3d6bd2a4be5162eadf))

## [3.18.0](https://github.com/hashgraph-online/hol-guard/compare/v3.17.1...v3.18.0) (2026-10-03)


### Features

* **guard:** add Syngraphe command extension ([#2929](https://github.com/hashgraph-online/hol-guard/issues/2929)) ([77b9d11](https://github.com/hashgraph-online/hol-guard/commit/77b9d11a9d7b10d96f9efe2bf104fad5ea0cea1e))


### Bug Fixes

* **ci:** stop fixture rebuild churn while preserving contributor extensions ([#3425](https://github.com/hashgraph-online/hol-guard/issues/3425)) ([d756e57](https://github.com/hashgraph-online/hol-guard/commit/d756e57ce8aa7c1888805f2739ceffed5c4ded18))
* **extension-builder:** exempt regen/* PRs from carried-projection rejection ([#3421](https://github.com/hashgraph-online/hol-guard/issues/3421)) ([a9f9a88](https://github.com/hashgraph-online/hol-guard/commit/a9f9a882419e4124bc22124de38e95cef5f99a51))
* format resident lease receiver call ([7da89ac](https://github.com/hashgraph-online/hol-guard/commit/7da89ac3ecc039d08b310c3830c31a5a8a807773))
* **guard:** block review requests without prompting by default ([#3428](https://github.com/hashgraph-online/hol-guard/issues/3428)) ([8ee4111](https://github.com/hashgraph-online/hol-guard/commit/8ee4111d5f41787066675e64c8f43ed7b8abd12d))
* **mcp:** honor fresh one-shot approvals through launch revalidation ([9754d13](https://github.com/hashgraph-online/hol-guard/commit/9754d139f119549fc2ab7f673a1a8a18700613fb))
* restore native hook review across frozen launches and linked worktrees ([#3411](https://github.com/hashgraph-online/hol-guard/issues/3411)) ([7d0afe6](https://github.com/hashgraph-online/hol-guard/commit/7d0afe60689bf0dd17d37995a8e156274a339eec))
* restore routine file workflows and contained Bun Vitest execution ([#3427](https://github.com/hashgraph-online/hol-guard/issues/3427)) ([7c5bb38](https://github.com/hashgraph-online/hol-guard/commit/7c5bb389e1b1858d703de008afc7e7689033c45f))
* **runtime:** remove idle accept latency and stabilize deadline verification ([912251f](https://github.com/hashgraph-online/hol-guard/commit/912251f723e9f832df46a10c011f40a62967a85d))
* **runtime:** restore the previous runtime when a transition fails ([#3422](https://github.com/hashgraph-online/hol-guard/issues/3422)) ([0c31916](https://github.com/hashgraph-online/hol-guard/commit/0c319168b4bc11e2ce02ebf203f6f35d316ddec4))
* **runtime:** wake idle Unix accepts and verify absolute lease deadlines ([c00209c](https://github.com/hashgraph-online/hol-guard/commit/c00209c3607a0f54f3af98175de6f2456b4af388))

## [3.17.1](https://github.com/hashgraph-online/hol-guard/compare/v3.17.0...v3.17.1) (2026-10-02)


### Bug Fixes

* **ci:** rebuild release projections before packaging ([29091e5](https://github.com/hashgraph-online/hol-guard/commit/29091e5a9489610ffb93c62e1a7c6432763f25aa))
* **desktop:** freeze projections from the attested Core wheel ([d6a66e8](https://github.com/hashgraph-online/hol-guard/commit/d6a66e8cb22efd1e5caec45de03d613147fe6dc4))

## [3.17.0](https://github.com/hashgraph-online/hol-guard/compare/v3.16.5...v3.17.0) (2026-10-02)


### Features

* **guard:** add recovery step to native inspection unavailable result ([#3393](https://github.com/hashgraph-online/hol-guard/issues/3393)) ([4a835fd](https://github.com/hashgraph-online/hol-guard/commit/4a835fd444350f552f34c923038e15acb6eaf448))
* **guard:** verify delegated workspace review decisions ([#3120](https://github.com/hashgraph-online/hol-guard/issues/3120)) ([a288694](https://github.com/hashgraph-online/hol-guard/commit/a28869423243e17111036d2e3e978fc0cafb2b3e))
* **native:** own approval-context digests in the resident worker ([#3346](https://github.com/hashgraph-online/hol-guard/issues/3346)) ([73d1de1](https://github.com/hashgraph-online/hol-guard/commit/73d1de17580b4477ed67dbb54aa2e91159e7bd2c))


### Bug Fixes

* **daemon:** close publishers after early startup failure ([5bf2c11](https://github.com/hashgraph-online/hol-guard/commit/5bf2c119a51f7908b7709eaeaca99b8fb44f966e))
* **guard:** emit approval_requests on store-quarantined deny path ([#3390](https://github.com/hashgraph-online/hol-guard/issues/3390)) ([97c2c1e](https://github.com/hashgraph-online/hol-guard/commit/97c2c1e7d812698bd6ba282424c2b2b99472f4a4))
* **guard:** preserve Codex rollback state and harden MCPB verification ([#3380](https://github.com/hashgraph-online/hol-guard/issues/3380)) ([8b18ef9](https://github.com/hashgraph-online/hol-guard/commit/8b18ef95f813111956deec5c50f60f01ca41b32f))
* **guard:** preserve daemon-failure category through local-queue fallback ([#3394](https://github.com/hashgraph-online/hol-guard/issues/3394)) ([8588fbe](https://github.com/hashgraph-online/hol-guard/commit/8588fbede0317786baed5015bab2da2fe0ef65a1))
* **guard:** preserve transaction participants on rollback conflict ([#3387](https://github.com/hashgraph-online/hol-guard/issues/3387)) ([d6c31d9](https://github.com/hashgraph-online/hol-guard/commit/d6c31d9ad6d024fdc31ad4c56e80b8ec3746d5cd))
* **guard:** report snapshot substitution as config_invalid, not rollback_conflict ([#3385](https://github.com/hashgraph-online/hol-guard/issues/3385)) ([078a981](https://github.com/hashgraph-online/hol-guard/commit/078a9815552fc8f8481fe0ef1a294624edf742e5))
* **guard:** restore quiet routine workflows without weakening risk checks ([37bb699](https://github.com/hashgraph-online/hol-guard/commit/37bb699e42a72e75676b684593a100d1e16a648c))
* **runtime:** retain cancelled workers through containment failures ([0944ff3](https://github.com/hashgraph-online/hol-guard/commit/0944ff3f6c8835d3c867f27523970e6aaf2c47a7))
* **security:** pin node-forge to 1.3.1 for mcpb tooling ([c61e9fc](https://github.com/hashgraph-online/hol-guard/commit/c61e9fc951bd66fc56038eeb2f6b2a72f1e8d5ec))

## [3.16.5](https://github.com/hashgraph-online/hol-guard/compare/v3.16.4...v3.16.5) (2026-10-02)


### Bug Fixes

* **evaluation:** retain partial setup recovery state ([#3373](https://github.com/hashgraph-online/hol-guard/issues/3373)) ([d26b794](https://github.com/hashgraph-online/hol-guard/commit/d26b79441ca13adbc243251d29231c75cfc95c74))

## [3.16.4](https://github.com/hashgraph-online/hol-guard/compare/v3.16.3...v3.16.4) (2026-10-02)


### Bug Fixes

* **ci:** prevent evidence drift and daemon response races ([#3368](https://github.com/hashgraph-online/hol-guard/issues/3368)) ([cf6481b](https://github.com/hashgraph-online/hol-guard/commit/cf6481b3450572694040d84a52af67d9aca715fa))
* **mcp:** keep managed servers discoverable after updates ([d6e4fd9](https://github.com/hashgraph-online/hol-guard/commit/d6e4fd9043d37f7166b229b7b255fe7c049beb20))
* **native:** allow standalone plain directory changes ([e430915](https://github.com/hashgraph-online/hol-guard/commit/e43091501fa6e55e570fba85ee1935cb7703a554))
* **review:** recover collided snapshot sequences ([#3348](https://github.com/hashgraph-online/hol-guard/issues/3348)) ([e5f9503](https://github.com/hashgraph-online/hol-guard/commit/e5f9503def74e65a8f6f08b1f4281b734a6da667))

## [3.16.3](https://github.com/hashgraph-online/hol-guard/compare/v3.16.2...v3.16.3) (2026-10-02)


### Bug Fixes

* **benchmarks:** preserve failure and route evidence ([#3357](https://github.com/hashgraph-online/hol-guard/issues/3357)) ([b4a1cab](https://github.com/hashgraph-online/hol-guard/commit/b4a1cabc48c879c4447bab75ff8a9f3fa3214c6a))
* **codex:** serialize competing configuration lifecycle writers ([e529cd0](https://github.com/hashgraph-online/hol-guard/commit/e529cd06324f4690bcf754a59689f24201b01e6b))
* **runtime:** detect closed supervisor pipes before serving requests ([#3349](https://github.com/hashgraph-online/hol-guard/issues/3349)) ([92bd8df](https://github.com/hashgraph-online/hol-guard/commit/92bd8df9d3903c903fa252c04ebeb931fafff2b8))

## [3.16.2](https://github.com/hashgraph-online/hol-guard/compare/v3.16.1...v3.16.2) (2026-10-01)

### Bug Fixes
* **adapters:** withhold structured output without a validated destination ([8fcd376](https://github.com/hashgraph-online/hol-guard/commit/8fcd376b68be5d3b57c669cedc773e39cac6091c))
* **ci:** align macOS verification and surface native build blockers ([#3356](https://github.com/hashgraph-online/hol-guard/issues/3356)) ([d9fd6aa](https://github.com/hashgraph-online/hol-guard/commit/d9fd6aa9518371bec5ad9e2016fc5b770bbf2dd6))
* **command:** evaluate bounded timeout commands through native controls ([8523d6b](https://github.com/hashgraph-online/hol-guard/commit/8523d6b67e6a73a836679d36834729c40f9bc26d))

## [3.16.1](https://github.com/hashgraph-online/hol-guard/compare/v3.16.0...v3.16.1) (2026-10-01)

### Bug Fixes
* **codex:** bound optional hook diagnostics ([fde51df](https://github.com/hashgraph-online/hol-guard/commit/fde51df1df40413397a033476e0fce75da84a3b6))
* **codex:** preserve ownership conflicts for aliased Python imports ([f94860c](https://github.com/hashgraph-online/hol-guard/commit/f94860cb3efcd93bdec752fed0ddaee8fa7eae7e))
* **native:** bound managed client cleanup by the caller deadline ([14f4f8d](https://github.com/hashgraph-online/hol-guard/commit/14f4f8ded6de5a6477702538c525765c8cf2e576))

### Performance Improvements

* **ci:** give Sonar dedicated CPU and heap budgets ([#3350](https://github.com/hashgraph-online/hol-guard/issues/3350)) ([e22c395](https://github.com/hashgraph-online/hol-guard/commit/e22c395f7f0d2ae08b784a71a1e5cbb4e4dad61c))

## [3.16.0](https://github.com/hashgraph-online/hol-guard/compare/v3.15.6...v3.16.0) (2026-10-01)

### Features

* **mcp:** show app summaries from existing Codex hosts ([7c1e9b6](https://github.com/hashgraph-online/hol-guard/commit/7c1e9b60b44d82fbfd770b8cbd19fb7cbcf90a4e))

## [3.15.6](https://github.com/hashgraph-online/hol-guard/compare/v3.15.5...v3.15.6) (2026-10-01)

### Bug Fixes

* **approvals:** consume native reviews bound to policy domains ([7b3cf82](https://github.com/hashgraph-online/hol-guard/commit/7b3cf82c8ab08728d8d2c07ae60caa62175f4756))
* **claude:** deny tool actions when native review is unavailable ([9a97d62](https://github.com/hashgraph-online/hol-guard/commit/9a97d620a66654b4a24896efdc88dfcf74c7736e))
* **codex:** reject conflicting unowned Guard hooks ([cb47a1a](https://github.com/hashgraph-online/hol-guard/commit/cb47a1adcde5552a11517133a8308c807d20d473))
* **command:** recognize benign head and tail pipeline input ([e5aada7](https://github.com/hashgraph-online/hol-guard/commit/e5aada7c1132c43b521b9e21783711cc204b919f))
* **containment:** reject executable identity races ([#3331](https://github.com/hashgraph-online/hol-guard/issues/3331)) ([4faebae](https://github.com/hashgraph-online/hol-guard/commit/4faebae7f59707c74445dbd4e7ea0f21af715a70))
* **guard:** move archive inspection lease and containment into the Rust worker ([#3330](https://github.com/hashgraph-online/hol-guard/issues/3330)) ([d79f0c4](https://github.com/hashgraph-online/hol-guard/commit/d79f0c47d7d01ebbcf6487890bd77d9419a3ae6a))
* **hooks:** emit native failure responses as JSON ([6bdbc54](https://github.com/hashgraph-online/hol-guard/commit/6bdbc542d912ce338b838e8af927334f187819ad))
* **native:** honor the caller budget during resident startup ([399f7cb](https://github.com/hashgraph-online/hol-guard/commit/399f7cbcc1322ef43f4240c17c9c18f0ef6a69ce))

## [3.15.5](https://github.com/hashgraph-online/hol-guard/compare/v3.15.4...v3.15.5) (2026-10-01)

### Bug Fixes

* **mcp:** discover up to 100 configured servers ([#3317](https://github.com/hashgraph-online/hol-guard/issues/3317)) ([02b3aad](https://github.com/hashgraph-online/hol-guard/commit/02b3aad99e1b880010019b47cf111dc61486bd0f))

## [3.15.4](https://github.com/hashgraph-online/hol-guard/compare/v3.15.3...v3.15.4) (2026-10-01)

### Bug Fixes

* **mcp:** explain discovery capability rejections ([b2bc18f](https://github.com/hashgraph-online/hol-guard/commit/b2bc18fb3abcc64e60d6f5829307d9204c3fc56c))

## [3.15.3](https://github.com/hashgraph-online/hol-guard/compare/v3.15.2...v3.15.3) (2026-10-01)

### Bug Fixes

* **ci:** dispatch Desktop Core feeds after verified publication ([8c3dc97](https://github.com/hashgraph-online/hol-guard/commit/8c3dc9750789c407ca8c78508507296cda8e7d01))
* **ci:** isolate test setup and trim worker dependencies ([766db3b](https://github.com/hashgraph-online/hol-guard/commit/766db3bdf02eb2722d42a8e169f7993befa7a5a2))
* **ci:** retain bounded receipt persistence diagnostics ([0e6fbef](https://github.com/hashgraph-online/hol-guard/commit/0e6fbefcff1b919ff7f11d5632f4609cf9eaf019))

## [3.15.2](https://github.com/hashgraph-online/hol-guard/compare/v3.15.1...v3.15.2) (2026-10-01)

### Performance Improvements

* **mcp:** reduce decision connection overhead and page connectors ([ad915da](https://github.com/hashgraph-online/hol-guard/commit/ad915da0488d4665ef8b83999d2705d919520d9d))

## [3.15.1](https://github.com/hashgraph-online/hol-guard/compare/v3.15.0...v3.15.1) (2026-10-01)

### Bug Fixes

* **ci:** preserve pending Core feed publishers ([99e2b36](https://github.com/hashgraph-online/hol-guard/commit/99e2b36f1324b2168454d148135942bc015c2167))
* **ci:** wake Core feeds after stable publication ([a9e0657](https://github.com/hashgraph-online/hol-guard/commit/a9e0657391476bf2590f8cd96e82fa74cd029812))
* **mcp:** diagnose inventory refresh failures ([a9ddedb](https://github.com/hashgraph-online/hol-guard/commit/a9ddedb5d8605d85381864943cce41a259e488db))

## [3.15.0](https://github.com/hashgraph-online/hol-guard/compare/v3.14.1...v3.15.0) (2026-10-01)

### Features

* **guard:** move offline archive inspection into the Rust runtime ([#3300](https://github.com/hashgraph-online/hol-guard/issues/3300)) ([61ef105](https://github.com/hashgraph-online/hol-guard/commit/61ef105eb7aae0aa8a8c9c4e46ec3a83a976efd0))
* **mcp:** add reviewed Undo for Codex setup ([#3289](https://github.com/hashgraph-online/hol-guard/issues/3289)) ([9e6ccb1](https://github.com/hashgraph-online/hol-guard/commit/9e6ccb1cd5ab93a0c9b2c7e0ce69bb6d1f6f1ef4))

## [3.14.1](https://github.com/hashgraph-online/hol-guard/compare/v3.14.0...v3.14.1) (2026-09-30)

### Bug Fixes

* **daemon:** load pipx shared dependencies during isolated startup ([6af80cb](https://github.com/hashgraph-online/hol-guard/commit/6af80cb3540a66732eeabae2d21ff72e6a29ffc9))
* **hooks:** deny protected requests without native decisions ([#3228](https://github.com/hashgraph-online/hol-guard/issues/3228)) ([eba5953](https://github.com/hashgraph-online/hol-guard/commit/eba59535d34f93637a8736d0b10045ea848c8d90))

Older releases are listed in the [changelog archive](docs/changelog-archive.md).

## [Unreleased]

### Fixed

- Claude marketplace scans treat `strict` as an optional boolean on each
  `plugins[]` entry (default `true`) instead of requiring a root-level field
  that Claude Code rejects.
- `HARDCODED_SECRET` no longer treats pure `${VAR}` or `{{var}}` expansions as
  embedded credentials outside docs and tests. Non-empty defaults and suffixes
  still fail.
- Native DeepSeek Harness packages can set `dsh.bundle.mode` to `"patch"` so
  patch-only bundles are not required to export Cordis `apply(ctx)`. Packages
  that declare `main` or `exports` still need that runtime.

### Changed

- Added the HOL Guard 3.0 Managed Controls user, operator, migration, recovery,
  incident, rollback, support, and release documentation set.
- Persistent menu-bar and system-tray ownership moved to the separate
  `hashgraph-online/hol-guard-desktop` application.
- HOL Guard Core remains headless and continues to own policy enforcement,
  approvals, receipts, the local daemon, browser dashboard, fallback
  notifications, updates, repair, and diagnostics.
- The canonical dashboard launcher remains available to trusted local callers.
- User-facing credential redaction moved to the platform-neutral
  `guard.secret_redaction` module.

### Removed

- Python/pystray tray runtime, platform startup adapters, tray CLI commands,
  dashboard tray controls, tray update handoff, tray assets, and tray-only
  dependencies.
