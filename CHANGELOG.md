# Changelog

All notable changes to HOL Guard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Older releases are preserved in the [changelog archive](docs/changelog-archive.md).

## Unreleased

### Fixed
* **command:** close a family of shell heredoc scanner evasions that hid commands from text review. Each one made the scan mask text as heredoc body that bash executes. A greedy `<<-` operator now parses a `--DELIM` delimiter the way bash reads it. The scan state now spans lines, so a quote opened earlier is no longer forgotten and a `<<EOF` written inside it stops masking the lines bash runs. Scanning stops at a word-initial `#` comment, with the word boundary taken from the scan's own steps and carried across a line continuation, so an escaped blank, an escaped operator and a joined line are read the way bash reads them. A backslash inside single quotes is taken literally and no longer consumes the closing quote. The scan replaces a per-candidate lookbehind regular expression with a direct character scan, preserving the original grammar and the extraction and masking offsets.
* **daemon:** skip the unused structured-output configuration projection on native denials, which carry no model-visible content to project. Allowed requests retain fresh configuration and revocation checks, and the daemon records a lifecycle reason when an idle timeout or an interrupt starts shutdown.
* **scanner:** stop reporting a risky approval default when Markdown documentation only names a bare value such as `danger-full-access` in an inline code span. Fenced and indented code, values after an assignment or a flag, `approval_policy` and `approvalMode` settings, and agent instruction files (skills, commands, agents, `AGENTS.md`, `.claude/` and similar) are still reported.
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

## [3.52.0](https://github.com/hashgraph-online/hol-guard/compare/v3.51.0...v3.52.0) (2026-10-21)


### Features

* **containment:** let the resident answer containment health ([#5417](https://github.com/hashgraph-online/hol-guard/issues/5417)) ([7e78ed3](https://github.com/hashgraph-online/hol-guard/commit/7e78ed38587e9c6f9372ac819375924b9405f7b1))
* **containment:** run the installed containment proof in the native runtime ([#5441](https://github.com/hashgraph-online/hol-guard/issues/5441)) ([68c3c8b](https://github.com/hashgraph-online/hol-guard/commit/68c3c8b20e86b5c4c6bcf9be9576b4ec1f0da038))
* **dashboard:** give Rules & exceptions the Home hero, a widest-rules spotlight, and a rule inspector ([#5458](https://github.com/hashgraph-online/hol-guard/issues/5458)) ([e309ad0](https://github.com/hashgraph-online/hol-guard/commit/e309ad05c1bad4069f8ab4aa0a056c73bad5052f))
* **dashboard:** put remembered rules first on Rules & exceptions with at-a-glance counts, action filters, and bulk removal ([#5453](https://github.com/hashgraph-online/hol-guard/issues/5453)) ([b99e7da](https://github.com/hashgraph-online/hol-guard/commit/b99e7da06b5e317791de23abce91c687bfc48f2e))
* **extensions:** accept a public profile on extension credit ([#5454](https://github.com/hashgraph-online/hol-guard/issues/5454)) ([298c1a7](https://github.com/hashgraph-online/hol-guard/commit/298c1a7421527625e2602394d571b21fdbca857f))
* **windows:** run a project's pytest inside read-only containment ([#5422](https://github.com/hashgraph-online/hol-guard/issues/5422)) ([e31d1c9](https://github.com/hashgraph-online/hol-guard/commit/e31d1c99d992373a6a9a2e67c921d0f7a10a377b))


### Bug Fixes

* **contained:** accept a venv link into the macOS developer directory ([#5425](https://github.com/hashgraph-online/hol-guard/issues/5425)) ([7396af8](https://github.com/hashgraph-online/hol-guard/commit/7396af87f8c1e1decb1f8f953674968a626895f9))
* **containment:** keep the contained workspace write's own deadline ([#5446](https://github.com/hashgraph-online/hol-guard/issues/5446)) ([4c96a78](https://github.com/hashgraph-online/hol-guard/commit/4c96a78f2cdf3e337d1f84c51e4bad3da8bd91ca))
* **deps:** take certifi 2026.10.19 for the compromised emSign roots ([#5480](https://github.com/hashgraph-online/hol-guard/issues/5480)) ([4cf5146](https://github.com/hashgraph-online/hol-guard/commit/4cf514673613ba184f89ea00838aa8bf0a2fdf63))
* **extensions:** keep the Extensions page loading after a catalog activation lands ([#5438](https://github.com/hashgraph-online/hol-guard/issues/5438)) ([ad1fd09](https://github.com/hashgraph-online/hol-guard/commit/ad1fd093da998e2a2deac5603d9d3574b1da3e2b))
* **extensions:** save a protection policy without reaching the network ([#5442](https://github.com/hashgraph-online/hol-guard/issues/5442)) ([be47b9a](https://github.com/hashgraph-online/hol-guard/commit/be47b9a7d530e2c1d1d5537ca7319adffe8c3d51))
* **fleet:** report AIBOM-detected items and name machines by host name ([#5440](https://github.com/hashgraph-online/hol-guard/issues/5440)) ([3c3d1ad](https://github.com/hashgraph-online/hol-guard/commit/3c3d1ad2669e85ef28fae6e47adcce455dd27138))
* **gauntlet:** re-run a case the model never exercised instead of a whole attempt ([#5411](https://github.com/hashgraph-online/hol-guard/issues/5411)) ([016ced7](https://github.com/hashgraph-online/hol-guard/commit/016ced789de138d8cd9f3f4151b6beb541d54bc3))
* **gauntlet:** tell a session started beside a checkout where it really is ([#5421](https://github.com/hashgraph-online/hol-guard/issues/5421)) ([1126b18](https://github.com/hashgraph-online/hol-guard/commit/1126b180572efb273390a1d389f5ed88a9017a03))
* **guard:** record a failing catalog preparation and report it as terminal ([#5437](https://github.com/hashgraph-online/hol-guard/issues/5437)) ([42c3be7](https://github.com/hashgraph-online/hol-guard/commit/42c3be7a1f01e302114df2b626380f929c8165a4))
* **guard:** surface container extension hints and category icons in inbox ([#5439](https://github.com/hashgraph-online/hol-guard/issues/5439)) ([b4399c9](https://github.com/hashgraph-online/hol-guard/commit/b4399c963a25b87b5c948844afbd28ececa98d02))
* **pretool:** allow worktree creation through missing parent directories ([#5456](https://github.com/hashgraph-online/hol-guard/issues/5456)) ([fa10941](https://github.com/hashgraph-online/hol-guard/commit/fa1094177cf3011a19e6315eab84f43dbe2a6c6a))
* **pretool:** let a read-only git route to a directory without a repository ([#5408](https://github.com/hashgraph-online/hol-guard/issues/5408)) ([91d99a8](https://github.com/hashgraph-online/hol-guard/commit/91d99a87c760df46960b52ca5371af0260efd9c5))
* **pretool:** list a temporary scratch directory the way its owner sees it ([#5432](https://github.com/hashgraph-online/hol-guard/issues/5432)) ([3fd63bb](https://github.com/hashgraph-online/hol-guard/commit/3fd63bbbac21edbe1c32a9173b2e2ba1cd90d774))
* **pretool:** prove an rg listing by the names it can print ([#5429](https://github.com/hashgraph-online/hol-guard/issues/5429)) ([abcaadc](https://github.com/hashgraph-online/hol-guard/commit/abcaadc3aa7c7ec90d9b037f344fbe491a9b4048))
* **pretool:** read a missing path in a registered worktree quietly ([#5424](https://github.com/hashgraph-online/hol-guard/issues/5424)) ([6afb490](https://github.com/hashgraph-online/hol-guard/commit/6afb490ef253d2c43ea7d8508c75f215bba72b85))
* **pretool:** stop a missing worktree read from climbing out with .. ([#5457](https://github.com/hashgraph-online/hol-guard/issues/5457)) ([d2a1b30](https://github.com/hashgraph-online/hol-guard/commit/d2a1b305cf44387fa42d2be5fa706363866c780a))
* **runtime:** keep a cancelled Bash launch's reply deliverable on Windows ([#5428](https://github.com/hashgraph-online/hol-guard/issues/5428)) ([4f28277](https://github.com/hashgraph-online/hol-guard/commit/4f28277c89cc39d5f0a93b59a01eda8cd2c512d8))
* **runtime:** keep a journaled receipt when the store is briefly locked ([#5415](https://github.com/hashgraph-online/hol-guard/issues/5415)) ([dd4fa37](https://github.com/hashgraph-online/hol-guard/commit/dd4fa3780d4590477ac3b96ea54caa72ee212746))


### Performance Improvements

* **ci:** extend nextest archive caching to command and core partitions ([#5423](https://github.com/hashgraph-online/hol-guard/issues/5423)) ([d78503b](https://github.com/hashgraph-online/hol-guard/commit/d78503b6c55e633f1636e8ce45f799a427b6d4cf))

## [3.51.0](https://github.com/hashgraph-online/hol-guard/compare/v3.50.0...v3.51.0) (2026-10-20)


### Features

* **mcp-servers:** add Kuuhaku MCP contribution ([#5231](https://github.com/hashgraph-online/hol-guard/issues/5231)) ([ab8f860](https://github.com/hashgraph-online/hol-guard/commit/ab8f860b60b9618a72367a33fe23b951bedb33df))
* **mcp:** add leadline MCP server to catalog ([#5308](https://github.com/hashgraph-online/hol-guard/issues/5308)) ([fcb99a9](https://github.com/hashgraph-online/hol-guard/commit/fcb99a986a146fce7b5432e5b450cceabbd128b0))
* **runtime:** let the resident resolve the package firewall entitlement ([#5360](https://github.com/hashgraph-online/hol-guard/issues/5360)) ([f6d0fd9](https://github.com/hashgraph-online/hol-guard/commit/f6d0fd9c13b5e1655e3fdcf15d940deed4c4047a))


### Bug Fixes

* **dashboard:** say what a failed extension load means instead of its reason code ([#5418](https://github.com/hashgraph-online/hol-guard/issues/5418)) ([9b90a09](https://github.com/hashgraph-online/hol-guard/commit/9b90a09c30cae150d9dc19af089d2f9ebd289afe))
* **gauntlet:** end an attempt on a product failure, not on model non-compliance ([#5404](https://github.com/hashgraph-online/hol-guard/issues/5404)) ([e965682](https://github.com/hashgraph-online/hol-guard/commit/e9656825c914e1a2cadac874465e78ca10338d14))
* **gauntlet:** give qualification a budget that can outlast model noise ([#5407](https://github.com/hashgraph-online/hol-guard/issues/5407)) ([eff459c](https://github.com/hashgraph-online/hol-guard/commit/eff459c7ac50e557d9a6b83d2880baea63346192))
* **gauntlet:** judge the Windows private temp folder in either separator spelling ([#5403](https://github.com/hashgraph-online/hol-guard/issues/5403)) ([2fc4784](https://github.com/hashgraph-online/hol-guard/commit/2fc4784204164a8e13a59b92f29e630a866e89d2))
* **gauntlet:** tell these two cases apart from work a model declines ([#5406](https://github.com/hashgraph-online/hol-guard/issues/5406)) ([6f39ee0](https://github.com/hashgraph-online/hol-guard/commit/6f39ee0a97855abd204e8de8e1062165b20b626c))
* **guard:** judge $HOME read operands like their ~ spelling ([#5389](https://github.com/hashgraph-online/hol-guard/issues/5389)) ([bc9ef37](https://github.com/hashgraph-online/hol-guard/commit/bc9ef37a73c118c8a6accac08b576cd0b087ae28))
* **pretool:** read a tool's own home directory by the word it was named ([#5413](https://github.com/hashgraph-online/hol-guard/issues/5413)) ([e70212a](https://github.com/hashgraph-online/hol-guard/commit/e70212a5b9a302e7eb8dea417b3c454d01642791))
* **redirect:** admit sibling repository writes on Windows ([#5399](https://github.com/hashgraph-online/hol-guard/issues/5399)) ([a2e0fa8](https://github.com/hashgraph-online/hol-guard/commit/a2e0fa8a2e60296fb97c33fb0d4cc42db59f110e))
* **release:** keep the command pack bundle binding when staging Desktop Core ([#5420](https://github.com/hashgraph-online/hol-guard/issues/5420)) ([dedc537](https://github.com/hashgraph-online/hol-guard/commit/dedc537d0ae8d40f0e9ff476fd6e4e743bd3846b)), closes [#5419](https://github.com/hashgraph-online/hol-guard/issues/5419)
* **release:** reseal the source compiler manifest after Apple signing ([#5416](https://github.com/hashgraph-online/hol-guard/issues/5416)) ([d4e3372](https://github.com/hashgraph-online/hol-guard/commit/d4e3372c0715daeabbd16bd465416da63343b9e8))
* **unmodeled:** review a command whose substitutions name their programs ([#5388](https://github.com/hashgraph-online/hol-guard/issues/5388)) ([9ac1050](https://github.com/hashgraph-online/hol-guard/commit/9ac105001ae659aa33db5cf12d88ff1185bfefce))

## [3.50.0](https://github.com/hashgraph-online/hol-guard/compare/v3.49.0...v3.50.0) (2026-10-20)


### Features

* add Kelados TTS command source extension ([#3749](https://github.com/hashgraph-online/hol-guard/issues/3749)) ([4adc6a0](https://github.com/hashgraph-online/hol-guard/commit/4adc6a09340d60bd2c3f6c077e0bf0e939a172c0))
* **approvals:** inspect bounded Bash subjects ([#5097](https://github.com/hashgraph-online/hol-guard/issues/5097)) ([f0bc4bb](https://github.com/hashgraph-online/hol-guard/commit/f0bc4bb6505932a6efd35c522d3986764a697476))
* **approvals:** raise one setup notice per connector instead of one per command ([#5077](https://github.com/hashgraph-online/hol-guard/issues/5077)) ([6802599](https://github.com/hashgraph-online/hol-guard/commit/680259976af7c7ea6652d1219dad5d76204d7f39))
* **approvals:** recommend setting up the connector a held request waits on ([#5078](https://github.com/hashgraph-online/hol-guard/issues/5078)) ([3fa8e1d](https://github.com/hashgraph-online/hol-guard/commit/3fa8e1db789a979caed3747b8697389f8517f23f))
* **catalog:** register aseprite-lua-mcp extension ([#5241](https://github.com/hashgraph-online/hol-guard/issues/5241)) ([89af72d](https://github.com/hashgraph-online/hol-guard/commit/89af72df4248099cffe2c52432879724bd398ece))
* **ci:** reject Guard modules that nothing references ([#5268](https://github.com/hashgraph-online/hol-guard/issues/5268)) ([5dfbe5f](https://github.com/hashgraph-online/hol-guard/commit/5dfbe5fd5cde6fd533c34e5a630e43eedf6550ea))
* **dashboard:** open the Protect page on a held connector request ([#5084](https://github.com/hashgraph-online/hol-guard/issues/5084)) ([f2ee7d7](https://github.com/hashgraph-online/hol-guard/commit/f2ee7d7c012e516ca2ba2ca80308e8c846c3ee55))
* **dashboard:** redesign Home with particle brand mark and plain-language walkthrough ([#5271](https://github.com/hashgraph-online/hol-guard/issues/5271)) ([fa3b867](https://github.com/hashgraph-online/hol-guard/commit/fa3b8674325cd3c67634db1e2efeb22c82c55234))
* **dashboard:** set up custom extensions with the same family browser as the detail page ([#5048](https://github.com/hashgraph-online/hol-guard/issues/5048)) ([325de84](https://github.com/hashgraph-online/hol-guard/commit/325de840587a6d057c3fbde1bdf731b686f71416))
* **dashboard:** show one setup card per connector in the inbox ([#5065](https://github.com/hashgraph-online/hol-guard/issues/5065)) ([babbda1](https://github.com/hashgraph-online/hol-guard/commit/babbda1f9bd11f03a6bc6c1ecd2b421f1ea5ae62))
* **extensions:** add command.kintsua command safety extension ([#5047](https://github.com/hashgraph-online/hol-guard/issues/5047)) ([bb774ae](https://github.com/hashgraph-online/hol-guard/commit/bb774ae817155f533a1dcdfadded1ffc4e0319e7))
* **extensions:** add command.skills-check-updates command source ([#4918](https://github.com/hashgraph-online/hol-guard/issues/4918)) ([b6dd222](https://github.com/hashgraph-online/hol-guard/commit/b6dd2229f6d6908b2459aa65dd9ed74744b45237))
* **extensions:** compile immutable policy packs with a bounded index ([#5105](https://github.com/hashgraph-online/hol-guard/issues/5105)) ([7767cb4](https://github.com/hashgraph-online/hol-guard/commit/7767cb4363d3eb4d7f8fadde428c1bb9a1671e6b))
* **extensions:** load enabled policies independently of the catalog ([#5246](https://github.com/hashgraph-online/hol-guard/issues/5246)) ([4d17f27](https://github.com/hashgraph-online/hol-guard/commit/4d17f271848d1bdedc85d6bcc1b575d76d9de21b))
* **extensions:** reuse validated packs in catalog-free compiler sessions ([#5114](https://github.com/hashgraph-online/hol-guard/issues/5114)) ([bad8965](https://github.com/hashgraph-online/hol-guard/commit/bad8965d3963916250881e1718761d9d72ee1104))
* **guard:** add a harness version coverage promotion command and enforce release binding on stable builds ([#5252](https://github.com/hashgraph-online/hol-guard/issues/5252)) ([0f4e84a](https://github.com/hashgraph-online/hol-guard/commit/0f4e84a1d8c13303ab556401968c0a0a6577b976))
* **guard:** add Repo Notebook MCP server contribution ([#5207](https://github.com/hashgraph-online/hol-guard/issues/5207)) ([6f693b0](https://github.com/hashgraph-online/hol-guard/commit/6f693b020ece6b0a99799adabff1964af1bf14fd))
* **guard:** compose selected command packs without an aggregate program ([#5139](https://github.com/hashgraph-online/hol-guard/issues/5139)) ([19f6969](https://github.com/hashgraph-online/hol-guard/commit/19f6969c39408284c11e3d6e5d145857e54dec91))
* **guard:** decide a policy document in the runtime instead of beside it ([#5042](https://github.com/hashgraph-online/hol-guard/issues/5042)) ([fd5567f](https://github.com/hashgraph-online/hol-guard/commit/fd5567f5596eab63d6ff2f3bd1dc402eb2636d94))
* **guard:** group reviews of CLIs this device was never set up for ([#5063](https://github.com/hashgraph-online/hol-guard/issues/5063)) ([8647fb8](https://github.com/hashgraph-online/hol-guard/commit/8647fb8e199a60bbc1cee35d1647f0d09133eb25))
* **guard:** group reviews of MCP servers this device was never set up for ([#5072](https://github.com/hashgraph-online/hol-guard/issues/5072)) ([49530cc](https://github.com/hashgraph-online/hol-guard/commit/49530ccf37a3e13c73df7f3fdc428c75067659cf))
* **guard:** list configured MCP servers in mcp list, status and doctor ([#5061](https://github.com/hashgraph-online/hol-guard/issues/5061)) ([cca77ac](https://github.com/hashgraph-online/hol-guard/commit/cca77ace13c8c41a3bdc4782a784705ee3b2d422))
* **guard:** prove the two Git listings that only print ([#5058](https://github.com/hashgraph-online/hol-guard/issues/5058)) ([c7861d9](https://github.com/hashgraph-online/hol-guard/commit/c7861d9f1ea07ec5090121a1248c2d28fb2e43f9))
* **guard:** record connector setup context and compute the setup recommendation ([#5085](https://github.com/hashgraph-online/hol-guard/issues/5085)) ([400b0f6](https://github.com/hashgraph-online/hol-guard/commit/400b0f658497c3b12d8d1a37269cc501ffbe5047))
* **guard:** resume Oh My Pi after a safe-alternative approval ([#4988](https://github.com/hashgraph-online/hol-guard/issues/4988)) ([d2de648](https://github.com/hashgraph-online/hol-guard/commit/d2de648e811ed2109d2ef696651f338552546730))
* **guard:** run content-bound Bash approvals through the native owner ([#5269](https://github.com/hashgraph-online/hol-guard/issues/5269)) ([a517659](https://github.com/hashgraph-online/hol-guard/commit/a5176594c2c5a4331a8a51479e95cafec039bb6c))
* **guard:** run granted local CLIs in a capability-scoped workspace sandbox ([#5074](https://github.com/hashgraph-online/hol-guard/issues/5074)) ([e2574e0](https://github.com/hashgraph-online/hol-guard/commit/e2574e0157450ce8dba4aa88f687437c03081c52))
* **guard:** say what runs contained and what runs directly in sandbox text ([#5090](https://github.com/hashgraph-online/hol-guard/issues/5090)) ([79c3b3d](https://github.com/hashgraph-online/hol-guard/commit/79c3b3d23b60b0c4d77cf3f10669935e7b8158f0))
* **guard:** store per-CLI capabilities behind the extension-control proof ([#5071](https://github.com/hashgraph-online/hol-guard/issues/5071)) ([533529e](https://github.com/hashgraph-online/hol-guard/commit/533529eb4d61bbfb8882c60f8b92ba9c6c04417a))
* **guard:** suggest the access a granted CLI's contained run was denied ([#5153](https://github.com/hashgraph-online/hol-guard/issues/5153)) ([3f12646](https://github.com/hashgraph-online/hol-guard/commit/3f1264695ccae74753b2ff3c8561b0f42f340718))
* **hook:** let the resident name the action observe mode records ([#5262](https://github.com/hashgraph-online/hol-guard/issues/5262)) ([4023fb6](https://github.com/hashgraph-online/hol-guard/commit/4023fb6ea9e93ee44e462827d3dd0e4819bab4a4))
* **hook:** let the resident say why a remembered local rule was refused ([#5345](https://github.com/hashgraph-online/hol-guard/issues/5345)) ([204bad5](https://github.com/hashgraph-online/hol-guard/commit/204bad5ee667277989c21da69b41ff78a97f9420))
* **hook:** settle a package request's saved-approval reuse in the resident ([#5343](https://github.com/hashgraph-online/hol-guard/issues/5343)) ([a7e801c](https://github.com/hashgraph-online/hol-guard/commit/a7e801c11ef7ce852d001afd1fff7e83025afec0))
* **local-cli:** resolve a connector's held requests once it is set up ([#5083](https://github.com/hashgraph-online/hol-guard/issues/5083)) ([39a8cba](https://github.com/hashgraph-online/hol-guard/commit/39a8cba6e7a6246733b55258fa58dbd90618000f))
* **mcp-relay:** keep servers with shell and command tools on the native relay ([#5230](https://github.com/hashgraph-online/hol-guard/issues/5230)) ([c7fd754](https://github.com/hashgraph-online/hol-guard/commit/c7fd754194cc9f18f7db773c803a9a5dac706347))
* **mcp-relay:** resolve a relayed workspace instead of deferring to the proxy ([#5237](https://github.com/hashgraph-online/hol-guard/issues/5237)) ([9be09d7](https://github.com/hashgraph-online/hol-guard/commit/9be09d71cd3b18a6813f941365e438daf333c6f5))
* **mcp-servers:** add DC Hub MCP contribution ([#5176](https://github.com/hashgraph-online/hol-guard/issues/5176)) ([f44c63c](https://github.com/hashgraph-online/hol-guard/commit/f44c63c3a553483b426ab5827c5d31816c1c039a))
* **mcp-servers:** add OpenScreenShot MCP contribution ([#4991](https://github.com/hashgraph-online/hol-guard/issues/4991)) ([b89fda9](https://github.com/hashgraph-online/hol-guard/commit/b89fda9f239955dd0e96fe625a4e142d567313af))
* **mcp-servers:** add ops-brain MCP contribution ([#5255](https://github.com/hashgraph-online/hol-guard/issues/5255)) ([3a4c085](https://github.com/hashgraph-online/hol-guard/commit/3a4c085954039d897c6fb05c489813de434770ab))
* **mcp-servers:** Add Seq MCP Server contribution configuration. ([#5056](https://github.com/hashgraph-online/hol-guard/issues/5056)) ([f316cb9](https://github.com/hashgraph-online/hol-guard/commit/f316cb9832f8bd87ecb59b8f30648dd2b3e57a50))
* **mcp:** add CI Guard MCP server contribution ([#5082](https://github.com/hashgraph-online/hol-guard/issues/5082)) ([780bfcc](https://github.com/hashgraph-online/hol-guard/commit/780bfcccaeb88d3feb7eb6f3acff2729bc475c8d))
* **mcp:** add g-krusch MCP server contribution and trust binding ([#5270](https://github.com/hashgraph-online/hol-guard/issues/5270)) ([cf2ab35](https://github.com/hashgraph-online/hol-guard/commit/cf2ab35dc84853f89e3babd67534d0afe2e93a3e))
* **mcp:** add krusch harness MCP server contribution and trust binding ([#5296](https://github.com/hashgraph-online/hol-guard/issues/5296)) ([752d83b](https://github.com/hashgraph-online/hol-guard/commit/752d83b31aa9d57daa958850eb2d6dd0946b22f9))
* **mcp:** add krusch-agentic-proxy MCP server contribution and trust… ([#5295](https://github.com/hashgraph-online/hol-guard/issues/5295)) ([27a9e4d](https://github.com/hashgraph-online/hol-guard/commit/27a9e4d50ed88f5d016d6e843187efc3d1b29b79))
* **mcp:** add krusch-context-mcp MCP server contribution and trust b… ([#5290](https://github.com/hashgraph-online/hol-guard/issues/5290)) ([27c8705](https://github.com/hashgraph-online/hol-guard/commit/27c8705d79670de801b32e0d978c3a766973f5e3))
* **mcp:** add krusch-git MCP server contribution and trust binding ([#5291](https://github.com/hashgraph-online/hol-guard/issues/5291)) ([67c2053](https://github.com/hashgraph-online/hol-guard/commit/67c20538041642bccbb86c7a47502e222b2fa867))
* **mcp:** cover FableCut frame and track tools ([#5031](https://github.com/hashgraph-online/hol-guard/issues/5031)) ([df8336a](https://github.com/hashgraph-online/hol-guard/commit/df8336a340ee7c93674336dcc1ea445a40dec1e7))
* **pretool:** prove a patch check the way it reports ([#5109](https://github.com/hashgraph-online/hol-guard/issues/5109)) ([aea52ad](https://github.com/hashgraph-online/hol-guard/commit/aea52ad7a5afa4f6bb7500634757546284ee2749))
* **prompt:** review a prompt's credential-looking local file in the resident ([#5238](https://github.com/hashgraph-online/hol-guard/issues/5238)) ([615bc3e](https://github.com/hashgraph-online/hol-guard/commit/615bc3e9ce94c3311e1d032e147510e5d2f92979))
* publish authenticated extension packs and paged directory data ([#5122](https://github.com/hashgraph-online/hol-guard/issues/5122)) ([68fba25](https://github.com/hashgraph-online/hol-guard/commit/68fba25c3bca834ade1f6dd66ae2c95ba8ec995c))
* **runtime:** admit authenticated command pack snapshots ([#5147](https://github.com/hashgraph-online/hol-guard/issues/5147)) ([2beef2e](https://github.com/hashgraph-online/hol-guard/commit/2beef2ef2932360310d972792c372306924f07b6))
* **runtime:** build the data-flow request artifact in the resident ([#5309](https://github.com/hashgraph-online/hol-guard/issues/5309)) ([45ede93](https://github.com/hashgraph-online/hol-guard/commit/45ede9390a42728b37b6979209fcbba8aa475f76))
* **runtime:** fold multi-signal prompt reviews in the resident ([#5310](https://github.com/hashgraph-online/hol-guard/issues/5310)) ([0059d44](https://github.com/hashgraph-online/hol-guard/commit/0059d440880f7005fb47a09eeb247b587e2abbeb))
* **runtime:** let the resident calibrate detector signals ([#5364](https://github.com/hashgraph-online/hol-guard/issues/5364)) ([9895d1e](https://github.com/hashgraph-online/hol-guard/commit/9895d1e360b629ee1187ac137ba6740cb6f4586f))
* **runtime:** let the resident derive the sensitive tool-action artifact id ([#5315](https://github.com/hashgraph-online/hol-guard/issues/5315)) ([ca19fc8](https://github.com/hashgraph-online/hol-guard/commit/ca19fc8f7e89a44adba292ac4788fbaee96bd337))
* **runtime:** mediate Oh My Pi structured output in the resident ([#5166](https://github.com/hashgraph-online/hol-guard/issues/5166)) ([3e0dbb5](https://github.com/hashgraph-online/hol-guard/commit/3e0dbb5af276e743bdedacaa9754ff3805e89345))
* **runtime:** move the routine local runner verdict into the resident parser ([#5280](https://github.com/hashgraph-online/hol-guard/issues/5280)) ([7ea2858](https://github.com/hashgraph-online/hol-guard/commit/7ea2858377c2c4b2b23f5ad1a1922d44ace11cdf))
* **runtime:** plan every proven shell directory in one Cisco preflight exchange ([#5349](https://github.com/hashgraph-online/hol-guard/issues/5349)) ([5f4a26e](https://github.com/hashgraph-online/hol-guard/commit/5f4a26eb994a543076bfd098c73c13a38a8e1976))
* **runtime:** port the hook evidence writer's journal, receipt, Composio and correlation seams ([#5098](https://github.com/hashgraph-online/hol-guard/issues/5098)) ([a44c9ae](https://github.com/hashgraph-online/hol-guard/commit/a44c9aeb4a2152bebd1927bca7e34863c34d321a))
* **runtime:** read artifact confidence strength off the confidence text in the resident ([#5350](https://github.com/hashgraph-online/hol-guard/issues/5350)) ([2bebd13](https://github.com/hashgraph-online/hol-guard/commit/2bebd137aa1fdff55ee91e69214f54012792355e))
* **runtime:** record Composio provider discovery in the guard store resident ([#5112](https://github.com/hashgraph-online/hol-guard/issues/5112)) ([2aaaf0e](https://github.com/hashgraph-online/hol-guard/commit/2aaaf0e7f0aab58b2e60cb08cf87911feedb3581))
* **runtime:** record hook evidence through the native store ([#5118](https://github.com/hashgraph-online/hol-guard/issues/5118)) ([e0b6c26](https://github.com/hashgraph-online/hol-guard/commit/e0b6c2688515c023fdfe2e6617bf2f303707feda))
* **runtime:** record native decision receipts in the resident store ([#5107](https://github.com/hashgraph-online/hol-guard/issues/5107)) ([39a9ab2](https://github.com/hashgraph-online/hol-guard/commit/39a9ab25d6353c7611875ffd48b86de81f9cb175))
* **runtime:** render the Hermes verdict in the resident ([#5323](https://github.com/hashgraph-online/hol-guard/issues/5323)) ([20e6fb9](https://github.com/hashgraph-online/hol-guard/commit/20e6fb9c6dd3da26a5be74e8bd25a3f2486582d5))
* **runtime:** report a fatal store failure to the client that owns recovery ([#5154](https://github.com/hashgraph-online/hol-guard/issues/5154)) ([ad2df92](https://github.com/hashgraph-online/hol-guard/commit/ad2df92c125e19b5d3a55b27b6316764d757aa4e))
* **runtime:** run the Claude daemon hook in the native bridge ([#5208](https://github.com/hashgraph-online/hol-guard/issues/5208)) ([73d51a7](https://github.com/hashgraph-online/hol-guard/commit/73d51a7e705c519bb9833fab055db5ef6237d122))
* **runtime:** run the hook evidence writer inside the resident ([#5149](https://github.com/hashgraph-online/hol-guard/issues/5149)) ([ecf79de](https://github.com/hashgraph-online/hol-guard/commit/ecf79de2251588eceef2bb0d88007d48b21da063))
* **workflow:** decide GitHub workflow approval lineage in the native runtime ([#5278](https://github.com/hashgraph-online/hol-guard/issues/5278)) ([6bb03b0](https://github.com/hashgraph-online/hol-guard/commit/6bb03b07ac40808b16db18388a6acd05dad7dddc))


### Bug Fixes

* **approvals:** bind a file-tool approval to the file, not the arguments ([#5220](https://github.com/hashgraph-online/hol-guard/issues/5220)) ([3beb48d](https://github.com/hashgraph-online/hol-guard/commit/3beb48dd8cd2fc86ab27162fe4dfaafb588e461b))
* **approvals:** let Allow once reach the retry Claude Code and Codex send ([#5216](https://github.com/hashgraph-online/hol-guard/issues/5216)) ([0c1c641](https://github.com/hashgraph-online/hol-guard/commit/0c1c641affd50caa9618381031621c5470c8bdfb))
* **approvals:** reject consent that cannot authorize a retry ([#5054](https://github.com/hashgraph-online/hol-guard/issues/5054)) ([daa62e4](https://github.com/hashgraph-online/hol-guard/commit/daa62e4e1456945de692e6396404a930218be6de))
* **approvals:** retry a queue read the resident dropped once ([#5161](https://github.com/hashgraph-online/hol-guard/issues/5161)) ([5db0470](https://github.com/hashgraph-online/hol-guard/commit/5db047063ea7624be846edcca0266d28426a3730))
* **catalog:** close the draft lease before Windows renames the extension view ([#5359](https://github.com/hashgraph-online/hol-guard/issues/5359)) ([6fae17e](https://github.com/hashgraph-online/hol-guard/commit/6fae17e174fc1cceeb6d9dba9c7fa053c9e925b4))
* **ci:** bring the nightly native qualification back to green ([#5132](https://github.com/hashgraph-online/hol-guard/issues/5132)) ([2d219f9](https://github.com/hashgraph-online/hol-guard/commit/2d219f941af3bdcac43725862d8512b805d3237b))
* **ci:** build the Windows runtime without lint errors and name the fixture compiler per platform ([#5337](https://github.com/hashgraph-online/hol-guard/issues/5337)) ([5212aee](https://github.com/hashgraph-online/hol-guard/commit/5212aee1a86f77195f6f28018dcbabf4391eeed1))
* **ci:** drop the hook-state waiver the hook graph no longer reaches ([#5311](https://github.com/hashgraph-online/hol-guard/issues/5311)) ([e418155](https://github.com/hashgraph-online/hol-guard/commit/e418155d6465d6f970c4fe3cd2daf233087ef398))
* **ci:** drop the workflow-runtime waiver the hook graph no longer needs ([#5314](https://github.com/hashgraph-online/hol-guard/issues/5314)) ([a3c3307](https://github.com/hashgraph-online/hol-guard/commit/a3c3307b9af90a5c9e1552032d5dd904250ca9d4))
* **ci:** fail qualification on a dead inference lane before the wheel build ([#5352](https://github.com/hashgraph-online/hol-guard/issues/5352)) ([2eea99b](https://github.com/hashgraph-online/hol-guard/commit/2eea99b25050ca6f0a9c8ee4c9f296420e8bc35e))
* **ci:** keep non-pack downloads live in the installed extension probe ([#5335](https://github.com/hashgraph-online/hol-guard/issues/5335)) ([9c92227](https://github.com/hashgraph-online/hol-guard/commit/9c92227731dd915b7e5d8f31858423ce5fd41023))
* **ci:** keep the nightly native lanes on the packaged source compiler ([#5329](https://github.com/hashgraph-online/hol-guard/issues/5329)) ([780b048](https://github.com/hashgraph-online/hol-guard/commit/780b048872dbc4fcfeda6b774ad8e3777aeabd33))
* **ci:** keep the pack-marker fixture out of the Sonar coverage report ([#5174](https://github.com/hashgraph-online/hol-guard/issues/5174)) ([ab1b71d](https://github.com/hashgraph-online/hol-guard/commit/ab1b71dd6a5ddb34d4988c06a9b6dd2bb8dd1000))
* **ci:** reject an I/O ownership waiver the hook graph no longer reaches ([#5302](https://github.com/hashgraph-online/hol-guard/issues/5302)) ([9f7f227](https://github.com/hashgraph-online/hol-guard/commit/9f7f227274eb8f955db6b69f59f970498d36bdbb))
* **ci:** send the global validation context when wheel builds author against the packaged base ([#5305](https://github.com/hashgraph-online/hol-guard/issues/5305)) ([7b1692b](https://github.com/hashgraph-online/hol-guard/commit/7b1692b80b250f156fa041cc8891b52ab287745c))
* **ci:** serve unreleased pack assets to the nightly installed extension probe ([#5330](https://github.com/hashgraph-online/hol-guard/issues/5330)) ([2fe3141](https://github.com/hashgraph-online/hol-guard/commit/2fe31418d2bd948288c99b755ee87f0d8a83cbff))
* **ci:** stop reading a renamed sibling import as filesystem I/O ([#5285](https://github.com/hashgraph-online/hol-guard/issues/5285)) ([83aedf5](https://github.com/hashgraph-online/hol-guard/commit/83aedf5cfdc449b7c7b4069261a3ca361f636ce6))
* **ci:** verify the installed builder from a native wheel and stage packs once ([#5361](https://github.com/hashgraph-online/hol-guard/issues/5361)) ([2b84dc7](https://github.com/hashgraph-online/hol-guard/commit/2b84dc7a2c05c0ed6f35aeb437578914268c5835))
* **cline:** read Cline's two copies of a tool call as one call ([#5160](https://github.com/hashgraph-online/hol-guard/issues/5160)) ([30c223b](https://github.com/hashgraph-online/hol-guard/commit/30c223b245f2f47c683b4ca2c96831a03beb0706))
* **codex:** let a reinstall replace the handlers Guard itself planted ([#5225](https://github.com/hashgraph-online/hol-guard/issues/5225)) ([16079b9](https://github.com/hashgraph-online/hol-guard/commit/16079b9ef443d11bb5dfee1bb7f132761aeb9a63))
* **command:** close three heredoc scanner evasions in the shell structure scan ([#3806](https://github.com/hashgraph-online/hol-guard/issues/3806)) ([48caaa2](https://github.com/hashgraph-online/hol-guard/commit/48caaa260fbb5ca95b911dcf9881ed3e41cb5d30))
* **command:** prove Windows drive-path writes the POSIX spelling already proves ([#5377](https://github.com/hashgraph-online/hol-guard/issues/5377)) ([0af3874](https://github.com/hashgraph-online/hol-guard/commit/0af38743b5393e6aa81443abf3f02368519ce0ed))
* **command:** read a program lookup as the list of names it prints ([#5116](https://github.com/hashgraph-online/hol-guard/issues/5116)) ([896bfbb](https://github.com/hashgraph-online/hol-guard/commit/896bfbbb5ffe8caf134e566e5419cea0dec5aa87))
* **contained-process:** launch hardened images on macOS 14 and name failed launch steps ([#5339](https://github.com/hashgraph-online/hol-guard/issues/5339)) ([1accd48](https://github.com/hashgraph-online/hol-guard/commit/1accd48f1b68de46d27f059c60a255dcf98d0888))
* **contained:** admit a shimmed interpreter in the pytest gate ([#5395](https://github.com/hashgraph-online/hol-guard/issues/5395)) ([4610f60](https://github.com/hashgraph-online/hol-guard/commit/4610f608b6d169bb1f4d328c4c7a1821c2ad2e55))
* **contained:** plan an activation from the command its denial answered for ([#5397](https://github.com/hashgraph-online/hol-guard/issues/5397)) ([26c118e](https://github.com/hashgraph-online/hol-guard/commit/26c118ea55b5aa9599875c20cf9ccd268845fe71))
* **contained:** recognize an external venv whose interpreter is a forwarded macOS developer tool ([#5381](https://github.com/hashgraph-online/hol-guard/issues/5381)) ([7d46c76](https://github.com/hashgraph-online/hol-guard/commit/7d46c764d4021a87ef3ab2f4ebb50d66fef18635))
* **contained:** refuse both Windows spellings of a Python path selector ([#5382](https://github.com/hashgraph-online/hol-guard/issues/5382)) ([4ec1918](https://github.com/hashgraph-online/hol-guard/commit/4ec19188b1baa8f97301d527e60b5d7b6534216f))
* **contained:** resolve macOS /usr/bin tool shims before composing the sandbox ([#5354](https://github.com/hashgraph-online/hol-guard/issues/5354)) ([9b33e08](https://github.com/hashgraph-online/hol-guard/commit/9b33e080db86302a725e10cee74c294cd02d467c))
* **contained:** stop retrying a silent runtime and say it did not answer ([#5211](https://github.com/hashgraph-online/hol-guard/issues/5211)) ([ca10f6f](https://github.com/hashgraph-online/hol-guard/commit/ca10f6fe7e6a0c5bda103d6a884799eb842e9fe1))
* **daemon:** adopt the spawned one-file child on Windows ([#5104](https://github.com/hashgraph-online/hol-guard/issues/5104)) ([730e3de](https://github.com/hashgraph-online/hol-guard/commit/730e3de10b0b990a300de6918b76b58fc0038136))
* **daemon:** find a local CLI on the agent's PATH, not the daemon's ([#5123](https://github.com/hashgraph-online/hol-guard/issues/5123)) ([1dcaec5](https://github.com/hashgraph-online/hol-guard/commit/1dcaec5594d6cfad85a5deddfb93ca7dee1af70d))
* **daemon:** keep the installed daemon and Extensions page working on a fresh install ([#5325](https://github.com/hashgraph-online/hol-guard/issues/5325)) ([ff5e158](https://github.com/hashgraph-online/hol-guard/commit/ff5e1585254bf8918a10e94190c22c8df894ab83))
* **daemon:** recover the control API after a fail-closed authority startup ([#5336](https://github.com/hashgraph-online/hol-guard/issues/5336)) ([4cbc9ba](https://github.com/hashgraph-online/hol-guard/commit/4cbc9ba97d8f0e931b1ad3a8aeecf73b9ad500c6))
* **daemon:** release prepared cache leases when the daemon stops ([#5378](https://github.com/hashgraph-online/hol-guard/issues/5378)) ([854d079](https://github.com/hashgraph-online/hol-guard/commit/854d079234f43c2e95de45e4ad14165cfc3e9892))
* **daemon:** send a hook decision that finished after its deadline ([#5172](https://github.com/hashgraph-online/hol-guard/issues/5172)) ([4148fc2](https://github.com/hashgraph-online/hol-guard/commit/4148fc29994be20bf60f44364475cf261287c917))
* **dashboard:** explain remote connectors and expired sessions on the connector card ([#5156](https://github.com/hashgraph-online/hol-guard/issues/5156)) ([8d8056e](https://github.com/hashgraph-online/hol-guard/commit/8d8056e9db47d039da98c6b050e6e27d5cb3c28b))
* **dashboard:** repeat the sponsor slot every ten extensions in the catalog feed ([#5045](https://github.com/hashgraph-online/hol-guard/issues/5045)) ([acfc8b2](https://github.com/hashgraph-online/hol-guard/commit/acfc8b2c991b322fc12cd7de1d7fe874c589d3cc))
* **desktop:** pin generated extensions to the current Desktop core and stop a superseded CLI early ([#5224](https://github.com/hashgraph-online/hol-guard/issues/5224)) ([d37c82e](https://github.com/hashgraph-online/hol-guard/commit/d37c82e32350a47e4befacd6042aee94071b2f50))
* **detect:** find MCP servers in ~/.claude.json and Oh My Pi's mcp.json ([#5206](https://github.com/hashgraph-online/hol-guard/issues/5206)) ([865d4d0](https://github.com/hashgraph-online/hol-guard/commit/865d4d05eb8fa3fbe3e00eea6b27b737c7c9ed23))
* **extensions:** compile raw sources without a corpus envelope ([2b7649a](https://github.com/hashgraph-online/hol-guard/commit/2b7649af7ca73f29d0f41e50b37b9f61bad48751))
* **gate:** count the pre-tool restricted-command screens as runtime code ([#5244](https://github.com/hashgraph-online/hol-guard/issues/5244)) ([b541273](https://github.com/hashgraph-online/hol-guard/commit/b54127398d05375834a863e754c3162dbeea3a3b))
* **gauntlet:** build the post-merge hook case's fixture shape ([#5284](https://github.com/hashgraph-online/hol-guard/issues/5284)) ([2a14ffc](https://github.com/hashgraph-online/hol-guard/commit/2a14ffc22d1de5b0533379bb88de11b4a3292201))
* **gauntlet:** give a case one stage directory instead of four ([#5374](https://github.com/hashgraph-online/hol-guard/issues/5374)) ([b4f9b06](https://github.com/hashgraph-online/hol-guard/commit/b4f9b06435251bf69add88f12f0b0c9e09d286f0))
* **gauntlet:** give the sibling a workflows directory to probe ([#5396](https://github.com/hashgraph-online/hol-guard/issues/5396)) ([3249f6b](https://github.com/hashgraph-online/hol-guard/commit/3249f6bd18d558cd929ca613503db47594d85d83))
* **gauntlet:** qualify against Oh My Pi 18.11.3 ([#5254](https://github.com/hashgraph-online/hol-guard/issues/5254)) ([de657cd](https://github.com/hashgraph-online/hol-guard/commit/de657cda43e298852750116db3449773b1674fce))
* **gauntlet:** refuse harness lanes whose runner cannot resolve its OS account ([#5185](https://github.com/hashgraph-online/hol-guard/issues/5185)) ([a11854f](https://github.com/hashgraph-online/hol-guard/commit/a11854fe1ae7762b39a41fcf59d3562df550e1fb))
* **gauntlet:** report a provider route that died during a run ([#5355](https://github.com/hashgraph-online/hol-guard/issues/5355)) ([11b4117](https://github.com/hashgraph-online/hol-guard/commit/11b4117de1048e2fffd2e2a75898cb9ea2249659))
* **gauntlet:** set up extension-control cases through the control service ([#5373](https://github.com/hashgraph-online/hol-guard/issues/5373)) ([2b346e3](https://github.com/hashgraph-online/hol-guard/commit/2b346e349c64e27e1fa2b49c86f993056cdd43d5))
* **gauntlet:** stop counting a stopped call's output scan as a second stop ([#5390](https://github.com/hashgraph-online/hol-guard/issues/5390)) ([a79ee81](https://github.com/hashgraph-online/hol-guard/commit/a79ee81e3ad36dc755896758fd37a7270ef9733a))
* **grants:** let an allowed CLI lift only a review Guard raised for an unknown program ([#5148](https://github.com/hashgraph-online/hol-guard/issues/5148)) ([21cf544](https://github.com/hashgraph-online/hol-guard/commit/21cf54428d8bd2a234472cebadaabc682b5f997b))
* **guard:** allow OMP grep path globs below a proven folder ([#5394](https://github.com/hashgraph-online/hol-guard/issues/5394)) ([fc72ec3](https://github.com/hashgraph-online/hol-guard/commit/fc72ec344515462d2e24e37791b47111392d7343))
* **guard:** answer a file test for a name and a path a read screen holds back ([#5026](https://github.com/hashgraph-online/hol-guard/issues/5026)) ([ffa0eaa](https://github.com/hashgraph-online/hol-guard/commit/ffa0eaa6ac9a1ca8daaa18cc587937dbd501cfd5))
* **guard:** answer a queued hint from the caller's shell, not the daemon's ([#5032](https://github.com/hashgraph-online/hol-guard/issues/5032)) ([20d5317](https://github.com/hashgraph-online/hol-guard/commit/20d5317ae9d93d5bdb8eb41582950dcdfdda60c4))
* **guard:** bind one-time approval to env-prefixed commands and mark rows that cannot unlock ([#5079](https://github.com/hashgraph-online/hol-guard/issues/5079)) ([b03fb8a](https://github.com/hashgraph-online/hol-guard/commit/b03fb8ac53cbaa8ba0bdf50181dac625c15132aa))
* **guard:** bring the Windows and Linux nightly native checks back to green ([#5075](https://github.com/hashgraph-online/hol-guard/issues/5075)) ([2dcf15f](https://github.com/hashgraph-online/hol-guard/commit/2dcf15f6c3d578790e9de878345b4042ac3a9a71))
* **guard:** clear the SonarCloud reliability findings on new code ([#5155](https://github.com/hashgraph-online/hol-guard/issues/5155)) ([3baabd6](https://github.com/hashgraph-online/hol-guard/commit/3baabd655c1ef738881205c794117a23cb709943))
* **guard:** contain a sibling build the agent spells from home ([#5035](https://github.com/hashgraph-online/hol-guard/issues/5035)) ([d831569](https://github.com/hashgraph-online/hol-guard/commit/d8315693c5f9325bd7050d09c38e24fc42812ab9))
* **guard:** contain Yarn and bare pnpm script runs like npm run ([#5055](https://github.com/hashgraph-online/hol-guard/issues/5055)) ([2ad8d29](https://github.com/hashgraph-online/hol-guard/commit/2ad8d29a9165f4647489f1968491d1120129742b))
* **guard:** give a stale tab its reload back when the user stays on the leave prompt ([#5264](https://github.com/hashgraph-online/hol-guard/issues/5264)) ([0de7c20](https://github.com/hashgraph-online/hol-guard/commit/0de7c206dadb502f02de878625599359573ffea8))
* **guard:** judge a bun shim script launch by the script, not its arguments' wording ([#5192](https://github.com/hashgraph-online/hol-guard/issues/5192)) ([982c7c5](https://github.com/hashgraph-online/hol-guard/commit/982c7c577054fb38342de8344cca2ded6e335bd9))
* **guard:** keep a review when the workspace sandbox cannot run the program ([#5066](https://github.com/hashgraph-online/hol-guard/issues/5066)) ([58baa65](https://github.com/hashgraph-online/hol-guard/commit/58baa65bfd296eb15a314f15e6792307aae5d980))
* **guard:** keep pack interface checks after the admission split ([#5119](https://github.com/hashgraph-online/hol-guard/issues/5119)) ([7a38b77](https://github.com/hashgraph-online/hol-guard/commit/7a38b77f32a6cbcbb03c8586b7f3e45fd46e612c))
* **guard:** keep Windows launch approvals reusable with a long PATH ([#5040](https://github.com/hashgraph-online/hol-guard/issues/5040)) ([6529eb9](https://github.com/hashgraph-online/hol-guard/commit/6529eb95140759bae3e1500bd4cad5ff08b611bf))
* **guard:** let every review be approved with Allow once or Always allow ([#5125](https://github.com/hashgraph-online/hol-guard/issues/5125)) ([c23110e](https://github.com/hashgraph-online/hol-guard/commit/c23110e162f5ed28aca9f0d685d6973e64c3f573))
* **guard:** let git blame, describe and reflog read history without review ([#5043](https://github.com/hashgraph-online/hol-guard/issues/5043)) ([848feec](https://github.com/hashgraph-online/hol-guard/commit/848feec23e0203429ba930a62ff1ceffec266b32))
* **guard:** let pip print installed package metadata without review ([#5089](https://github.com/hashgraph-online/hol-guard/issues/5089)) ([8ddc4d9](https://github.com/hashgraph-online/hol-guard/commit/8ddc4d9a3690a9cad299de2c8d99f23462cf5cac))
* **guard:** let the native runtime name the action a tool call enforces ([#5027](https://github.com/hashgraph-online/hol-guard/issues/5027)) ([f02f139](https://github.com/hashgraph-online/hol-guard/commit/f02f1396e75d0e5417a396f22162dad2f20be2d8))
* **guard:** let writes into framework build output pass in sibling checkouts ([#5092](https://github.com/hashgraph-online/hol-guard/issues/5092)) ([87e09cb](https://github.com/hashgraph-online/hol-guard/commit/87e09cb5f6c761148393eafcc7fcd54cafea600f))
* **guard:** make a local CLI or script setup review an ordinary approvable review ([#5197](https://github.com/hashgraph-online/hol-guard/issues/5197)) ([eed5310](https://github.com/hashgraph-online/hol-guard/commit/eed5310d3b6d1990849b26f05cdb7de90dae44f6))
* **guard:** prove the Git tag listing and clean preview as reads ([#5044](https://github.com/hashgraph-online/hol-guard/issues/5044)) ([ac5359a](https://github.com/hashgraph-online/hol-guard/commit/ac5359a2f12653595049f9ab2afc1d227a5eb32c))
* **guard:** read a braced parameter expansion as the value it is ([#5036](https://github.com/hashgraph-online/hol-guard/issues/5036)) ([87c737d](https://github.com/hashgraph-online/hol-guard/commit/87c737d997a3be74bbc50da5977792be0ee74874))
* **guard:** read a command written inside a double-quoted brace ([#5038](https://github.com/hashgraph-online/hol-guard/issues/5038)) ([1e1145f](https://github.com/hashgraph-online/hol-guard/commit/1e1145f18e2b121bfb4f1a03b2c6c2850e400eb0))
* **guard:** read a fetch dry run as the refresh it describes ([#5108](https://github.com/hashgraph-online/hol-guard/issues/5108)) ([bfeba74](https://github.com/hashgraph-online/hol-guard/commit/bfeba74b76ea93e796f63520743288a2fe7de637))
* **guard:** read a piped rg as the filter it is, not a walk of the tree ([#5028](https://github.com/hashgraph-online/hol-guard/issues/5028)) ([bf71b74](https://github.com/hashgraph-online/hol-guard/commit/bf71b74784d2ad640166b559cdfdd87c79415c2e))
* **guard:** read a process id beside a quoted word the way the shell reads it ([#5106](https://github.com/hashgraph-online/hol-guard/issues/5106)) ([d6971cc](https://github.com/hashgraph-online/hol-guard/commit/d6971cc9a93b0cbe00b7bc525b9b971dfd98563b))
* **guard:** read a project's own dotfile as the document it is ([#5025](https://github.com/hashgraph-online/hol-guard/issues/5025)) ([8fe97d2](https://github.com/hashgraph-online/hol-guard/commit/8fe97d2f0ab005615311abdd9027791483af01c6))
* **guard:** read a word spelled with ANSI-C escapes ([#5041](https://github.com/hashgraph-online/hol-guard/issues/5041)) ([7962220](https://github.com/hashgraph-online/hol-guard/commit/796222008c76a34feaf1415e0d11774a87ea12f9))
* **guard:** read the program a scheduling prefix runs ([#5037](https://github.com/hashgraph-online/hol-guard/issues/5037)) ([a89e162](https://github.com/hashgraph-online/hol-guard/commit/a89e162d8e3460386a5d5c7898fb8d4f993fc960))
* **guard:** read Windows machine policy from the registry natively ([#5039](https://github.com/hashgraph-online/hol-guard/issues/5039)) ([2d74e89](https://github.com/hashgraph-online/hol-guard/commit/2d74e89cb2e27a3b89bda0ab13b52c6747988a68))
* **guard:** recover a stalled native resident inside the hook's own wait ([#5199](https://github.com/hashgraph-online/hol-guard/issues/5199)) ([68daed0](https://github.com/hashgraph-online/hol-guard/commit/68daed01ebd31f8b5501250b3fa80739b021e106))
* **guard:** release an approved Oh My Pi learn that also writes a skill ([#5060](https://github.com/hashgraph-online/hol-guard/issues/5060)) ([27d2027](https://github.com/hashgraph-online/hol-guard/commit/27d202794c36c0a675e3b096a839979dab49f465)), closes [#4986](https://github.com/hashgraph-online/hol-guard/issues/4986)
* **guard:** reload dashboard tabs left on a bundle from before an update ([#5051](https://github.com/hashgraph-online/hol-guard/issues/5051)) ([c202cd5](https://github.com/hashgraph-online/hol-guard/commit/c202cd51dc7fb936973b7137f47a30cb8cea93f6))
* **guard:** retry transient native policy publication within a hook's wait ([#5188](https://github.com/hashgraph-online/hol-guard/issues/5188)) ([9b48586](https://github.com/hashgraph-online/hol-guard/commit/9b485861cf60b8df18a4b30db7f9066ea6ae4cdb))
* **guard:** route a package script by its body, not its name ([#5067](https://github.com/hashgraph-online/hol-guard/issues/5067)) ([90afae7](https://github.com/hashgraph-online/hol-guard/commit/90afae72c817688983c4ee47477562a6e03d1036))
* **guard:** run a Prettier format check inside read-only containment ([#5057](https://github.com/hashgraph-online/hol-guard/issues/5057)) ([9db23c2](https://github.com/hashgraph-online/hol-guard/commit/9db23c2fd59c4de75b42dfe22d2d179d98fe3ddf))
* **guard:** run lint, typecheck and format checks contained on Windows ([#5183](https://github.com/hashgraph-online/hol-guard/issues/5183)) ([8783aa4](https://github.com/hashgraph-online/hol-guard/commit/8783aa47ffcf9115270aa06b56b8e8b9b2f62518))
* **guard:** say what the workspace sandbox blocked when a contained run fails ([#5069](https://github.com/hashgraph-online/hol-guard/issues/5069)) ([4d1be00](https://github.com/hashgraph-online/hol-guard/commit/4d1be002abcc00ffd61b6a024e41168d10ee56c1))
* **guard:** stop withholding clean tool output over an unlisted tool name or a prose credential answer ([#5328](https://github.com/hashgraph-online/hol-guard/issues/5328)) ([6e32496](https://github.com/hashgraph-online/hol-guard/commit/6e3249682d0ae3e06f2dc80c9d8d5bd337b18b03))
* **guard:** tell the pre-tool lane where the command runs ([#5023](https://github.com/hashgraph-online/hol-guard/issues/5023)) ([a26b875](https://github.com/hashgraph-online/hol-guard/commit/a26b8752d9495417563d37a1c9782a6b39e9586c))
* **guard:** treat the approval queue and retry hint reads as read-only ([#5081](https://github.com/hashgraph-online/hol-guard/issues/5081)) ([c241cbf](https://github.com/hashgraph-online/hol-guard/commit/c241cbf916ea43c311a375ad570df8146019ebca))
* **guard:** wait out an extension control change that lands mid-publish ([#5375](https://github.com/hashgraph-online/hol-guard/issues/5375)) ([184f68a](https://github.com/hashgraph-online/hol-guard/commit/184f68af24614845e52e84964d60cfc504c0a135))
* **hook:** a review with no deadline is not a review that is out of time ([#5234](https://github.com/hashgraph-online/hol-guard/issues/5234)) ([d02a819](https://github.com/hashgraph-online/hol-guard/commit/d02a8196137c8263b835168eb6170dcd45ce2dde))
* **hook:** let the output review say whether it withheld the output ([#5261](https://github.com/hashgraph-online/hol-guard/issues/5261)) ([5f73e23](https://github.com/hashgraph-online/hol-guard/commit/5f73e23fbe4c57d9b4e9ce69fab1ee737e8a2fd9))
* **hooks:** keep approval links out of default-mode connector setup reasons ([#5070](https://github.com/hashgraph-online/hol-guard/issues/5070)) ([1ba6ad3](https://github.com/hashgraph-online/hol-guard/commit/1ba6ad334d7f3d62ab826eb0bfe6ee4b758f901f))
* **hooks:** wait out a policy update instead of failing the hook ([#5068](https://github.com/hashgraph-online/hol-guard/issues/5068)) ([c9a6a4d](https://github.com/hashgraph-online/hol-guard/commit/c9a6a4d382178eb91d0dd2adf2210b3caabb2a05))
* **inventory:** forget a remote connector's origin once its config entry is removed ([#5164](https://github.com/hashgraph-online/hol-guard/issues/5164)) ([be14d45](https://github.com/hashgraph-online/hol-guard/commit/be14d45541c180f1c18ef8da9dc44e0833a81ce1))
* **mcp:** list Oh My Pi tools whose names flatten the server's dashes ([#5251](https://github.com/hashgraph-online/hol-guard/issues/5251)) ([5c9be3b](https://github.com/hashgraph-online/hol-guard/commit/5c9be3b866ee2da6f329bc8b7a5774f6acf048b5))
* **mcp:** show a remote server's endpoint in mcp list when it was first seen through its calls ([#5151](https://github.com/hashgraph-online/hol-guard/issues/5151)) ([e18ab85](https://github.com/hashgraph-online/hol-guard/commit/e18ab85dee91b1b2dbe1ba9b3e997457cb769f86))
* **native:** let Guard store calls wait out their own deadline ([#5384](https://github.com/hashgraph-online/hol-guard/issues/5384)) ([081e58a](https://github.com/hashgraph-online/hol-guard/commit/081e58a9ea9270b49c8d4ce0431f07cb58ade874))
* **native:** model a plain `sh -c` script on Windows too ([#5126](https://github.com/hashgraph-online/hol-guard/issues/5126)) ([d263ea3](https://github.com/hashgraph-online/hol-guard/commit/d263ea3a0fb3ccd0bb7ecfaa4b42629640a32a7d))
* **native:** model a shell's inline script instead of blocking it unapprovably ([#5088](https://github.com/hashgraph-online/hol-guard/issues/5088)) ([f83badb](https://github.com/hashgraph-online/hol-guard/commit/f83badb1d45ed9db1c62ba34736cd54889b78a2f))
* **package:** reuse saved allows of any scope, and review packages by risk instead of by default ([#5250](https://github.com/hashgraph-online/hol-guard/issues/5250)) ([6b484cc](https://github.com/hashgraph-online/hol-guard/commit/6b484cc60df11dba565bcb8ef3011dc0c2bb8fbb))
* **packages:** keep the npm scope in package review messages ([#5049](https://github.com/hashgraph-online/hol-guard/issues/5049)) ([cddce95](https://github.com/hashgraph-online/hol-guard/commit/cddce95a6121ac3c386cf5b125483a410a938b43))
* **pi:** tell the agent why its tool output was withheld ([#5204](https://github.com/hashgraph-online/hol-guard/issues/5204)) ([8d238bf](https://github.com/hashgraph-online/hol-guard/commit/8d238bf5b8d8dfc362542d530a0de3d99500b467))
* **policy:** name the rule a rejected cloud policy bundle could not compile ([#5299](https://github.com/hashgraph-online/hol-guard/issues/5299)) ([87b3b4d](https://github.com/hashgraph-online/hol-guard/commit/87b3b4d7cd96d599c03cdf95924d54fb0a7eb27b))
* **posttool:** keep in-workspace feature folders listable ([#5281](https://github.com/hashgraph-online/hol-guard/issues/5281)) ([12a0843](https://github.com/hashgraph-online/hol-guard/commit/12a08431e9757b86831badb6db2b2f8d74c660db))
* **pretool:** a dependency link into a separate clone of the same repository stops reviewing ([#5229](https://github.com/hashgraph-online/hol-guard/issues/5229)) ([9a97fbe](https://github.com/hashgraph-online/hol-guard/commit/9a97fbefb825600f764295a3e090b17efcd208c7))
* **pretool:** admit rg --replace reads and read-only guard settings views ([#5189](https://github.com/hashgraph-online/hol-guard/issues/5189)) ([0c9305b](https://github.com/hashgraph-online/hol-guard/commit/0c9305b494a098ddf2ccb7fd4270b3574691c274))
* **pretool:** allow Oh My Pi github lookups as network reads ([#5210](https://github.com/hashgraph-online/hol-guard/issues/5210)) ([d9e6334](https://github.com/hashgraph-online/hol-guard/commit/d9e633491d38f62d66c40dfd59afd7d3a33c0836))
* **pretool:** answer a CLI presence probe from every bin directory ([#5129](https://github.com/hashgraph-online/hol-guard/issues/5129)) ([758c1a8](https://github.com/hashgraph-online/hol-guard/commit/758c1a89254b7b0b817cf0837791eee93689f3dd))
* **pretool:** build and test a Cargo package inside the workspace sandbox ([#5146](https://github.com/hashgraph-online/hol-guard/issues/5146)) ([a182c03](https://github.com/hashgraph-online/hol-guard/commit/a182c036d2cc6a892ad41775a9ed2b8d584b5e4c))
* **pretool:** build and test a Go module inside the sandbox ([#5145](https://github.com/hashgraph-online/hol-guard/issues/5145)) ([015daff](https://github.com/hashgraph-online/hol-guard/commit/015daffa2461ddd588130d971366d0aec8f94ab4))
* **pretool:** clear recursive searches whose pattern cannot match a sensitive file ([#5215](https://github.com/hashgraph-online/hol-guard/issues/5215)) ([3848995](https://github.com/hashgraph-online/hol-guard/commit/384899516c3bb97bc2e9fbccb37a34498422a4c9))
* **pretool:** filter a contained run's output with rg as well as grep ([#5127](https://github.com/hashgraph-online/hol-guard/issues/5127)) ([fa6e665](https://github.com/hashgraph-online/hol-guard/commit/fa6e665178eede38f92cc573bffc30a01b6add6e))
* **pretool:** judge a command after a virtualenv activation as the command alone ([#5247](https://github.com/hashgraph-online/hol-guard/issues/5247)) ([41f1429](https://github.com/hashgraph-online/hol-guard/commit/41f1429a92e196b5833c2483204dd92e9928baa1))
* **pretool:** keep /usr/sbin and /sbin on the workspace sandbox PATH ([#5277](https://github.com/hashgraph-online/hol-guard/issues/5277)) ([a5e5cc8](https://github.com/hashgraph-online/hol-guard/commit/a5e5cc8894f24f32c0405bd17f0364582178a599))
* **pretool:** keep a globbed gitignore negation instead of voiding the proof ([#5113](https://github.com/hashgraph-online/hol-guard/issues/5113)) ([6e2c9fc](https://github.com/hashgraph-online/hol-guard/commit/6e2c9fc030048a748182ab6bd981a3da95c823e4))
* **pretool:** keep plain git reads out of the approval inbox ([#5218](https://github.com/hashgraph-online/hol-guard/issues/5218)) ([197a55f](https://github.com/hashgraph-online/hol-guard/commit/197a55fd2e280316090f4623da375e6e18736d55))
* **pretool:** let a proven fast-forward merge of origin run without review ([#5245](https://github.com/hashgraph-online/hol-guard/issues/5245)) ([b53aa2d](https://github.com/hashgraph-online/hol-guard/commit/b53aa2dd867e56b9c779c71aa35709b446f0bc9c))
* **pretool:** let a read that names no file run without review ([#5240](https://github.com/hashgraph-online/hol-guard/issues/5240)) ([382221e](https://github.com/hashgraph-online/hol-guard/commit/382221e2c7d7426864f6885a9f163665cb46b59c))
* **pretool:** let a scratch-copy edit chain run without review ([#5226](https://github.com/hashgraph-online/hol-guard/issues/5226)) ([8f2045e](https://github.com/hashgraph-online/hol-guard/commit/8f2045e31e8fdc64e25f047fe2c7b48d43ad44af))
* **pretool:** let a search reach a repository's own sign-in code ([#5282](https://github.com/hashgraph-online/hol-guard/issues/5282)) ([b896bb8](https://github.com/hashgraph-online/hol-guard/commit/b896bb8e62921f3f640a3f65267b7942ac4a25b7))
* **pretool:** let a shared dependency link land in a directory already there ([#5228](https://github.com/hashgraph-online/hol-guard/issues/5228)) ([ae2cedf](https://github.com/hashgraph-online/hol-guard/commit/ae2cedf54e2b4ba7881eacec8b628661e8475905))
* **pretool:** let a sibling's Jest run with a heap size and probe a sibling's workflows without review ([#5275](https://github.com/hashgraph-online/hol-guard/issues/5275)) ([f1c2d07](https://github.com/hashgraph-online/hol-guard/commit/f1c2d075b61b90cbb9d0ce903ffa19cb39500c4b))
* **pretool:** let activating a virtualenv reach review ([#5165](https://github.com/hashgraph-online/hol-guard/issues/5165)) ([3d999ae](https://github.com/hashgraph-online/hol-guard/commit/3d999aeb5614fe60d5c51a2559719e4a5bc21d19))
* **pretool:** let an agent write plan notes under its own plans folder without review ([#5221](https://github.com/hashgraph-online/hol-guard/issues/5221)) ([4fcd437](https://github.com/hashgraph-online/hol-guard/commit/4fcd437c99ff41b4e63aedd9ea1a60bdf803d530))
* **pretool:** let dd print a slice of a readable file without review ([#5227](https://github.com/hashgraph-online/hol-guard/issues/5227)) ([6b85f00](https://github.com/hashgraph-online/hol-guard/commit/6b85f009ea1bd110919059d2dcecdd97b1edd1a5))
* **pretool:** let digest printers read the files they name ([#5121](https://github.com/hashgraph-online/hol-guard/issues/5121)) ([5645b68](https://github.com/hashgraph-online/hol-guard/commit/5645b68818baa9f7a229e794e89a4cda09199a9b))
* **pretool:** let the resident decide when a verified shim owns an archive download ([#5253](https://github.com/hashgraph-online/hol-guard/issues/5253)) ([2bc7c13](https://github.com/hashgraph-online/hol-guard/commit/2bc7c13e7eb1ae3c9af42f071650a807b23c519e))
* **pretool:** let the sibling search proof finish on a real repository ([#5222](https://github.com/hashgraph-online/hol-guard/issues/5222)) ([4005d79](https://github.com/hashgraph-online/hol-guard/commit/4005d793fc9baa742ccc41361bb81ab994eb5f89))
* **pretool:** list a neighbouring repository's files by name ([#5120](https://github.com/hashgraph-online/hol-guard/issues/5120)) ([65f3833](https://github.com/hashgraph-online/hol-guard/commit/65f38330257f4cc53cd8388c2060e7fac868e0e3))
* **pretool:** list the local builders and running compose projects as reads ([#5136](https://github.com/hashgraph-online/hol-guard/issues/5136)) ([0cd3913](https://github.com/hashgraph-online/hol-guard/commit/0cd39131fdb1446a0ebd83328c5341b383bd9c0c))
* **pretool:** prove locale, colour and shell-option settings read-only ([#5190](https://github.com/hashgraph-online/hol-guard/issues/5190)) ([d33692e](https://github.com/hashgraph-online/hol-guard/commit/d33692e08ffbf76db0f29ee4d1a0caa75b9f5b01))
* **pretool:** prove worktree add in repositories with large configs ([#5274](https://github.com/hashgraph-online/hol-guard/issues/5274)) ([754f206](https://github.com/hashgraph-online/hol-guard/commit/754f2066da35217ab064bd7c023df12149f46ba6))
* **pretool:** read a background job's output through proc:// without review ([#5201](https://github.com/hashgraph-online/hol-guard/issues/5201)) ([197feac](https://github.com/hashgraph-online/hol-guard/commit/197feac6f5047ca85b645a94c03103d149f3b348))
* **pretool:** read a bracketed route file as the path it names ([#5134](https://github.com/hashgraph-online/hol-guard/issues/5134)) ([9b8b712](https://github.com/hashgraph-online/hol-guard/commit/9b8b712048943850fa577dd80af394a679e377d9))
* **pretool:** read a Docker version banner as the listing it already allows ([#5117](https://github.com/hashgraph-online/hol-guard/issues/5117)) ([d02d4aa](https://github.com/hashgraph-online/hol-guard/commit/d02d4aaeeeb385ede12082a5260d7da039b448ca))
* **pretool:** read a loop body's bare name as the name something binds ([#5110](https://github.com/hashgraph-online/hol-guard/issues/5110)) ([825b7a2](https://github.com/hashgraph-online/hol-guard/commit/825b7a244f42b077ac08c5a45c3fcb8b09820c0c))
* **pretool:** read a loop rebinding as the word the shell builds ([#5102](https://github.com/hashgraph-online/hol-guard/issues/5102)) ([bcc0853](https://github.com/hashgraph-online/hol-guard/commit/bcc08536061b244aeddcfb38e538a88f75e119fb))
* **pretool:** read a name guessed inside a sibling repository ([#5138](https://github.com/hashgraph-online/hol-guard/issues/5138)) ([1836258](https://github.com/hashgraph-online/hol-guard/commit/1836258845664cd35e61fc69fd3fd59d7bb54c9d))
* **pretool:** read a redirected lookup as the lookup it is ([#5167](https://github.com/hashgraph-online/hol-guard/issues/5167)) ([c86ea16](https://github.com/hashgraph-online/hol-guard/commit/c86ea165ee539c9248a624ea6543e7e49de1aba8))
* **pretool:** read a repository's auth and token folders without review ([#5212](https://github.com/hashgraph-online/hol-guard/issues/5212)) ([6c52c8a](https://github.com/hashgraph-online/hol-guard/commit/6c52c8a363575d60bb40afa57239a8da0fc3ce15))
* **pretool:** read a sourced script's comments and dead wrappers as text ([#5168](https://github.com/hashgraph-online/hol-guard/issues/5168)) ([3e8abcb](https://github.com/hashgraph-online/hol-guard/commit/3e8abcbf66cd560b73dd10b9733c31a387e15741))
* **pretool:** read a stray file in a Node version directory as no config ([#5163](https://github.com/hashgraph-online/hol-guard/issues/5163)) ([9edc325](https://github.com/hashgraph-online/hol-guard/commit/9edc325b007514431e3342d16f4c6152bbfd0e89))
* **pretool:** read a tool's own script from its program directory ([#5133](https://github.com/hashgraph-online/hol-guard/issues/5133)) ([a5dd395](https://github.com/hashgraph-online/hol-guard/commit/a5dd3959961c003b3a7356ff08731e4f19ae0575))
* **pretool:** read an escaped operator on Windows as part of its word ([#5292](https://github.com/hashgraph-online/hol-guard/issues/5292)) ([013bde2](https://github.com/hashgraph-online/hol-guard/commit/013bde293cb7d1f12852cb74700883de7700b6ff))
* **pretool:** read back a server on the port the agent chose for it ([#5130](https://github.com/hashgraph-online/hol-guard/issues/5130)) ([9887781](https://github.com/hashgraph-online/hol-guard/commit/9887781f919642a0c75553f14f2ce41e6f6ef29a))
* **pretool:** read find operands as the words the shell hands the program ([#5100](https://github.com/hashgraph-online/hol-guard/issues/5100)) ([0710ab2](https://github.com/hashgraph-online/hol-guard/commit/0710ab215c9619cf1f20c22fdd1590143605e6cb))
* **pretool:** read npx's offline and quiet options as the options they are ([#5170](https://github.com/hashgraph-online/hol-guard/issues/5170)) ([012bc79](https://github.com/hashgraph-online/hol-guard/commit/012bc7965f5c56c0089b5c7bedc59a3b40bcbfc5))
* **pretool:** read plan notes with a discarded stderr without a review ([#5203](https://github.com/hashgraph-online/hol-guard/issues/5203)) ([b98186e](https://github.com/hashgraph-online/hol-guard/commit/b98186eff5e7685ad532ebcadb94c49454cda9d4))
* **pretool:** read scratch files in the macOS private temporary directory ([#5265](https://github.com/hashgraph-online/hol-guard/issues/5265)) ([8d79d83](https://github.com/hashgraph-online/hol-guard/commit/8d79d83b2151a5a6c711ccef4726bfa2b8a5b4ac))
* **pretool:** read scratch output staged in the private temporary directory ([#5393](https://github.com/hashgraph-online/hol-guard/issues/5393)) ([5190a35](https://github.com/hashgraph-online/hol-guard/commit/5190a3508554488ee52cf5bc8201dee5d0385e6c))
* **pretool:** read the globally installed npm tree without review ([#5131](https://github.com/hashgraph-online/hol-guard/issues/5131)) ([76ee227](https://github.com/hashgraph-online/hol-guard/commit/76ee22770a9eefdaa9a9946d3de660ce42dd6d15))
* **pretool:** rebase a branch onto a local ref without a review ([#5158](https://github.com/hashgraph-online/hol-guard/issues/5158)) ([2c85522](https://github.com/hashgraph-online/hol-guard/commit/2c855222d33b303780957660133b2f27db2c7eb9))
* **pretool:** review an env that names no program, contain the sealed macOS tool directories, and redact forwarded credentials from Gauntlet evidence ([#5259](https://github.com/hashgraph-online/hol-guard/issues/5259)) ([e59ee8f](https://github.com/hashgraph-online/hol-guard/commit/e59ee8f445fc1f0b5359bf2532a2fa5b61096704))
* **pretool:** run a project venv's python inside the workspace sandbox ([#5141](https://github.com/hashgraph-online/hol-guard/issues/5141)) ([7f06f81](https://github.com/hashgraph-online/hol-guard/commit/7f06f8165768a454f384e8f75cc366dc7b83d80d))
* **pretool:** run a version manager's shims inside the workspace sandbox ([#5140](https://github.com/hashgraph-online/hol-guard/issues/5140)) ([4a4faa9](https://github.com/hashgraph-online/hol-guard/commit/4a4faa9490de466e796fdffaaa06c0cb0e25baaa))
* **pretool:** run uv's local verbs inside the workspace sandbox ([#5143](https://github.com/hashgraph-online/hol-guard/issues/5143)) ([46376f6](https://github.com/hashgraph-online/hol-guard/commit/46376f691ab3e4f322d012bfdfccf8778e5507ca))
* **pretool:** screen .npmrc keys the way npm reads them ([#5101](https://github.com/hashgraph-online/hol-guard/issues/5101)) ([3a07a23](https://github.com/hashgraph-online/hol-guard/commit/3a07a23c3c237900da0254b624834ed5aefb95da))
* **pretool:** search a bracketed route as the path it names ([#5115](https://github.com/hashgraph-online/hol-guard/issues/5115)) ([41cf5fc](https://github.com/hashgraph-online/hol-guard/commit/41cf5fc8be161124af8282068d9a4fdaac030a19))
* **pretool:** search a bracketed route directory with fd as the path it names ([#5135](https://github.com/hashgraph-online/hol-guard/issues/5135)) ([92f14ad](https://github.com/hashgraph-online/hol-guard/commit/92f14ada44989d0f9469f73a9e11183e6b33bc7b))
* **pretool:** search a sibling repository's bracketed route ([#5128](https://github.com/hashgraph-online/hol-guard/issues/5128)) ([bec7464](https://github.com/hashgraph-online/hol-guard/commit/bec74642e0c238e56112fca1219cb5e02a302188))
* **pretool:** stop typing a tool's query argument as a model prompt ([#5186](https://github.com/hashgraph-online/hol-guard/issues/5186)) ([f280bad](https://github.com/hashgraph-online/hol-guard/commit/f280badfdd4ff2c27e7f05f6d1fe06fbb6e2938c))
* **pretool:** treat a docker buildx imagetools inspect registry query as a read ([#5198](https://github.com/hashgraph-online/hol-guard/issues/5198)) ([159a34e](https://github.com/hashgraph-online/hol-guard/commit/159a34ebd9146ee6f6e96e0c5ba1481cb54152ae))
* **pretool:** treat a repository beside the session folder as the workspace for file writes ([#5200](https://github.com/hashgraph-online/hol-guard/issues/5200)) ([e9fc4c9](https://github.com/hashgraph-online/hol-guard/commit/e9fc4c92c021218d94f198a5ccc5f25c8f6f55ab))
* **pretool:** worktree add and origin fetch stop reviewing ordinary developer git config ([#5214](https://github.com/hashgraph-online/hol-guard/issues/5214)) ([a71eeb3](https://github.com/hashgraph-online/hol-guard/commit/a71eeb3415154fd60980e51b48f9a122dc228ac4))
* **pretool:** write a sibling clone from a home spelled through a symlink ([#5387](https://github.com/hashgraph-online/hol-guard/issues/5387)) ([1d8fddb](https://github.com/hashgraph-online/hol-guard/commit/1d8fddbfcdaa67250d4c1cfd5ee3006561c1051a))
* **runtime:** ignore an exited resident's state when probing the owner lock ([#5162](https://github.com/hashgraph-online/hol-guard/issues/5162)) ([c4a17c7](https://github.com/hashgraph-online/hol-guard/commit/c4a17c798ac6aa81f60dddb8502251e40870757b))
* **runtime:** keep the agent's home when Guard runs ordinary work in its sandbox ([#5184](https://github.com/hashgraph-online/hol-guard/issues/5184)) ([9a229c3](https://github.com/hashgraph-online/hol-guard/commit/9a229c39a7fce063d99cf4ca453e3ca90f3eb3bb))
* **runtime:** keep the supervisor exit hold on Windows only ([#5249](https://github.com/hashgraph-online/hol-guard/issues/5249)) ([514d534](https://github.com/hashgraph-online/hol-guard/commit/514d534ccfcbdcbf05e1d994ff5f5136e44771d4))
* **runtime:** let a harness read prove its own output read-only ([#5195](https://github.com/hashgraph-online/hol-guard/issues/5195)) ([42b387b](https://github.com/hashgraph-online/hol-guard/commit/42b387ba578939a3b5586a6c963d423d01eee7d6))
* **runtime:** let a write probe remove the directory it created ([#5095](https://github.com/hashgraph-online/hol-guard/issues/5095)) ([baa4b6f](https://github.com/hashgraph-online/hol-guard/commit/baa4b6f186f87adbac1fc3efd0933c766a9be716))
* **runtime:** let the supervisor finish its exit record before a stop removes the scope ([#5217](https://github.com/hashgraph-online/hol-guard/issues/5217)) ([d1f6153](https://github.com/hashgraph-online/hol-guard/commit/d1f61531f05d0015b772c2805a473fe5ce354c78))
* **runtime:** read a task result schema's field names as labels, not credential arguments ([#5205](https://github.com/hashgraph-online/hol-guard/issues/5205)) ([ea6c7d3](https://github.com/hashgraph-online/hol-guard/commit/ea6c7d32aa605ee0839df670a6bc9d81ae01723f))
* **runtime:** recognize a bounded local bun script chain in the resident ([#5283](https://github.com/hashgraph-online/hol-guard/issues/5283)) ([b902d0f](https://github.com/hashgraph-online/hol-guard/commit/b902d0f70ed582c4612315d7c6c338f80171acda))
* **runtime:** record resident discovery counts in native diagnostics ([#5347](https://github.com/hashgraph-online/hol-guard/issues/5347)) ([9d8e21e](https://github.com/hashgraph-online/hol-guard/commit/9d8e21edf470908cd2f5a9643b46ead34a5dc55a))
* **runtime:** remove the source compiler's temporary copy on Windows ([#5356](https://github.com/hashgraph-online/hol-guard/issues/5356)) ([c6a1fda](https://github.com/hashgraph-online/hol-guard/commit/c6a1fda212c9cc0a034dbb7534f62e667e312d61))
* **runtime:** report a closed Codex app-server socket the way Python does ([#5338](https://github.com/hashgraph-online/hol-guard/issues/5338)) ([62f34af](https://github.com/hashgraph-online/hol-guard/commit/62f34af156bc867ab9febdbbd3223473cff4f88e))
* **runtime:** report a held pack cache busy on Windows instead of invalid ([#5365](https://github.com/hashgraph-online/hol-guard/issues/5365)) ([4700ceb](https://github.com/hashgraph-online/hol-guard/commit/4700ceb28ef290be002d07cf861849953c89ae45))
* **runtime:** stop a busy authority lease from reading as lost protection ([#5179](https://github.com/hashgraph-online/hol-guard/issues/5179)) ([f21039b](https://github.com/hashgraph-online/hol-guard/commit/f21039b2425acd4890552120e188265854696522))
* **runtime:** stop a second Guard install from tripping the resident restart circuit ([#5150](https://github.com/hashgraph-online/hol-guard/issues/5150)) ([ea18a79](https://github.com/hashgraph-online/hol-guard/commit/ea18a792903bd749aff22fa6ca34a2f2a02915ba))
* **runtime:** stop counting an orderly resident cycle as a restart ([#5182](https://github.com/hashgraph-online/hol-guard/issues/5182)) ([5ead1ed](https://github.com/hashgraph-online/hol-guard/commit/5ead1ed980bd6109ae0e8789e25fdfd582b8d338))
* **runtime:** stop the daemon spawning native checks every second after an extension is enabled ([#5367](https://github.com/hashgraph-online/hol-guard/issues/5367)) ([be2a206](https://github.com/hashgraph-online/hol-guard/commit/be2a206e7ee9e9005214996d9ad2b2b30d1f1cdf))
* **runtime:** stop the evidence worker deadlocking on its own state lock ([#5169](https://github.com/hashgraph-online/hol-guard/issues/5169)) ([ff43c32](https://github.com/hashgraph-online/hol-guard/commit/ff43c32e9d260f6028d6dd62123b3ad6acaa0398))
* **runtime:** stop turning a busy host into an approval row ([#5202](https://github.com/hashgraph-online/hol-guard/issues/5202)) ([f273b41](https://github.com/hashgraph-online/hol-guard/commit/f273b415137daf102feea65a0ccf867bbf7684d4))
* **runtime:** wait out a briefly held restart budget lock on Windows ([#5344](https://github.com/hashgraph-online/hol-guard/issues/5344)) ([dece3c2](https://github.com/hashgraph-online/hol-guard/commit/dece3c28e523875d3aa2f498e34120a6aaea70c5))
* **runtime:** walk directories in a deterministic order ([#5287](https://github.com/hashgraph-online/hol-guard/issues/5287)) ([be29e4d](https://github.com/hashgraph-online/hol-guard/commit/be29e4dbfe308ec67a6a1bfb10b1e275c4c8618a))
* **scanner:** distinguish embedded secrets from runtime access ([#3807](https://github.com/hashgraph-online/hol-guard/issues/3807)) ([2d2f350](https://github.com/hashgraph-online/hol-guard/commit/2d2f350c3bae2e91d19d62a6cdc2dc0e73d4d234))
* **scanner:** don't treat Guard's own approval link as a credential ([#5194](https://github.com/hashgraph-online/hol-guard/issues/5194)) ([d60a7ad](https://github.com/hashgraph-online/hol-guard/commit/d60a7ad0b29412eb7a83ef27f07b0c058d587ec9))
* **scanner:** pin guarded-repository action with secret boundary fix ([#3464](https://github.com/hashgraph-online/hol-guard/issues/3464)) ([a4eff88](https://github.com/hashgraph-online/hol-guard/commit/a4eff88843dfda2f366a89cc8433ebd694a36c95))
* **scanner:** stop flagging token-handling source as a leaked credential ([#5187](https://github.com/hashgraph-online/hol-guard/issues/5187)) ([990f6af](https://github.com/hashgraph-online/hol-guard/commit/990f6afc54676217088a58abbd1c332e6e623e54))
* **storage:** start a review store call's own budget once the gate is held ([#5236](https://github.com/hashgraph-online/hol-guard/issues/5236)) ([562ef28](https://github.com/hashgraph-online/hol-guard/commit/562ef285ba31dac124dae49af4154c2a7a7f71b2))
* **storage:** take a real shared storage gate on Windows ([#5181](https://github.com/hashgraph-online/hol-guard/issues/5181)) ([232db02](https://github.com/hashgraph-online/hol-guard/commit/232db02e8af59df9407afa40133307403a87860b))
* **tests:** compile the frozen v4 schema fixture under its real path ([#5272](https://github.com/hashgraph-online/hol-guard/issues/5272)) ([8de2fb9](https://github.com/hashgraph-online/hol-guard/commit/8de2fb9c3c9e25b69e95c283fdad4ed4c638cc0f))
* **unmodeled:** read a sourced file's quoted assignment as one word ([#5171](https://github.com/hashgraph-online/hol-guard/issues/5171)) ([99c0323](https://github.com/hashgraph-online/hol-guard/commit/99c0323270074df846b2293f875f61ad12ce8fe4))


### Performance Improvements

* **ci:** cache offline-upgrade baseline and isolate native runtime cache keys ([#5398](https://github.com/hashgraph-online/hol-guard/issues/5398)) ([090d2ba](https://github.com/hashgraph-online/hol-guard/commit/090d2ba95581a872b7c0dbd8797b3fd505e5dcc2))
* **compiler:** reuse authenticated packs across fresh builds ([#5137](https://github.com/hashgraph-online/hol-guard/issues/5137)) ([01328b1](https://github.com/hashgraph-online/hol-guard/commit/01328b154556879cf7f9dad3ebf85aa3f83c698a))
* **extensions:** index active rules and reuse matcher memo storage ([#5111](https://github.com/hashgraph-online/hol-guard/issues/5111)) ([43f506c](https://github.com/hashgraph-online/hol-guard/commit/43f506cba5344fb2b7af8f1e27e5b3a30f82c500))
* **guard:** admit the embedded command program without re-proving its build checks ([#5086](https://github.com/hashgraph-online/hol-guard/issues/5086)) ([dcecb7f](https://github.com/hashgraph-online/hol-guard/commit/dcecb7fbeae571ca8339d687b60737fb6976f3e3))
* **guard:** hash the resident runtime with hardware SHA-256 ([#5059](https://github.com/hashgraph-online/hol-guard/issues/5059)) ([f18c2f0](https://github.com/hashgraph-online/hol-guard/commit/f18c2f076837594422bc08c1ef63503d26bec822))
* **guard:** load the packaged command program during resident self-check ([#5064](https://github.com/hashgraph-online/hol-guard/issues/5064)) ([eb39481](https://github.com/hashgraph-online/hol-guard/commit/eb394817e19f7df6edadd42b6ff3a7778cfc8a77))
* **hook:** compose a hook's tool-action verdict once instead of twice ([#5258](https://github.com/hashgraph-online/hol-guard/issues/5258)) ([68f91b7](https://github.com/hashgraph-online/hol-guard/commit/68f91b759ade0b69134af2225440f16b2529c3a5))
* **native:** build cold-path crates for size ([#5288](https://github.com/hashgraph-online/hol-guard/issues/5288)) ([f9549c2](https://github.com/hashgraph-online/hol-guard/commit/f9549c2f8f67b876abc305040de301dceb81ef85))
* **native:** reuse the verified runtime copy for the life of the process ([#5376](https://github.com/hashgraph-online/hol-guard/issues/5376)) ([947a005](https://github.com/hashgraph-online/hol-guard/commit/947a005d0023b53b17a1590ba6aa7da4a48bf51b))
* **runtime:** look up resident process images directly on Windows ([#5053](https://github.com/hashgraph-online/hol-guard/issues/5053)) ([3d1328a](https://github.com/hashgraph-online/hol-guard/commit/3d1328a80438b68fe1348df8119bb7a4bc6e2901))


### Dependencies

* **actions:** bump devcontainers/action from 1.4.3 to 1.4.4 ([#5243](https://github.com/hashgraph-online/hol-guard/issues/5243)) ([7bc8258](https://github.com/hashgraph-online/hol-guard/commit/7bc8258a6cf69a9a16254b9e620335fdae6a5830))
* bump aiohttp to 3.14.4 for the request timeout advisory ([#5289](https://github.com/hashgraph-online/hol-guard/issues/5289)) ([4914365](https://github.com/hashgraph-online/hol-guard/commit/491436512ada08d1e0e0252d98a49db70cf23fc1))
* **pip:** bump the codex-lab-patch-minor group across 1 directory with 2 updates ([#5242](https://github.com/hashgraph-online/hol-guard/issues/5242)) ([4d23403](https://github.com/hashgraph-online/hol-guard/commit/4d23403a9dc8a183323e1620bcaecf29bedc7ed5))


### Documentation

* **guard:** state what Guard enforces on Windows ([#5293](https://github.com/hashgraph-online/hol-guard/issues/5293)) ([e05eb0f](https://github.com/hashgraph-online/hol-guard/commit/e05eb0fa4512b6616c1b90ef86fa5ee7f5ef43b0))
* **security:** record the reviewed hook bridge argv disposition ([#5276](https://github.com/hashgraph-online/hol-guard/issues/5276)) ([2c7ee8a](https://github.com/hashgraph-online/hol-guard/commit/2c7ee8a71ef4f9e12b332921e0432d15c9109a1b))

## [3.49.0](https://github.com/hashgraph-online/hol-guard/compare/v3.48.0...v3.49.0) (2026-10-17)


### Features

* **guard:** add extensions list and mcp list inventory commands ([#5022](https://github.com/hashgraph-online/hol-guard/issues/5022)) ([bb05a30](https://github.com/hashgraph-online/hol-guard/commit/bb05a30258932a24dca5e30719288c07e2a0e6e2))
* **guard:** decide relayed package calls in the native runtime ([#5017](https://github.com/hashgraph-online/hol-guard/issues/5017)) ([512b92f](https://github.com/hashgraph-online/hol-guard/commit/512b92f070cdbf5c6513ceb3f03cef7ddebc49dd))


### Bug Fixes

* **guard:** copy a local repository without an approval ([#5020](https://github.com/hashgraph-online/hol-guard/issues/5020)) ([f766b0b](https://github.com/hashgraph-online/hol-guard/commit/f766b0b8157e5383f5d545f6244cd5c7a3634ec5))
* **guard:** let a sibling search answer for the files it actually reads ([#5005](https://github.com/hashgraph-online/hol-guard/issues/5005)) ([a2e237d](https://github.com/hashgraph-online/hol-guard/commit/a2e237dfb80d1d82eb804474008f8ae6cb547f65))
* **guard:** search a neighbouring repository with grep, not only with rg ([#5011](https://github.com/hashgraph-online/hol-guard/issues/5011)) ([c295801](https://github.com/hashgraph-online/hol-guard/commit/c295801baa5f8f65893a99ae3ddf41345e825cb3))

## [3.48.0](https://github.com/hashgraph-online/hol-guard/compare/v3.47.0...v3.48.0) (2026-10-17)


### Features

* Add DeArmour command extension ([#3073](https://github.com/hashgraph-online/hol-guard/issues/3073)) ([c8b2de9](https://github.com/hashgraph-online/hol-guard/commit/c8b2de9de00975a8afb5562d479c01792cccecb9))
* **dashboard:** search, filter, sort and group custom extension scripts and commands ([#5002](https://github.com/hashgraph-online/hol-guard/issues/5002)) ([17d952c](https://github.com/hashgraph-online/hol-guard/commit/17d952ca24307ebc1700ebb5873e5527d1a32c41))
* **extension:** add command.hashdup extension for HashDup CLI ([#3018](https://github.com/hashgraph-online/hol-guard/issues/3018)) ([eb56d5d](https://github.com/hashgraph-online/hol-guard/commit/eb56d5d5586c65ffb1dba09fef60ae3701a11cee))
* **extensions:** add kindling command source ([#3277](https://github.com/hashgraph-online/hol-guard/issues/3277)) ([3039dcf](https://github.com/hashgraph-online/hol-guard/commit/3039dcf5c4742e764e788cf2fe5d1823f001b272))
* **guard:** report fleet posture (Guard version, OS, AI-tool protection, inventory, policy ack) to Guard Cloud ([e3b4358](https://github.com/hashgraph-online/hol-guard/commit/e3b435860efc4ca902f1a3eb5b5ca06a681012e8))
* **mcp:** add PC-Control MCP server contribution ([#4320](https://github.com/hashgraph-online/hol-guard/issues/4320)) ([e621a7b](https://github.com/hashgraph-online/hol-guard/commit/e621a7b2975eb34ee96543c7a7d512009e97601d))


### Bug Fixes

* **daemon:** retry the Windows daemon-state replace while a reader holds the file ([#5021](https://github.com/hashgraph-online/hol-guard/issues/5021)) ([5091996](https://github.com/hashgraph-online/hol-guard/commit/5091996e61163ca422e21be524022b33935f104d))
* **guard:** bind one-time ssh push approvals on hosts with XQuartz ([#4999](https://github.com/hashgraph-online/hol-guard/issues/4999)) ([27f8143](https://github.com/hashgraph-online/hol-guard/commit/27f814337a2f34cb6ff49d6b50db223a5345ac6a))
* **guard:** end the extension policy conflict dead-end ([#5000](https://github.com/hashgraph-online/hol-guard/issues/5000)) ([bcee8a8](https://github.com/hashgraph-online/hol-guard/commit/bcee8a81200997786d5ef3c316f50d034e0140a0))
* **guard:** keep the output of a toolchain package read under a hidden home directory ([#5019](https://github.com/hashgraph-online/hol-guard/issues/5019)) ([c23a791](https://github.com/hashgraph-online/hol-guard/commit/c23a7918c9a942d1e796109f7382d38397127601))
* **guard:** let a literal pattern bound an fd search below a dot-directory ([#5015](https://github.com/hashgraph-online/hol-guard/issues/5015)) ([7945fae](https://github.com/hashgraph-online/hol-guard/commit/7945fae5654a03efd7d4b2e70680e588544d2484))
* **guard:** let a name pattern bound what a deeper find prints ([#5013](https://github.com/hashgraph-online/hol-guard/issues/5013)) ([6f9a890](https://github.com/hashgraph-online/hol-guard/commit/6f9a89040fe16b5670d187dfa346a6f4fbae13fe))
* **guard:** list a home dot-directory through the host's own listing tools ([#5003](https://github.com/hashgraph-online/hol-guard/issues/5003)) ([07f2352](https://github.com/hashgraph-online/hol-guard/commit/07f23529f66cece609d8a6990391a0ded317da9f))
* **guard:** prove a recursive search for what it actually reads ([#5012](https://github.com/hashgraph-online/hol-guard/issues/5012)) ([e53bdd2](https://github.com/hashgraph-online/hol-guard/commit/e53bdd270db6264233382c9229a5d0d1a5ca2162))
* **guard:** read a file named in a neighbouring repository without review ([#5009](https://github.com/hashgraph-online/hol-guard/issues/5009)) ([c522ff8](https://github.com/hashgraph-online/hol-guard/commit/c522ff89e5f18a13694e2dd3152d0dc6dc7390ff))
* **guard:** read a migration named for the table it defines ([#5007](https://github.com/hashgraph-online/hol-guard/issues/5007)) ([f02d5e4](https://github.com/hashgraph-online/hol-guard/commit/f02d5e4790f15547d4bab08a34ce6ebed75018b6))
* **guard:** sandbox script smoke tests that reuse a fresh mktemp directory ([#4995](https://github.com/hashgraph-online/hol-guard/issues/4995)) ([44f7ded](https://github.com/hashgraph-online/hol-guard/commit/44f7ded1ce6314c043496b727a61756796944429))
* **guard:** screen hidden home reads for credentials, not for being hidden ([#4992](https://github.com/hashgraph-online/hol-guard/issues/4992)) ([46f9b33](https://github.com/hashgraph-online/hol-guard/commit/46f9b33422d6889c1e79ac0b2ed1c150fbcc0422))
* **mcp:** drop omarchy-mcp contribution pointing pipx at an unrelated package ([#4996](https://github.com/hashgraph-online/hol-guard/issues/4996)) ([6ef1fa9](https://github.com/hashgraph-online/hol-guard/commit/6ef1fa92aed72b56a128c9e47e49a563c3d71caf))
* **release:** raise x86_64 wheel download budgets so 3.47 can publish ([#4993](https://github.com/hashgraph-online/hol-guard/issues/4993)) ([37ef1bc](https://github.com/hashgraph-online/hol-guard/commit/37ef1bc4ebd0d2f4b2603dad031e90bdf3733710))

## [3.47.0](https://github.com/hashgraph-online/hol-guard/compare/v3.46.0...v3.47.0) (2026-10-16)


### Features

* add Omarchy MCP server guard profile ([#2973](https://github.com/hashgraph-online/hol-guard/issues/2973)) ([58bec64](https://github.com/hashgraph-online/hol-guard/commit/58bec64fdc93fe6598a1ea12253705051147eaef))
* **contributions:** add AgenticJobs command extension ([#3059](https://github.com/hashgraph-online/hol-guard/issues/3059)) ([507f32e](https://github.com/hashgraph-online/hol-guard/commit/507f32ee3819bf9ec9a7f0058c151a49d3502d32))
* **dashboard:** extension state pills, featured-first catalog and Discover spotlight ([#4762](https://github.com/hashgraph-online/hol-guard/issues/4762)) ([26ae2a5](https://github.com/hashgraph-online/hol-guard/commit/26ae2a548d721d3fcb96e06e451b91b2396efaa9))
* **dashboard:** offer the open extension slot in both surfaces and sharpen the starter shelf ([#4875](https://github.com/hashgraph-online/hol-guard/issues/4875)) ([a14045a](https://github.com/hashgraph-online/hol-guard/commit/a14045aa781ece4f65808b0854877088e7992609))
* **dashboard:** rebuild the Extensions surface around one placement shelf ([#4823](https://github.com/hashgraph-online/hol-guard/issues/4823)) ([b64a00b](https://github.com/hashgraph-online/hol-guard/commit/b64a00bac68a930dcf44574e1c422fba72b53b20))
* **extensions:** add command.rls-saboteur command source ([#4636](https://github.com/hashgraph-online/hol-guard/issues/4636)) ([f3ba41c](https://github.com/hashgraph-online/hol-guard/commit/f3ba41c6c2297d29513b27158d6dd51589b322a8))
* **extensions:** add crisp-tui protection and fix the macOS pending check ([#3344](https://github.com/hashgraph-online/hol-guard/issues/3344)) ([31d3c61](https://github.com/hashgraph-online/hol-guard/commit/31d3c61b72e1370b099610ebcc83ec85c8b466ed))
* **extensions:** add netdoctor command source ([#3762](https://github.com/hashgraph-online/hol-guard/issues/3762)) ([7960893](https://github.com/hashgraph-online/hol-guard/commit/79608934afba164d5f118253111148bd3bd4f2f8))
* **gauntlet:** build the qualify wheel on Linux and add --prepare-only ([d269186](https://github.com/hashgraph-online/hol-guard/commit/d26918604fe6989c8793d60cc8e143f4bd75ec5f))
* **gauntlet:** run full-task cases in parallel with --jobs ([#4964](https://github.com/hashgraph-online/hol-guard/issues/4964)) ([4df4479](https://github.com/hashgraph-online/hol-guard/commit/4df4479a5184580406898c6342442a51de6c527c))
* **gauntlet:** run full-task projects under Claude Code and Codex ([#4817](https://github.com/hashgraph-online/hol-guard/issues/4817)) ([1535cf0](https://github.com/hashgraph-online/hol-guard/commit/1535cf05af69a91ced56e98cdcf7951a4ef997b8))
* **guard:** acquire and inspect external archives in the native egress caller ([#4868](https://github.com/hashgraph-online/hol-guard/issues/4868)) ([800a5ec](https://github.com/hashgraph-online/hol-guard/commit/800a5ecbdb9496befc3a55a004e5e9e0a690c556))
* **guard:** add claude-tmux cleanup command Extension ([#2804](https://github.com/hashgraph-online/hol-guard/issues/2804)) ([d9b4821](https://github.com/hashgraph-online/hol-guard/commit/d9b4821e0b5008729f469560e6d798d235bfc4b4))
* **guard:** add Seahorse memory MCP server contribution ([#2989](https://github.com/hashgraph-online/hol-guard/issues/2989)) ([8dbae45](https://github.com/hashgraph-online/hol-guard/commit/8dbae4512a514cebdfcd5bc9b4ff14f901b5e27f))
* **guard:** assemble the caller side of a native package evaluation ([#4904](https://github.com/hashgraph-online/hol-guard/issues/4904)) ([88e0e3b](https://github.com/hashgraph-online/hol-guard/commit/88e0e3b37d512ceb4c183a0b843718e208e11091))
* **guard:** assemble the relay's native package evaluation ([#4913](https://github.com/hashgraph-online/hol-guard/issues/4913)) ([dc7ddd5](https://github.com/hashgraph-online/hol-guard/commit/dc7ddd5d1012c8ee71bca56d137a98bde9bce2de))
* **guard:** build the native MCP relay on Windows ([#4903](https://github.com/hashgraph-online/hol-guard/issues/4903)) ([2533d1e](https://github.com/hashgraph-online/hol-guard/commit/2533d1ef44445e0335160a7960f881c4b2306bc7))
* **guard:** carry a package evaluation over the relay's resident lane ([#4896](https://github.com/hashgraph-online/hol-guard/issues/4896)) ([f6da007](https://github.com/hashgraph-online/hol-guard/commit/f6da007f8b8a5bd0c37266902e47bacd8a78a655))
* **guard:** compose machine-managed policy into the native Guard config ([#4893](https://github.com/hashgraph-online/hol-guard/issues/4893)) ([477e7c1](https://github.com/hashgraph-online/hol-guard/commit/477e7c17e2130c6eea962e350856e134a3bee233))
* **guard:** decide opencode ask-mode MCP tool calls in the resident ([#4821](https://github.com/hashgraph-online/hol-guard/issues/4821)) ([3a3dc6b](https://github.com/hashgraph-online/hol-guard/commit/3a3dc6b2735bbe256a2948f64f93f23fbc17ff36))
* **guard:** drive package authority evaluation rounds from the native caller ([#4882](https://github.com/hashgraph-online/hol-guard/issues/4882)) ([d67b9f5](https://github.com/hashgraph-online/hol-guard/commit/d67b9f5474f68cd9d194e7a1aaf4fae2d686483d))
* **guard:** hydrate a relayed package call's policy view from the bound config ([#4914](https://github.com/hashgraph-online/hol-guard/issues/4914)) ([2dcb094](https://github.com/hashgraph-online/hol-guard/commit/2dcb09456c9aa1be8e46c45cde2fd8c6559de65c))
* **guard:** load machine-managed policy from the native machine source ([#4892](https://github.com/hashgraph-online/hol-guard/issues/4892)) ([045d506](https://github.com/hashgraph-online/hol-guard/commit/045d5061868352f774f09bb238d9045c8dfc2444))
* **guard:** parse the machine-managed policy in the native runtime ([#4885](https://github.com/hashgraph-online/hol-guard/issues/4885)) ([bf5a4fe](https://github.com/hashgraph-online/hol-guard/commit/bf5a4fe31ebb0105cde78b2f6818f32b9d3c8144))
* **guard:** perform brokered supply-chain egress from the Rust caller ([#4862](https://github.com/hashgraph-online/hol-guard/issues/4862)) ([a7e6b13](https://github.com/hashgraph-online/hol-guard/commit/a7e6b13fd66a5248e617e8d848e5849f07d8990e))
* **guard:** raise the inline approval prompt from the native MCP relay ([#4845](https://github.com/hashgraph-online/hol-guard/issues/4845)) ([b77a610](https://github.com/hashgraph-online/hol-guard/commit/b77a610237645b63cc2ec38edb6b606242dbff60))
* **guard:** resolve package policy inside the native relay ([#4937](https://github.com/hashgraph-online/hol-guard/issues/4937)) ([8aed2f5](https://github.com/hashgraph-online/hol-guard/commit/8aed2f5f1825fef7a2b030c8e42ed881c2673642))
* **guard:** resolve the managed network policy in the native egress caller ([#4870](https://github.com/hashgraph-online/hol-guard/issues/4870)) ([809d968](https://github.com/hashgraph-online/hol-guard/commit/809d9682e0e5c3c355421697aa6fe4a9e1dd2ed7))
* **guard:** run the native MCP relay on Windows ([#4905](https://github.com/hashgraph-online/hol-guard/issues/4905)) ([423931c](https://github.com/hashgraph-online/hol-guard/commit/423931c43462cb57c0c264b015b85c5f9a607f1c))
* **guard:** show harness version coverage in the dashboard ([#4981](https://github.com/hashgraph-online/hol-guard/issues/4981)) ([0dcbc31](https://github.com/hashgraph-online/hol-guard/commit/0dcbc31674d0dff236d43b09654592f32d7b8028))
* **mcp-servers:** add Thingery MCP contribution ([#4605](https://github.com/hashgraph-online/hol-guard/issues/4605)) ([ba67080](https://github.com/hashgraph-online/hol-guard/commit/ba6708051eb7297cc89f6c842a31cc53784a0411))
* **release:** publish Intel macOS native wheels on the GitHub release only ([#4978](https://github.com/hashgraph-online/hol-guard/issues/4978)) ([1d9cb7c](https://github.com/hashgraph-online/hol-guard/commit/1d9cb7c942801b655ef6c9385cdc364be3f613bf))
* **release:** ship Windows ARM64 native wheels from GitHub releases ([#4946](https://github.com/hashgraph-online/hol-guard/issues/4946)) ([8af1185](https://github.com/hashgraph-online/hol-guard/commit/8af1185497b3d4eb5e487324a50650fad6154bc0))
* **windows:** run direct Vite builds in an AppContainer ([b021d78](https://github.com/hashgraph-online/hol-guard/commit/b021d78ec699b65ad246189d619b9ed4f0249fa9))


### Bug Fixes

* **ci:** bound stuck jobs and let the macOS evaluator wheel finish ([6501ab2](https://github.com/hashgraph-online/hol-guard/commit/6501ab25a47b0734eb90c4f252809846918870dc))
* **ci:** stop Windows resident startup from failing at nine seconds ([#4950](https://github.com/hashgraph-online/hol-guard/issues/4950)) ([e782c18](https://github.com/hashgraph-online/hol-guard/commit/e782c182993df7958120ed092c5a6d32a2567ed2))
* **dashboard:** quote slot capacity for the product the price belongs to ([#4889](https://github.com/hashgraph-online/hol-guard/issues/4889)) ([90dbcc4](https://github.com/hashgraph-online/hol-guard/commit/90dbcc425f5180ac79a4128b6e1da733f6264c87))
* **dashboard:** tighten Extensions shelf and slot rows, switch between built-in and custom lists ([#4954](https://github.com/hashgraph-online/hol-guard/issues/4954)) ([9781318](https://github.com/hashgraph-online/hol-guard/commit/9781318a1ee435741f3b196098c170c0c48c2289))
* **evidence:** show approved-once actions that stayed blocked as stopped ([51bb46e](https://github.com/hashgraph-online/hol-guard/commit/51bb46e7ad4e107af12c83d8970fd584fdb939e9)), closes [#3844](https://github.com/hashgraph-online/hol-guard/issues/3844)
* **extensions:** bind the crisp-tui command extension to its trust class ([#4958](https://github.com/hashgraph-online/hol-guard/issues/4958)) ([1a407a8](https://github.com/hashgraph-online/hol-guard/commit/1a407a82afc96b1d82514cd9249601c0dc90a338))
* **gauntlet:** accept a delegated report that uses the schema its parent declared ([#4951](https://github.com/hashgraph-online/hol-guard/issues/4951)) ([30145a7](https://github.com/hashgraph-online/hol-guard/commit/30145a760d26ae04a3123a05866e7f131c4468b7))
* **gauntlet:** close stdin for agent processes on POSIX hosts ([#4966](https://github.com/hashgraph-online/hol-guard/issues/4966)) ([5ed315d](https://github.com/hashgraph-online/hol-guard/commit/5ed315d3f5394061406e03f1f3011df5d5a53433))
* **gauntlet:** count a finished print session with a running dev server as ended ([#4898](https://github.com/hashgraph-online/hol-guard/issues/4898)) ([9d18c60](https://github.com/hashgraph-online/hol-guard/commit/9d18c6028a76e82b829938e52898696756090cb4))
* **gauntlet:** count finished local apps the full-task oracle missed ([#4947](https://github.com/hashgraph-online/hol-guard/issues/4947)) ([81fe5c6](https://github.com/hashgraph-online/hol-guard/commit/81fe5c62d101ecf6037350b36bd31f403a5f6e9f))
* **gauntlet:** observe the hook bridge through the child spawn method ([#4899](https://github.com/hashgraph-online/hol-guard/issues/4899)) ([5aa4bea](https://github.com/hashgraph-online/hol-guard/commit/5aa4bea7f8dfe3f6acfd09817094a579b727df65))
* **gauntlet:** show the Luna adapter's stderr when it fails to start ([#4770](https://github.com/hashgraph-online/hol-guard/issues/4770)) ([17024fd](https://github.com/hashgraph-online/hol-guard/commit/17024fdfb83f462e82aa1e3a818324f8f64723ad))
* **gauntlet:** skip Node option values when finding a spawned script ([#4952](https://github.com/hashgraph-online/hol-guard/issues/4952)) ([cd27133](https://github.com/hashgraph-online/hol-guard/commit/cd27133df86706e2dfcd097ccb2337d7c2ba86a6))
* **guard:** accept unified-diff old rows inside Oh My Pi PUT bodies ([#4907](https://github.com/hashgraph-online/hol-guard/issues/4907)) ([d839431](https://github.com/hashgraph-online/hol-guard/commit/d839431eaaa844805e4dae7742457975babb9ebe))
* **guard:** allow node --check syntax checks of local and served scripts ([#4932](https://github.com/hashgraph-online/hol-guard/issues/4932)) ([01882c2](https://github.com/hashgraph-online/hol-guard/commit/01882c2ac63b63ea7777e605b16445e70d7f4ddd))
* **guard:** answer the first Windows hook in a file-less directory spelled with a short name or other case ([#4942](https://github.com/hashgraph-online/hol-guard/issues/4942)) ([ce1695b](https://github.com/hashgraph-online/hol-guard/commit/ce1695b8d1b987bf703a86fecc193b0779b1bf18))
* **guard:** apply the saved package approval the claim reports ([#4938](https://github.com/hashgraph-online/hol-guard/issues/4938)) ([31a4a11](https://github.com/hashgraph-online/hol-guard/commit/31a4a118f06fb5da74c4a5fc7ee4c9dece871263))
* **guard:** bind Windows native launches to their loader inputs ([ca9d1f5](https://github.com/hashgraph-online/hol-guard/commit/ca9d1f536b994626ca6bb1a780cda3955381f2d8))
* **guard:** build the native runtime on Windows again ([#4867](https://github.com/hashgraph-online/hol-guard/issues/4867)) ([a9d3b3e](https://github.com/hashgraph-online/hol-guard/commit/a9d3b3e09e525540f3cff662db21207fb305aa75))
* **guard:** build the package evaluation spool on Windows ([#4924](https://github.com/hashgraph-online/hol-guard/issues/4924)) ([dacc20c](https://github.com/hashgraph-online/hol-guard/commit/dacc20cb5b2266f7f92d8f94fd765376daab3da1))
* **guard:** build the Windows path helpers under strict clippy ([#4936](https://github.com/hashgraph-online/hol-guard/issues/4936)) ([9fb9e6f](https://github.com/hashgraph-online/hol-guard/commit/9fb9e6f63f2f1f0c7bc2bf6d5798d412fc8a6485))
* **guard:** check Claude Code's PowerShell tool calls ([#4780](https://github.com/hashgraph-online/hol-guard/issues/4780)) ([829e58e](https://github.com/hashgraph-online/hol-guard/commit/829e58e9f219a1615e18f9e38e553b1f6655dd9d))
* **guard:** check vite output directories before sandboxing and keep doctor's approval gate check passive ([#4776](https://github.com/hashgraph-online/hol-guard/issues/4776)) ([49be1ad](https://github.com/hashgraph-online/hol-guard/commit/49be1adb8d3d0032242ba4b3ae965b789e305f39))
* **guard:** classify Windows name aliases of secret paths like the plain path ([#4786](https://github.com/hashgraph-online/hol-guard/issues/4786)) ([9159a86](https://github.com/hashgraph-online/hol-guard/commit/9159a86978f231a0ec6b15b51d5076c684b510db))
* **guard:** clear common read-only commands agents run while building a project ([#4879](https://github.com/hashgraph-online/hol-guard/issues/4879)) ([ab3f692](https://github.com/hashgraph-online/hol-guard/commit/ab3f6927d9e771abf5971fb18ce1d02f3135d589))
* **guard:** clear Windows false positives in guard-command integration reads ([#4830](https://github.com/hashgraph-online/hol-guard/issues/4830)) ([5d1a4ac](https://github.com/hashgraph-online/hol-guard/commit/5d1a4ac1024d2b98ba1cf0a7e6e183c95134cd1d))
* **guard:** close seven deferred review findings in hooks and command review ([#4772](https://github.com/hashgraph-online/hol-guard/issues/4772)) ([71df40e](https://github.com/hashgraph-online/hol-guard/commit/71df40e2b91f3e30194dc5f5ec248d40c9bea51d))
* **guard:** contain the Codex safety-guide read when it is chained with a workspace file listing ([#4930](https://github.com/hashgraph-online/hol-guard/issues/4930)) ([a328171](https://github.com/hashgraph-online/hol-guard/commit/a328171e5a256dde323c255ea5fdeae15497fd27))
* **guard:** edit the Codex config instead of rewriting it ([#4858](https://github.com/hashgraph-online/hol-guard/issues/4858)) ([961fb14](https://github.com/hashgraph-online/hol-guard/commit/961fb14943c3ba56ea6c5dea32029035b93123a5))
* **guard:** fail closed when the resident cannot parse a wrapped install's package intent ([#4761](https://github.com/hashgraph-online/hol-guard/issues/4761)) ([20766bc](https://github.com/hashgraph-online/hol-guard/commit/20766bc19c4a94ec5bf3e642b3a8eace8e56551a))
* **guard:** free a hook's review slot before its answer is sent ([#4928](https://github.com/hashgraph-online/hol-guard/issues/4928)) ([cbf9ebb](https://github.com/hashgraph-online/hol-guard/commit/cbf9ebb6128f8c8ad28492ac18af632eab118009))
* **guard:** give install and doctor time to reach a cold native runtime ([#4852](https://github.com/hashgraph-online/hol-guard/issues/4852)) ([336e5e7](https://github.com/hashgraph-online/hol-guard/commit/336e5e72b7814c82feec5e887c8f3fa2d2c6e6e0))
* **guard:** give the packaged command program room for a growing catalog ([#4984](https://github.com/hashgraph-online/hol-guard/issues/4984)) ([5ce66b6](https://github.com/hashgraph-online/hol-guard/commit/5ce66b6d98a8b016dbd71730ade84476b83311c4))
* **guard:** honor the configured approval cooldown instead of asking for the password on every approval ([#4764](https://github.com/hashgraph-online/hol-guard/issues/4764)) ([2bafd9c](https://github.com/hashgraph-online/hol-guard/commit/2bafd9c618be0cd077abf91c9b21d65fc268baff))
* **guard:** install a missing native runtime before the lifecycle gate ([#4990](https://github.com/hashgraph-online/hol-guard/issues/4990)) ([51ddf63](https://github.com/hashgraph-online/hol-guard/commit/51ddf63d25e51487d4162b2f34207656191a00f1))
* **guard:** judge Oh My Pi eval shell calls and /tmp reads like direct calls ([#4782](https://github.com/hashgraph-online/hol-guard/issues/4782)) ([494d519](https://github.com/hashgraph-online/hol-guard/commit/494d51930da3ead6a2dae3968a4a5863472843f7))
* **guard:** keep a one-time approval matched to its identical retry across a policy republish ([#4977](https://github.com/hashgraph-online/hol-guard/issues/4977)) ([fcf06fd](https://github.com/hashgraph-online/hol-guard/commit/fcf06fd6c0ad6438b243cb96d0188ed3bb1c1d42))
* **guard:** keep a one-time approval matched to its retry across policy republishes ([#4960](https://github.com/hashgraph-online/hol-guard/issues/4960)) ([63b5dca](https://github.com/hashgraph-online/hol-guard/commit/63b5dca51406b700449658fa30ebf167c3f910e9))
* **guard:** keep MCP servers whose command argument sits behind a schema reference on the Python proxy ([#4857](https://github.com/hashgraph-online/hol-guard/issues/4857)) ([3ea7ba1](https://github.com/hashgraph-online/hol-guard/commit/3ea7ba1446d55c07df77ea614977b907da01c142))
* **guard:** keep the daemon cloud sync loop alive when the store cannot record an attempt ([0cf4f06](https://github.com/hashgraph-online/hol-guard/commit/0cf4f065fea837e33fdb7b46fc6ac61337f7a18f))
* **guard:** keep the Oh My Pi memory write under review and release only its receipt ([#4970](https://github.com/hashgraph-online/hol-guard/issues/4970)) ([e840b9b](https://github.com/hashgraph-online/hol-guard/commit/e840b9b6ad5def4a6f96622bbf2a3464281388b3))
* **guard:** keep the Windows drive when resolving compound Git paths ([#4911](https://github.com/hashgraph-online/hol-guard/issues/4911)) ([5e2271d](https://github.com/hashgraph-online/hol-guard/commit/5e2271ded7715b7ab41785fa717a6b7b2f12dc44))
* **guard:** keep Windows git approvals one-time ([#4959](https://github.com/hashgraph-online/hol-guard/issues/4959)) ([3e81cdd](https://github.com/hashgraph-online/hol-guard/commit/3e81cdd7871f738e98a7f3500371f51230d6e8ea))
* **guard:** leave interpreter pipes with a missing option value to the ordinary review ([#4806](https://github.com/hashgraph-online/hol-guard/issues/4806)) ([4d24244](https://github.com/hashgraph-online/hol-guard/commit/4d24244da8156852fb3badf5b9693f5edf3e1612))
* **guard:** let a one-time approval of a plain git push to a self-hosted origin run its retry ([#4975](https://github.com/hashgraph-online/hol-guard/issues/4975)) ([73d354e](https://github.com/hashgraph-online/hol-guard/commit/73d354e345591f031852eaa7c4c8a20f04fe1309))
* **guard:** let Always allow stick for node scripts whose imported code is unchanged ([#4768](https://github.com/hashgraph-online/hol-guard/issues/4768)) ([d8bc1a7](https://github.com/hashgraph-online/hol-guard/commit/d8bc1a7ae84f60682cf32e513870507ac417b1b3))
* **guard:** let an approved python script launch be reused while its source is unchanged ([cbf23ff](https://github.com/hashgraph-online/hol-guard/commit/cbf23ff7a21b9b832874271e625768cc799a0366))
* **guard:** let approve-once settle pipelines, kubectl reads and project removals ([#4818](https://github.com/hashgraph-online/hol-guard/issues/4818)) ([9798e6f](https://github.com/hashgraph-online/hol-guard/commit/9798e6f87f8d21e9aca52987b2a4d8cb246e3804))
* **guard:** let Codex apply_patch write to a private temp directory like other harnesses ([#4781](https://github.com/hashgraph-online/hol-guard/issues/4781)) ([07809db](https://github.com/hashgraph-online/hol-guard/commit/07809dba08c6491f357069da1397407b6e2725ac))
* **guard:** let files written from quoted heredocs name the smoke test's temporary variable ([#4906](https://github.com/hashgraph-online/hol-guard/issues/4906)) ([d7fa69d](https://github.com/hashgraph-online/hol-guard/commit/d7fa69def0581cae8a11d778730b879457f82b60))
* **guard:** let Oh My Pi eval drive the isolated browser on loopback pages and pass target-less edits ([#4933](https://github.com/hashgraph-online/hol-guard/issues/4933)) ([98ed511](https://github.com/hashgraph-online/hol-guard/commit/98ed5110734a2dc25d353db75e175b2508b19db8))
* **guard:** let omp browser smoke checks on loopback run without review ([f757723](https://github.com/hashgraph-online/hol-guard/commit/f757723b9484896a847efb412a646dc38e88c108))
* **guard:** let omp eval smoke checks fetch the local dev server and drive the page without review ([#4979](https://github.com/hashgraph-online/hol-guard/issues/4979)) ([fdebad2](https://github.com/hashgraph-online/hol-guard/commit/fdebad253a23f14958d0470412cd72640eada575))
* **guard:** let saved Always answer Windows file reads and searches ([#4923](https://github.com/hashgraph-online/hol-guard/issues/4923)) ([519f453](https://github.com/hashgraph-online/hol-guard/commit/519f45386b736860c686bd0a3d826a8a57dfd239))
* **guard:** let shell reads look for harness notes that do not exist yet ([#4908](https://github.com/hashgraph-online/hol-guard/issues/4908)) ([51f234b](https://github.com/hashgraph-online/hol-guard/commit/51f234b624f2b243ab46a87b7bbb1ef444017707))
* **guard:** list a name that is not there beside a glob ([#4983](https://github.com/hashgraph-online/hol-guard/issues/4983)) ([bd7ef8f](https://github.com/hashgraph-online/hol-guard/commit/bd7ef8f718d793326afa9fbadb1b16e2e041a362))
* **guard:** list a project's virtualenv without asking for approval ([#4865](https://github.com/hashgraph-online/hol-guard/issues/4865)) ([dc6bec8](https://github.com/hashgraph-online/hol-guard/commit/dc6bec861dadcc3dc922010b12f10cb2ed02b4fa))
* **guard:** log the hook exception behind a fail-closed native deny ([1ca0c80](https://github.com/hashgraph-online/hol-guard/commit/1ca0c80428812b19e780ef1a6244ef905796b89b))
* **guard:** map read-only PowerShell cmdlets to the POSIX reads Guard already proves ([#4784](https://github.com/hashgraph-online/hol-guard/issues/4784)) ([ee9d88b](https://github.com/hashgraph-online/hol-guard/commit/ee9d88b8eac305a336abef6afe4d96d03b7e9ffd))
* **guard:** name Windows child programs with native separators ([#4884](https://github.com/hashgraph-online/hol-guard/issues/4884)) ([0fae249](https://github.com/hashgraph-online/hol-guard/commit/0fae24964876df28a2ea650761232a17147c0501))
* **guard:** pass Oh My Pi edits that name no file ([#4971](https://github.com/hashgraph-online/hol-guard/issues/4971)) ([964f0a8](https://github.com/hashgraph-online/hol-guard/commit/964f0a84124449e21b85f6ed4dc6a17ccfa3a73d))
* **guard:** queue a post-claim re-approval from the native MCP relay ([#4920](https://github.com/hashgraph-online/hol-guard/issues/4920)) ([0f68d29](https://github.com/hashgraph-online/hol-guard/commit/0f68d29b51bd86f46dc2a1decfdc4b3027d1ffe6))
* **guard:** read `--cwd` as a directory, not a package to install ([#4972](https://github.com/hashgraph-online/hol-guard/issues/4972)) ([cf50693](https://github.com/hashgraph-online/hol-guard/commit/cf50693c7bd47b69fbe320424fd6598446a84a78)), closes [#4808](https://github.com/hashgraph-online/hol-guard/issues/4808)
* **guard:** read a project's saved decisions when the store holds other projects' rows ([#4847](https://github.com/hashgraph-online/hol-guard/issues/4847)) ([f975a66](https://github.com/hashgraph-online/hol-guard/commit/f975a66b916539a89a88a74648d97525af763481))
* **guard:** read a stash entry's diff without an approval ([#4927](https://github.com/hashgraph-online/hol-guard/issues/4927)) ([3199aef](https://github.com/hashgraph-online/hol-guard/commit/3199aef41d60ea30844231742264e5ead8d6fda3))
* **guard:** read a timeout clock through to the command it bounds ([15c8969](https://github.com/hashgraph-online/hol-guard/commit/15c89691ed8d9800e3fcccec7a6a8d07ec07c43c))
* **guard:** read inline and standard-input programs before deciding where they run ([#4816](https://github.com/hashgraph-online/hol-guard/issues/4816)) ([51c1d7e](https://github.com/hashgraph-online/hol-guard/commit/51c1d7e70ba30ecee269931ec80de8e17f23cbeb))
* **guard:** read interpreter options per family in remote-code pipes ([#4794](https://github.com/hashgraph-online/hol-guard/issues/4794)) ([b6cb681](https://github.com/hashgraph-online/hol-guard/commit/b6cb6816154e9b50e5ee397c107ee447fa61848c))
* **guard:** read Node long options in remote-code pipes and match the resident on repeated gate keys ([#4803](https://github.com/hashgraph-online/hol-guard/issues/4803)) ([380301e](https://github.com/hashgraph-online/hol-guard/commit/380301e8497b3469cdf8bbd1ee364c3080d5380b))
* **guard:** read Oh My Pi eval programs that compute in memory or drive a local browser page ([#4826](https://github.com/hashgraph-online/hol-guard/issues/4826)) ([0dd9a15](https://github.com/hashgraph-online/hol-guard/commit/0dd9a153543446ad6589a8f2a892e80502439946))
* **guard:** read the file a command sources before calling it unknown ([#4888](https://github.com/hashgraph-online/hol-guard/issues/4888)) ([76eabfa](https://github.com/hashgraph-online/hol-guard/commit/76eabfa7c436c1992251a4f9f7e0b9767a2091f4))
* **guard:** read the program an `xargs` names in the command text ([#4909](https://github.com/hashgraph-online/hol-guard/issues/4909)) ([c28309f](https://github.com/hashgraph-online/hol-guard/commit/c28309f8cb5190b6d33ceab5e0f9ca1da1199142))
* **guard:** record a package-policy lookup failure instead of an empty result ([#4957](https://github.com/hashgraph-online/hol-guard/issues/4957)) ([fcf9d91](https://github.com/hashgraph-online/hol-guard/commit/fcf9d91c7757c40b0669c30d8bc3b18802286b1a))
* **guard:** record which install wrote each extension-control catalog ([#4842](https://github.com/hashgraph-online/hol-guard/issues/4842)) ([7f602b3](https://github.com/hashgraph-online/hol-guard/commit/7f602b369896725644a17a6e89ace052555cb293))
* **guard:** report unknown gate posture for state the resident refuses ([#4789](https://github.com/hashgraph-online/hol-guard/issues/4789)) ([d1d216d](https://github.com/hashgraph-online/hol-guard/commit/d1d216d1b28fa28dcf0fbd77c364c421bdecddb8))
* **guard:** report why native hook authority could not decide ([#4828](https://github.com/hashgraph-online/hol-guard/issues/4828)) ([69725c2](https://github.com/hashgraph-online/hol-guard/commit/69725c2200ec051e17d037049f389798a3198678))
* **guard:** resolve agent read allowances in one path spelling on Windows ([ebc230b](https://github.com/hashgraph-online/hol-guard/commit/ebc230b2f87fd3faa2e0abe46865d5187d7dedf1))
* **guard:** reuse the Windows runtime digest while writers are locked out ([#4866](https://github.com/hashgraph-online/hol-guard/issues/4866)) ([0cd9336](https://github.com/hashgraph-online/hol-guard/commit/0cd9336872459b1bc294a546da4d4d5322b6840a))
* **guard:** review a backgrounded command instead of blocking it outright ([#4871](https://github.com/hashgraph-online/hol-guard/issues/4871)) ([d7379bd](https://github.com/hashgraph-online/hol-guard/commit/d7379bdd1d12b2155ce4a3dbdc68b0e633f446e3))
* **guard:** review unmatched read-only shell shapes instead of blocking them ([#4825](https://github.com/hashgraph-online/hol-guard/issues/4825)) ([9d497f8](https://github.com/hashgraph-online/hol-guard/commit/9d497f81a9c14f59d7203a35a19134edc688cbe5))
* **guard:** route build and test work only to sandboxes that can run it ([#4765](https://github.com/hashgraph-online/hol-guard/issues/4765)) ([2319bbe](https://github.com/hashgraph-online/hol-guard/commit/2319bbebe88ae2cd601f1cd98853559016fa8f6b))
* **guard:** route interpreter scripts by what their source does ([#4774](https://github.com/hashgraph-online/hol-guard/issues/4774)) ([b1e3cdf](https://github.com/hashgraph-online/hol-guard/commit/b1e3cdf4c43491429eebdf308bc6a060cb99c875))
* **guard:** run a kill of the shell's own job in the workspace sandbox ([#4915](https://github.com/hashgraph-online/hol-guard/issues/4915)) ([98b4d85](https://github.com/hashgraph-online/hol-guard/commit/98b4d857f4723ab73af38fa50df5bd875e5bd09c))
* **guard:** run a timeout-bounded test in the sandbox instead of failing it ([#4962](https://github.com/hashgraph-online/hol-guard/issues/4962)) ([49fd68d](https://github.com/hashgraph-online/hol-guard/commit/49fd68d341b079c485e6c39cbf36c181d3a04274))
* **guard:** run commands that cd into a fresh mktemp directory in the workspace sandbox ([#4887](https://github.com/hashgraph-online/hol-guard/issues/4887)) ([fee57eb](https://github.com/hashgraph-online/hol-guard/commit/fee57eb842f30d18e4298ef17b1e386d51524fdd))
* **guard:** run inline dev servers that read their port from the environment in the sandbox ([#4940](https://github.com/hashgraph-online/hol-guard/issues/4940)) ([c9639b0](https://github.com/hashgraph-online/hol-guard/commit/c9639b0984aea7b2cb8bb71dc1d38bb10baec734))
* **guard:** run inline Node servers and smoke tests on loopback ports in the workspace sandbox ([#4881](https://github.com/hashgraph-online/hol-guard/issues/4881)) ([ec10be2](https://github.com/hashgraph-online/hol-guard/commit/ec10be27c00457d49b689cef4709c2efc873a301))
* **guard:** run local dev servers from workspace scripts in the sandbox without review ([#4912](https://github.com/hashgraph-online/hol-guard/issues/4912)) ([f9e3b1c](https://github.com/hashgraph-online/hol-guard/commit/f9e3b1cc7b8950d4ae6331cf0fb0741dc82a5e71))
* **guard:** run multi-line CLI smoke tests that export a fresh temporary path inside the workspace sandbox ([#4901](https://github.com/hashgraph-online/hol-guard/issues/4901)) ([9947678](https://github.com/hashgraph-online/hol-guard/commit/9947678b4c583042075e754f2ec4f1f6c11bb4dd))
* **guard:** run scratch scripts outside the workspace in the workspace sandbox ([#4832](https://github.com/hashgraph-online/hol-guard/issues/4832)) ([05038cc](https://github.com/hashgraph-online/hol-guard/commit/05038cc40c416e0c208f429a45e1bf31837a461a))
* **guard:** run script smoke tests that reuse a fresh mktemp directory in the sandbox ([#4973](https://github.com/hashgraph-online/hol-guard/issues/4973)) ([587d5b4](https://github.com/hashgraph-online/hol-guard/commit/587d5b496b1672605e91bb20393f905d8d8037f7))
* **guard:** run Windows Codex Python test scripts in the contained sandbox ([#4835](https://github.com/hashgraph-online/hol-guard/issues/4835)) ([b957027](https://github.com/hashgraph-online/hol-guard/commit/b957027f659d079cea63e1bcedb3b1a16b31103c))
* **guard:** settle three omp dev-loop stops ([#4945](https://github.com/hashgraph-online/hol-guard/issues/4945)) ([9b914b0](https://github.com/hashgraph-online/hol-guard/commit/9b914b07d51482aa0a0d23c254521716a0f05eda))
* **guard:** stop an idle daemon from rebuilding its policy snapshot in a loop ([#4771](https://github.com/hashgraph-online/hol-guard/issues/4771)) ([c597705](https://github.com/hashgraph-online/hol-guard/commit/c597705441dfc11583ddebc2a91ce521dffc1b57))
* **guard:** stop blocking chains that start by setting a plain shell variable ([955a507](https://github.com/hashgraph-online/hol-guard/commit/955a507c6dd7a4d26f2d466f4c4fc7ae1e1265a8))
* **guard:** stop blocking package scripts and tools the sandbox can actually run ([6ddf4d0](https://github.com/hashgraph-online/hol-guard/commit/6ddf4d0eae403fd361484de9484cc18a920bd0d3))
* **guard:** stop holding branch work and config reads in long-lived signed clones ([#4758](https://github.com/hashgraph-online/hol-guard/issues/4758)) ([3b455b9](https://github.com/hashgraph-online/hol-guard/commit/3b455b9edd0d42b21d119523c9c640e036effa8e))
* **guard:** stop letting an agent authorize its own secret reads ([#4853](https://github.com/hashgraph-online/hol-guard/issues/4853)) ([07293f4](https://github.com/hashgraph-online/hol-guard/commit/07293f4ce8df7289af008ad5564df22ce98d97b9))
* **guard:** stop promising a retry when the install cannot publish policy ([#4872](https://github.com/hashgraph-online/hol-guard/issues/4872)) ([6aac93d](https://github.com/hashgraph-online/hol-guard/commit/6aac93dbf207b60b789b314ab24e0b6e9542c7b6))
* **guard:** stop reading bun and yarn option values as packages ([#4956](https://github.com/hashgraph-online/hol-guard/issues/4956)) ([0d133d8](https://github.com/hashgraph-online/hol-guard/commit/0d133d81ff42b3bc09ecfc3b714ad94e1f316c2a))
* **guard:** stop reporting protection as active when no app is registered ([88bf7b6](https://github.com/hashgraph-online/hol-guard/commit/88bf7b6bdf0fe71fef20528dc61d3456cae69a04))
* **guard:** stop reviewing workspace-wide omp grep over tracked fixtures and nested checkouts ([#4836](https://github.com/hashgraph-online/hol-guard/issues/4836)) ([b022d88](https://github.com/hashgraph-online/hol-guard/commit/b022d88fd12370235a5020276ad4c7f7bdde3c3d))
* **guard:** stop the native resident when uninstall removes the last harness ([#4916](https://github.com/hashgraph-online/hol-guard/issues/4916)) ([1d69c2a](https://github.com/hashgraph-online/hol-guard/commit/1d69c2ab1755da091b78db3d52b7f449bdfdbc55))
* **guard:** stop the native runtime when Guard uninstalls itself ([#4856](https://github.com/hashgraph-online/hol-guard/issues/4856)) ([026d1c0](https://github.com/hashgraph-online/hol-guard/commit/026d1c0899f95a1fb5e0547dbb3520f6ef72fe59))
* **guard:** tell agents never to approve their own requests and nudge users to protect approvals ([#4766](https://github.com/hashgraph-online/hol-guard/issues/4766)) ([74553bb](https://github.com/hashgraph-online/hol-guard/commit/74553bb22a166ca6cb95308b163c0dd989db4b92))
* **guard:** tell agents the script-free npm install Guard lets continue ([#4929](https://github.com/hashgraph-online/hol-guard/issues/4929)) ([36f0cc4](https://github.com/hashgraph-online/hol-guard/commit/36f0cc4222e0550c53834f29b869591917bbc281))
* **guard:** treat quoted cat heredoc text as file content and list the doctl config directory ([#4824](https://github.com/hashgraph-online/hol-guard/issues/4824)) ([f6c81a2](https://github.com/hashgraph-online/hol-guard/commit/f6c81a26427fadc65b91671000d58f8dcb4c14b9))
* **guard:** treat Windows drive and UNC search paths as outside the workspace ([#4802](https://github.com/hashgraph-online/hol-guard/issues/4802)) ([b59a883](https://github.com/hashgraph-online/hol-guard/commit/b59a883f0beaf788e4f8733c33cd86916e25b15a))
* **guard:** trust Codex hooks at install and launch them on Windows ([#4850](https://github.com/hashgraph-online/hol-guard/issues/4850)) ([958ad18](https://github.com/hashgraph-online/hol-guard/commit/958ad18b477787675e809e5e6c164732faf4a3df))
* **guard:** trust group write on the native runtime from file metadata only ([#4941](https://github.com/hashgraph-online/hol-guard/issues/4941)) ([11b636f](https://github.com/hashgraph-online/hol-guard/commit/11b636f5ba52e72e00c229cc325a32bb36fae023))
* **guard:** trust the native runtime when pip installs it under a 0002 umask ([#4939](https://github.com/hashgraph-online/hol-guard/issues/4939)) ([009bc82](https://github.com/hashgraph-online/hol-guard/commit/009bc82fa7d81d29c21f2d7818021f2cf551d91f))
* **guard:** unroll a loop over a glob into the directory the pattern names ([#4917](https://github.com/hashgraph-online/hol-guard/issues/4917)) ([8cc8cc7](https://github.com/hashgraph-online/hol-guard/commit/8cc8cc7b4c17296102a1eaa8e5e5dcc67e3abddf))
* **guard:** unwrap POSIX system wrappers on Windows and repair the nightly native proofs ([#4775](https://github.com/hashgraph-online/hol-guard/issues/4775)) ([eb2a89a](https://github.com/hashgraph-online/hol-guard/commit/eb2a89a625725be4fc4484f2cde441f71ca83a1a))
* **guard:** wait for the contained run's decision instead of cancelling it ([#4953](https://github.com/hashgraph-online/hol-guard/issues/4953)) ([f742c2b](https://github.com/hashgraph-online/hol-guard/commit/f742c2bc315862807adddd21e9f5aecba11c0f55))
* **guard:** weigh the entries a pattern expands into before refusing a copy ([#4900](https://github.com/hashgraph-online/hol-guard/issues/4900)) ([e1d86da](https://github.com/hashgraph-online/hol-guard/commit/e1d86daac84b2f1e1c2f77676593a0548193810e))
* **mcp:** launch proxied MCP servers on Windows through the native runtime ([#4755](https://github.com/hashgraph-online/hol-guard/issues/4755)) ([5912e66](https://github.com/hashgraph-online/hol-guard/commit/5912e6635daa70b699338591bb627042fc37cfbd))
* **omp:** release an approved learn that carries its optional context ([#4969](https://github.com/hashgraph-online/hol-guard/issues/4969)) ([31d7124](https://github.com/hashgraph-online/hol-guard/commit/31d71248a7e9906e62cbb26af740a19a0cb472c1))
* restore extension discovery and both placements on an installed build ([#4931](https://github.com/hashgraph-online/hol-guard/issues/4931)) ([b19b65d](https://github.com/hashgraph-online/hol-guard/commit/b19b65dc6b6b6038dedb03333a64b59a804eb4e2))
* **runtime:** keep resident phase diagnostics off the request path ([#4902](https://github.com/hashgraph-online/hol-guard/issues/4902)) ([79f0a87](https://github.com/hashgraph-online/hol-guard/commit/79f0a87c459bb413bc84064399efda4f0765358e))
* **scanner:** don't report documentation that only names danger-full-access ([6ce2a5a](https://github.com/hashgraph-online/hol-guard/commit/6ce2a5aca62afa0d2fa02df2b4eb1cb8b2691d38))
* **update:** reinstall native wheels without touching loaded dependencies ([645cdbf](https://github.com/hashgraph-online/hol-guard/commit/645cdbface5c8c7232fcf1f52d2b4eece8e2fed8))
* **windows:** run Oh My Pi and Pi Python test scripts in the AppContainer ([#4788](https://github.com/hashgraph-online/hol-guard/issues/4788)) ([73d5b5d](https://github.com/hashgraph-online/hol-guard/commit/73d5b5d5ae6689b9a22d496d8940f89ebfa1de07))


### Performance Improvements

* **ci:** keep CodeQL overlay active and reuse native compiler caches ([59f1ee4](https://github.com/hashgraph-online/hol-guard/commit/59f1ee47512bc720bba454ba56252be5f056804a))
* **guard:** answer benign GitHub shell checks in the resident ([#4846](https://github.com/hashgraph-online/hol-guard/issues/4846)) ([fcd5a2b](https://github.com/hashgraph-online/hol-guard/commit/fcd5a2be3f4e5aa02cc0191eecd73a37925785e0))
* **guard:** answer unmodeled shell reviews in one resident query ([#4863](https://github.com/hashgraph-online/hol-guard/issues/4863)) ([c3ed5d9](https://github.com/hashgraph-online/hol-guard/commit/c3ed5d90dbde74240f2838468ab7ac659b1a278d))
* **guard:** build embedded script evidence in one native call ([#4841](https://github.com/hashgraph-online/hol-guard/issues/4841)) ([1f6781a](https://github.com/hashgraph-online/hol-guard/commit/1f6781a58c88f77db51c069e4a838efeae6e3181))
* **guard:** compose compound runtime artifacts in the resident ([#4861](https://github.com/hashgraph-online/hol-guard/issues/4861)) ([d60d86c](https://github.com/hashgraph-online/hol-guard/commit/d60d86cc0574406a3c14c520f806823dbde9e39b))
* **guard:** decide local tool approval eligibility in the resident ([#4838](https://github.com/hashgraph-online/hol-guard/issues/4838)) ([8e5e3c8](https://github.com/hashgraph-online/hol-guard/commit/8e5e3c8c895655032bb625f5ed520a4969de91e2))
* **guard:** decide startup policy-integrity generation in the native runtime ([#4792](https://github.com/hashgraph-online/hol-guard/issues/4792)) ([2ac954e](https://github.com/hashgraph-online/hol-guard/commit/2ac954ee65b7ba5abf0ab6b0080622a596fa963a))
* **guard:** decide the final package-protect authority in one native call ([#4797](https://github.com/hashgraph-online/hol-guard/issues/4797)) ([67c28b3](https://github.com/hashgraph-online/hol-guard/commit/67c28b3dfbf4331efc293395f7a0048a9632bb0c))
* **guard:** derive artifact risk signals in the resident in one call ([#4839](https://github.com/hashgraph-online/hol-guard/issues/4839)) ([e0e1bd9](https://github.com/hashgraph-online/hol-guard/commit/e0e1bd943d55a493c64604ff57552953723d3541))
* **guard:** derive MCP saved-policy candidates in the resident ([#4878](https://github.com/hashgraph-online/hol-guard/issues/4878)) ([a869a4f](https://github.com/hashgraph-online/hol-guard/commit/a869a4f8dee2b2757be493a9f607409ddc4bf6ed))
* **guard:** expand generic-hook remembered candidates in the saved-decision lookup ([#4877](https://github.com/hashgraph-online/hol-guard/issues/4877)) ([a2f1c2c](https://github.com/hashgraph-online/hol-guard/commit/a2f1c2ccae58b11b706264a2cb7aa7347eab3096))
* **guard:** list each directory before opening ignore files in the rg hidden-file walk ([#4787](https://github.com/hashgraph-online/hol-guard/issues/4787)) ([ee13670](https://github.com/hashgraph-online/hol-guard/commit/ee13670d119fc1866bbb7f0858ec47c02e12aca7))
* **guard:** look up, remove and discard pending hook permissions in one resident call ([#4894](https://github.com/hashgraph-online/hol-guard/issues/4894)) ([33c9b46](https://github.com/hashgraph-online/hol-guard/commit/33c9b4625fe4187602c6b1ad6592b267ccc74739))
* **guard:** queue blocked approvals in the native runtime ([#4759](https://github.com/hashgraph-online/hol-guard/issues/4759)) ([6c3abdb](https://github.com/hashgraph-online/hol-guard/commit/6c3abdb775b9de9f069d6eca06d9aa29d49ecb87))
* **guard:** read approval metadata through the native runtime ([#4749](https://github.com/hashgraph-online/hol-guard/issues/4749)) ([a2e2ccb](https://github.com/hashgraph-online/hol-guard/commit/a2e2ccb15d769f99f53d0aa8b054fb5eea18e869))
* **guard:** read the non-consuming remembered-decision lookup in one resident call ([#4883](https://github.com/hashgraph-online/hol-guard/issues/4883)) ([c521090](https://github.com/hashgraph-online/hol-guard/commit/c521090dfd0c67c60d74356c06d5e86bc68e01df))
* **guard:** resolve dashboard and workspace-review decisions in the native runtime ([#4767](https://github.com/hashgraph-online/hol-guard/issues/4767)) ([713b2f4](https://github.com/hashgraph-online/hol-guard/commit/713b2f464f5d1dfdbbde02f608ad8a73389a5597))
* **guard:** scope the policy-bundle handoff to the harnesses its rules bind ([#4855](https://github.com/hashgraph-online/hol-guard/issues/4855)) ([46a83d3](https://github.com/hashgraph-online/hol-guard/commit/46a83d32b5fff3fbaa0c4c3e52f92326fb8976c7))
* **guard:** stop re-binding guard home's DACL after every store connection on Windows ([#4785](https://github.com/hashgraph-online/hol-guard/issues/4785)) ([cc76f76](https://github.com/hashgraph-online/hol-guard/commit/cc76f7665a8ae535dbfb5d4c016169c515988957))
* **guard:** verify downloaded package archives in the resident ([#4886](https://github.com/hashgraph-online/hol-guard/issues/4886)) ([0122185](https://github.com/hashgraph-online/hol-guard/commit/0122185bdb8c2e0b8610ea5c64f674a8184c185b))
* **hooks:** answer Grok prompts from the resident without a readiness round trip ([#4748](https://github.com/hashgraph-online/hol-guard/issues/4748)) ([c7dc7dc](https://github.com/hashgraph-online/hol-guard/commit/c7dc7dc826a5ddfb15e50614f622c52c426e2d82))
* **hooks:** answer Windows hooks on the resident direct lane ([#4753](https://github.com/hashgraph-online/hol-guard/issues/4753)) ([2276b1a](https://github.com/hashgraph-online/hol-guard/commit/2276b1a997225762e6e3fa4f53787a9d0ebf47b3))
* **hooks:** compose artifact-hook saved reuse in the saved-decision lookup ([#4805](https://github.com/hashgraph-online/hol-guard/issues/4805)) ([e96215c](https://github.com/hashgraph-online/hol-guard/commit/e96215c96bff0d82877f396031c2a349e9047c9e))
* **hooks:** reach the resident from an installed frozen Guard's hook command ([#4773](https://github.com/hashgraph-online/hol-guard/issues/4773)) ([f4178bd](https://github.com/hashgraph-online/hol-guard/commit/f4178bdf68349700daba2d2545905a6c5f7c6912))
* **hooks:** record and grant local CLIs in one resident call ([#4811](https://github.com/hashgraph-online/hol-guard/issues/4811)) ([354e058](https://github.com/hashgraph-online/hol-guard/commit/354e058ed2e7b3d639a16160f525073eb4b553b0))
* **hooks:** review Pi and Oh My Pi file reads in the resident runtime ([#4750](https://github.com/hashgraph-online/hol-guard/issues/4750)) ([7b13fb3](https://github.com/hashgraph-online/hol-guard/commit/7b13fb365e277978ab6ef3edeb8844cab1cfd0b4))


### Dependencies

* **actions:** bump astral-sh/setup-uv from 6.8.0 to 10.3.0 ([a8ef2a1](https://github.com/hashgraph-online/hol-guard/commit/a8ef2a17b6c0a0af6defb130ba2075a8b42307b2))

## [3.46.0](https://github.com/hashgraph-online/hol-guard/compare/v3.45.0...v3.46.0) (2026-10-15)


### Features

* **extensions:** add DataMan command safety extension and fixtures ([#3047](https://github.com/hashgraph-online/hol-guard/issues/3047)) ([8decf71](https://github.com/hashgraph-online/hol-guard/commit/8decf71a6ea785adeba647909dbf90bd9c6f9f13))
* **extensions:** add MusicContext publisher listing ([#3750](https://github.com/hashgraph-online/hol-guard/issues/3750)) ([634af9a](https://github.com/hashgraph-online/hol-guard/commit/634af9af9aea310fbfb2d1192739c965a15aa95f))
* **extensions:** command.faf-cli v1.1.0 — card init, npx --help, one severity re-rate ([#3657](https://github.com/hashgraph-online/hol-guard/issues/3657)) ([aa65550](https://github.com/hashgraph-online/hol-guard/commit/aa655507ea8432c78b327dfe713d5f9b13079189))
* **extensions:** protect DigitalOcean doctl operations and reproduce real false-positive shapes in the Gauntlet ([#4694](https://github.com/hashgraph-online/hol-guard/issues/4694)) ([0699f15](https://github.com/hashgraph-online/hol-guard/commit/0699f15ebc4217fbc50a3b0593259ef740af0457))
* **guard-policy:** author, test and explain policies from the command line ([#4716](https://github.com/hashgraph-online/hol-guard/issues/4716)) ([29f41c0](https://github.com/hashgraph-online/hol-guard/commit/29f41c002535353ae1945c90881021ee0399e8d3))
* **guard:** prepare contained Linux launches in the native runtime ([#4692](https://github.com/hashgraph-online/hol-guard/issues/4692)) ([c7a62c1](https://github.com/hashgraph-online/hol-guard/commit/c7a62c13cd9d651b3a9b0357cccd1d06d1a2da76))
* **guard:** write dashboard settings through the native runtime ([#4701](https://github.com/hashgraph-online/hol-guard/issues/4701)) ([392956f](https://github.com/hashgraph-online/hol-guard/commit/392956f5c286c4a8f02124d795d56df99e03c057))
* **mcp:** add Plim MCP server contribution ([#3372](https://github.com/hashgraph-online/hol-guard/issues/3372)) ([bf7b6bb](https://github.com/hashgraph-online/hol-guard/commit/bf7b6bb90077dbb7c6d6927da8cebbfd9f684d0d))
* **pi:** answer Pi and Oh My Pi hooks through the native runtime ([#4745](https://github.com/hashgraph-online/hol-guard/issues/4745)) ([66d79ae](https://github.com/hashgraph-online/hol-guard/commit/66d79ae246375d38031b0236586fe626aeb39e53))
* **runtime:** answer more hooks in the native bridges instead of running Python ([#4689](https://github.com/hashgraph-online/hol-guard/issues/4689)) ([eb064ce](https://github.com/hashgraph-online/hol-guard/commit/eb064ced0bdaf0c48c8cdb05a26c7c7fbff74593))
* **runtime:** route frozen Desktop hooks through the native bridges ([#4739](https://github.com/hashgraph-online/hol-guard/issues/4739)) ([93550a4](https://github.com/hashgraph-online/hol-guard/commit/93550a4a9110824273745d6abb6f6fb21e1df1f8))


### Bug Fixes

* **ci:** get the nightly native workflow building on macOS and Windows ([#4710](https://github.com/hashgraph-online/hol-guard/issues/4710)) ([d1568ed](https://github.com/hashgraph-online/hol-guard/commit/d1568ed4c6a1e38822107909625e28632e238e9e))
* **dashboard:** rank whole-word search matches first and stop matching inside words ([#4741](https://github.com/hashgraph-online/hol-guard/issues/4741)) ([4918b66](https://github.com/hashgraph-online/hol-guard/commit/4918b663b248999ae6b430b9a631e1fca5fa52d0))
* **guard:** clear Windows false positives for drive paths and stderr redirects ([#4713](https://github.com/hashgraph-online/hol-guard/issues/4713)) ([168f5fa](https://github.com/hashgraph-online/hol-guard/commit/168f5fa9b279426cfed4c2b75f952e1bfc39e141))
* **guard:** keep relative workspace cd builds on the sandbox the sink can run ([#4751](https://github.com/hashgraph-online/hol-guard/issues/4751)) ([8646b82](https://github.com/hashgraph-online/hol-guard/commit/8646b82de083ec7f892f6b40311050d0b17b7073))
* **guard:** keep rg and grep reviewed when they can reach hidden secrets ([#4721](https://github.com/hashgraph-online/hol-guard/issues/4721)) ([3841b78](https://github.com/hashgraph-online/hol-guard/commit/3841b78182912d7ee197c3f19a8541b3a69a5abe))
* **guard:** leave Copilot, Devin and ZCode approval prompts to the harness ([#4742](https://github.com/hashgraph-online/hol-guard/issues/4742)) ([95482e6](https://github.com/hashgraph-online/hol-guard/commit/95482e607a169fdd96519142437328c294551bc9))
* **guard:** let more routine Oh My Pi session work through ([#4718](https://github.com/hashgraph-online/hol-guard/issues/4718)) ([ccbb870](https://github.com/hashgraph-online/hol-guard/commit/ccbb870090472fa3fe620bd9b054f5e5087b750d))
* **guard:** let routine agent work through and fix the macOS and Windows nightly failures ([#4735](https://github.com/hashgraph-online/hol-guard/issues/4735)) ([20fc100](https://github.com/hashgraph-online/hol-guard/commit/20fc100a760dcf3fdc1eddd7e69b7963571c7a0f))
* **guard:** let routine Oh My Pi session work through and review language server edits ([#4695](https://github.com/hashgraph-online/hol-guard/issues/4695)) ([fc575a6](https://github.com/hashgraph-online/hol-guard/commit/fc575a670b329a6b54cfe7c901619942a7f414c6))
* **guard:** make native lib tests platform-aware and judge NTFS stream spellings on Windows ([#4723](https://github.com/hashgraph-online/hol-guard/issues/4723)) ([13fecd0](https://github.com/hashgraph-online/hol-guard/commit/13fecd064a043bd509416e4b5b193570dd80bf50))
* **guard:** quiet temp-root checkouts, test-vector searches and AskUserQuestion prompts ([#4669](https://github.com/hashgraph-online/hol-guard/issues/4669)) ([038cb62](https://github.com/hashgraph-online/hol-guard/commit/038cb62bd6394adeb933b65e3e92164bdf5269ea))
* **guard:** run redirected package commands correctly on macOS ([#4717](https://github.com/hashgraph-online/hol-guard/issues/4717)) ([0b9d7a7](https://github.com/hashgraph-online/hol-guard/commit/0b9d7a757ef12c2019d6f81f67243bf3596a68ca))
* **guard:** run relative cd builds and resolved workspace paths without false blocks, and repair nightly native tests ([#4747](https://github.com/hashgraph-online/hol-guard/issues/4747)) ([a18f3e6](https://github.com/hashgraph-online/hol-guard/commit/a18f3e60302bf71e40959c83c3cccb79a8b6d0f1))
* **guard:** stop flagging credential identifiers in source output as secrets ([#4706](https://github.com/hashgraph-online/hol-guard/issues/4706)) ([a2fa079](https://github.com/hashgraph-online/hol-guard/commit/a2fa079743f735ebc55a39e5555829d38e2f3f92))
* **guard:** stop review reasons from promising an approval that may not help ([#4686](https://github.com/hashgraph-online/hol-guard/issues/4686)) ([612b081](https://github.com/hashgraph-online/hol-guard/commit/612b081e4cab832e57eb0ce7980813cb943c4c04))
* **hooks:** answer Cursor and Grok hooks natively from older installed clients ([#4696](https://github.com/hashgraph-online/hol-guard/issues/4696)) ([153e389](https://github.com/hashgraph-online/hol-guard/commit/153e3893ebf00a9c565799cca145281c5199ce9e))
* **hooks:** wait for the restarted daemon before retrying a Claude hook ([#4738](https://github.com/hashgraph-online/hol-guard/issues/4738)) ([3dd06e3](https://github.com/hashgraph-online/hol-guard/commit/3dd06e36b5696d1d9e1fd827cae99a4541f496e4))
* **policy:** point the editor modeline at the published schema URL ([#4752](https://github.com/hashgraph-online/hol-guard/issues/4752)) ([ef959a4](https://github.com/hashgraph-online/hol-guard/commit/ef959a409c1c21f233bef135e6b393796c7af626))
* **release:** finish a stable release whose plugin-scanner upload stopped partway ([#4674](https://github.com/hashgraph-online/hol-guard/issues/4674)) ([e6d23e2](https://github.com/hashgraph-online/hol-guard/commit/e6d23e2a10e4f43013027976ef93cd250b0e72e2))


### Performance Improvements

* **guard:** answer saved lookups natively when the store holds cloud policy rows ([#4700](https://github.com/hashgraph-online/hol-guard/issues/4700)) ([5db48ad](https://github.com/hashgraph-online/hol-guard/commit/5db48ad3b0fb86ee073972b0648cb388be42880e))
* **guard:** keep saved lookups native when a cached policy bundle has no rows to match ([#4702](https://github.com/hashgraph-online/hol-guard/issues/4702)) ([88f87be](https://github.com/hashgraph-online/hol-guard/commit/88f87be6646897fecf73aa6fb2fdbec37bdc6e4f))
* **guard:** page, count and summarize approval requests in the native runtime ([#4737](https://github.com/hashgraph-online/hol-guard/issues/4737)) ([c296abe](https://github.com/hashgraph-online/hol-guard/commit/c296abe162eb51fad93457a6514da89c429499d5))
* **guard:** read approval requests through the native runtime ([#4731](https://github.com/hashgraph-online/hol-guard/issues/4731)) ([8de0471](https://github.com/hashgraph-online/hol-guard/commit/8de04713cb67ba6aea8da45e2a2bdebc64a99b48))
* **guard:** record approval creation events in the native queue write ([#4726](https://github.com/hashgraph-online/hol-guard/issues/4726)) ([d03b8af](https://github.com/hashgraph-online/hol-guard/commit/d03b8afb24e630b785bb5fb9e5811dba1c3cd926))
* **guard:** resolve a hook's saved decision in one resident call ([#4703](https://github.com/hashgraph-online/hol-guard/issues/4703)) ([7456894](https://github.com/hashgraph-online/hol-guard/commit/74568940ca121863865e202b750e1db177f098f9))
* **guard:** resolve approval scope sweeps in the native runtime ([#4743](https://github.com/hashgraph-online/hol-guard/issues/4743)) ([d32e0ad](https://github.com/hashgraph-online/hol-guard/commit/d32e0ad82f7cc515d24d16d14900f4f394c595a7))
* **guard:** resolve single and duplicate approval requests in the native runtime ([#4744](https://github.com/hashgraph-online/hol-guard/issues/4744)) ([51475ff](https://github.com/hashgraph-online/hol-guard/commit/51475ff73ce0eecdff12aee549ad8b637dd31d4d))
* **guard:** write approval requests through the native runtime ([#4705](https://github.com/hashgraph-online/hol-guard/issues/4705)) ([7266bee](https://github.com/hashgraph-online/hol-guard/commit/7266bee992587bed4b7e0fa8e15f8791fa4dc365))
* **hooks:** start a stopped daemon from the native Claude SessionStart hook ([#4746](https://github.com/hashgraph-online/hol-guard/issues/4746)) ([73df8f7](https://github.com/hashgraph-online/hol-guard/commit/73df8f7bc3c9fa103f80508f8a872420b9d55deb))
* **mcp-relay:** keep sessions native while the direct lane warms up ([#4697](https://github.com/hashgraph-online/hol-guard/issues/4697)) ([546a52f](https://github.com/hashgraph-online/hol-guard/commit/546a52f0bdd33a66d1e189f9545fd61871a1d98a))
* **mcp-relay:** reuse store connections and per-call policy work ([#4699](https://github.com/hashgraph-online/hol-guard/issues/4699)) ([1dc5bbb](https://github.com/hashgraph-online/hol-guard/commit/1dc5bbb12f2deb82fd6e0a323c579875884d75b0))
* **policy:** verify the current snapshot once instead of on every request ([#4698](https://github.com/hashgraph-online/hol-guard/issues/4698)) ([4e251f9](https://github.com/hashgraph-online/hol-guard/commit/4e251f98435b0c2496a7233dfbf407bf1f274750))
* **runtime:** answer reviews natively in homes with custom CLI rules when the command launches no local CLI ([#4719](https://github.com/hashgraph-online/hol-guard/issues/4719)) ([a9bc54b](https://github.com/hashgraph-online/hol-guard/commit/a9bc54b2d1028db1b88a07881202fd15fdfaf903))
* **runtime:** answer the first hook in a new file-less directory on the current policy snapshot ([#4727](https://github.com/hashgraph-online/hol-guard/issues/4727)) ([74d1f03](https://github.com/hashgraph-online/hol-guard/commit/74d1f03952e58f4403069eda7d6cbd42d0ed2d70))
* **runtime:** block custom-rule launches the resident cannot verify in the native hook ([#4724](https://github.com/hashgraph-online/hol-guard/issues/4724)) ([322ba87](https://github.com/hashgraph-online/hol-guard/commit/322ba876493f38fd57fbe8e5acf260ba2f5033b0))
* **runtime:** keep hooks on the direct lane while a new policy ACK lands ([#4728](https://github.com/hashgraph-online/hol-guard/issues/4728)) ([410e033](https://github.com/hashgraph-online/hol-guard/commit/410e033638f9b675126e77b2040d59f7e9b8738c))
* **runtime:** run npm -C and pnpm -C package scripts on the native contained sink ([#4730](https://github.com/hashgraph-online/hol-guard/issues/4730)) ([1e90d0a](https://github.com/hashgraph-online/hol-guard/commit/1e90d0abbabb3c75e0db1e808f0962556c3442ea))
* **runtime:** run package scripts in a workspace subdirectory in the native sink ([#4722](https://github.com/hashgraph-online/hol-guard/issues/4722)) ([d7b6faa](https://github.com/hashgraph-online/hol-guard/commit/d7b6faa75742cc150bb9d734c391542da96f8db8))
* **runtime:** run piped, stderr-folded and status-reading workspace commands in the native sink ([#4720](https://github.com/hashgraph-online/hol-guard/issues/4720)) ([956888b](https://github.com/hashgraph-online/hol-guard/commit/956888be72d6b8aa3f49dfc22c9e5eba4c73a4ab))
* **runtime:** run workspace commands that cd into a subdirectory in the native sink ([#4709](https://github.com/hashgraph-online/hol-guard/issues/4709)) ([afed27c](https://github.com/hashgraph-online/hol-guard/commit/afed27cbd4d1f1de103b8d4915fb532581c52a6d))
* **runtime:** run workspace-contained shell commands in the native runtime ([#4704](https://github.com/hashgraph-online/hol-guard/issues/4704)) ([3307eea](https://github.com/hashgraph-online/hol-guard/commit/3307eea504e1dfd79e548c28d65cde1e98012e1a))


### Documentation

* **policy:** describe Policy Studio and import as GuardPolicy authors ([#4729](https://github.com/hashgraph-online/hol-guard/issues/4729)) ([06cb740](https://github.com/hashgraph-online/hol-guard/commit/06cb7403c27d9e865d0ea43e2b3df66f1cd56ba1))

## [3.45.0](https://github.com/hashgraph-online/hol-guard/compare/v3.44.0...v3.45.0) (2026-10-14)


### Features

* **copilot:** move Copilot config discovery into the native resident ([#4572](https://github.com/hashgraph-online/hol-guard/issues/4572)) ([9e89252](https://github.com/hashgraph-online/hol-guard/commit/9e89252b729ec0f4a65f21f8fbd89dad7cf115ce))
* **cursor:** post deferred Cursor hooks to the Guard daemon natively ([#4617](https://github.com/hashgraph-online/hol-guard/issues/4617)) ([4cc2e22](https://github.com/hashgraph-online/hol-guard/commit/4cc2e222951f59193aed9c214a1946ca7c7361ca))
* **discovery:** sponsored extension discovery (native op, daemon transport, Discover view) ([#4480](https://github.com/hashgraph-online/hol-guard/issues/4480)) ([a40a351](https://github.com/hashgraph-online/hol-guard/commit/a40a351094639d21cd6f403aa0489d9aff767cfb))
* **guard:** detect Claude Code artifacts in the native resident ([#4583](https://github.com/hashgraph-online/hol-guard/issues/4583)) ([7455d98](https://github.com/hashgraph-online/hol-guard/commit/7455d986637819c5323e6f6e3ea3b099e0e7e078))
* **guard:** detect Cursor and OpenCode artifacts in the resident ([#4607](https://github.com/hashgraph-online/hol-guard/issues/4607)) ([71336f4](https://github.com/hashgraph-online/hol-guard/commit/71336f4e15eb76afbd75773a2ee162a8994006f1))
* **guard:** detect Devin artifacts in the resident ([#4600](https://github.com/hashgraph-online/hol-guard/issues/4600)) ([8ecbc65](https://github.com/hashgraph-online/hol-guard/commit/8ecbc6545137e8a288f3aa4af1076b1516412f97))
* **guard:** detect Gemini and Antigravity artifacts in the resident ([#4586](https://github.com/hashgraph-online/hol-guard/issues/4586)) ([7e34b30](https://github.com/hashgraph-online/hol-guard/commit/7e34b300601872bd26593a3d2c7a9427c7b87cea))
* **guard:** detect Grok and Kimi artifacts in the resident ([#4604](https://github.com/hashgraph-online/hol-guard/issues/4604)) ([be258aa](https://github.com/hashgraph-online/hol-guard/commit/be258aa17faba2f01d49cf493f4257e0dc3b8f0d))
* **guard:** detect OpenClaw gateway, channels, MCP servers and skills in the resident ([#4610](https://github.com/hashgraph-online/hol-guard/issues/4610)) ([1c470bc](https://github.com/hashgraph-online/hol-guard/commit/1c470bcbe01c161f6d393d52f094d66ecfe9b4ca))
* **guard:** detect Pi and Oh My Pi resources in the native runtime ([#4576](https://github.com/hashgraph-online/hol-guard/issues/4576)) ([0be2d91](https://github.com/hashgraph-online/hol-guard/commit/0be2d91bcb011d15c7da9e99344234d838eb4168))
* **guard:** prepare native MCP relay installer selection and measure relay deferrals ([#4564](https://github.com/hashgraph-online/hol-guard/issues/4564)) ([9ad162d](https://github.com/hashgraph-online/hol-guard/commit/9ad162d1f1704c812d85962e272cc351d063acab))
* **guard:** review post-tool output in the resident runtime ([#4622](https://github.com/hashgraph-online/hol-guard/issues/4622)) ([a3f1f7e](https://github.com/hashgraph-online/hol-guard/commit/a3f1f7e7afc771fe626e2932b421b87b25b69889))
* **hook:** answer saved exact-action decisions in Git checkouts with their portable project memory ([#4581](https://github.com/hashgraph-online/hol-guard/issues/4581)) ([83d3ab7](https://github.com/hashgraph-online/hol-guard/commit/83d3ab792015aa120a38d66e2b67f83243d65147))
* **mcp-relay:** advertise the native MCP relay on Unix ([#4612](https://github.com/hashgraph-online/hol-guard/issues/4612)) ([633d0ba](https://github.com/hashgraph-online/hol-guard/commit/633d0ba1ccba819b89f9214336f8ab374728e8c6))
* **mcp-relay:** bind the direct lane before a relay session starts ([#4571](https://github.com/hashgraph-online/hol-guard/issues/4571)) ([09318bc](https://github.com/hashgraph-online/hol-guard/commit/09318bc0b389ed2179e4e1dcdc0e83c76dc7058b))
* **mcp-relay:** decide observe-mode sessions natively ([#4615](https://github.com/hashgraph-online/hol-guard/issues/4615)) ([0d040dd](https://github.com/hashgraph-online/hol-guard/commit/0d040dd4994e03b0d35accc429ff5ff5e855b553))
* **mcp-relay:** run servers with proxy-decided tools under the Python proxy ([#4609](https://github.com/hashgraph-online/hol-guard/issues/4609)) ([d3e0314](https://github.com/hashgraph-online/hol-guard/commit/d3e03148b09811ddc2c8a22fe3c1eb89b230df0d))
* **mcp:** block queued relay calls natively under the safe-alternative mode ([#4603](https://github.com/hashgraph-online/hol-guard/issues/4603)) ([a417893](https://github.com/hashgraph-online/hol-guard/commit/a41789328f79ffecacbe96f918e04f7c1d751e4b))
* **mcp:** claim saved approvals for relayed calls in the resident ([#4566](https://github.com/hashgraph-online/hol-guard/issues/4566)) ([a2c38e0](https://github.com/hashgraph-online/hol-guard/commit/a2c38e066d4830a45442530a0f4a13ac6d938d41))
* **mcp:** decide relayed calls with saved policy decisions in the resident ([#4556](https://github.com/hashgraph-online/hol-guard/issues/4556)) ([b9e61c7](https://github.com/hashgraph-online/hol-guard/commit/b9e61c7a44257d9adbe21bcf7c3ec486eb8317bd))
* **mcp:** decide relayed MCP tool calls in the resident with one round trip ([#4546](https://github.com/hashgraph-online/hol-guard/issues/4546)) ([5e38fea](https://github.com/hashgraph-online/hol-guard/commit/5e38feaf4ef842daa512f4fe62476f31aa650fa6))
* **mcp:** decide relayed shell and command calls that install no package ([#4570](https://github.com/hashgraph-online/hol-guard/issues/4570)) ([a058b1e](https://github.com/hashgraph-online/hol-guard/commit/a058b1e0566c230b17a655a8604de9b27270de01))
* **mcp:** hand relay sessions the resident cannot decide to the Python proxy at startup ([#4606](https://github.com/hashgraph-online/hol-guard/issues/4606)) ([9408952](https://github.com/hashgraph-online/hol-guard/commit/94089521bfa8dc956ebf5340bf345ff6b574210a))
* **relay:** answer saved workspace lookups for Git checkouts in the native relay ([#4579](https://github.com/hashgraph-online/hol-guard/issues/4579)) ([f234757](https://github.com/hashgraph-online/hol-guard/commit/f23475748801588223eccb521a4b2f4264351753))


### Bug Fixes

* **dashboard:** keep the home screen working after a Guard update ([#4561](https://github.com/hashgraph-online/hol-guard/issues/4561)) ([321a9a2](https://github.com/hashgraph-online/hol-guard/commit/321a9a22cbb2b1aae6e5696c2d62e94ee9dbb85f))
* **gauntlet:** repair the Claude Code and Codex lanes on macOS and accept Oh My Pi's default task agent ([#4567](https://github.com/hashgraph-online/hol-guard/issues/4567)) ([d9aa883](https://github.com/hashgraph-online/hol-guard/commit/d9aa88332ed8517b9646dc6fbf03fda6e392e0bd))
* **guard:** accept a trusted KUBECONFIG prefix on kubectl reads ([#4639](https://github.com/hashgraph-online/hol-guard/issues/4639)) ([7c3023f](https://github.com/hashgraph-online/hol-guard/commit/7c3023f9252d2d52c44fb265828413aebcd89d9b))
* **guard:** accept bundled short flags in git branch listings ([#4644](https://github.com/hashgraph-online/hol-guard/issues/4644)) ([d8179d5](https://github.com/hashgraph-online/hol-guard/commit/d8179d56964a8b2018cc584f17a9c30a88ca2ffb))
* **guard:** allow bounded kubectl logs reads and opening the Guard dashboard ([#4588](https://github.com/hashgraph-online/hol-guard/issues/4588)) ([8a02fe7](https://github.com/hashgraph-online/hol-guard/commit/8a02fe783b36ad19c3520ee3fe80f0f38bdf152f))
* **guard:** allow cd-semicolon chains, awk reads and rustfmt in sibling repositories ([#4493](https://github.com/hashgraph-online/hol-guard/issues/4493)) ([6c31949](https://github.com/hashgraph-online/hol-guard/commit/6c31949dc8dde39cd6f6ca43f9b2a2377c0fa8e0))
* **guard:** allow copying scratch checkout files into the workspace ([#4547](https://github.com/hashgraph-online/hol-guard/issues/4547)) ([dadd721](https://github.com/hashgraph-online/hol-guard/commit/dadd72175d0533f860ed3922ecf145c03890c91c))
* **guard:** allow curl to print response headers ([#4589](https://github.com/hashgraph-online/hol-guard/issues/4589)) ([3692383](https://github.com/hashgraph-online/hol-guard/commit/369238344524edba8a9f9bdf75684cb3c44852fa))
* **guard:** allow git -C reads in the checkout a worktree add creates ([#4656](https://github.com/hashgraph-online/hol-guard/issues/4656)) ([cc79940](https://github.com/hashgraph-online/hol-guard/commit/cc79940ccd1c8f8cd368949dc0c3a4515ab68901))
* **guard:** allow git worktree add -b from a plain branch name ([#4548](https://github.com/hashgraph-online/hol-guard/issues/4548)) ([e3d6c0c](https://github.com/hashgraph-online/hol-guard/commit/e3d6c0cd7c8da57d8d2be90fe531cced75ada697))
* **guard:** allow listing a sibling checkout's tool bin directory and screen autostart worktree targets ([#4542](https://github.com/hashgraph-online/hol-guard/issues/4542)) ([78e48f3](https://github.com/hashgraph-online/hol-guard/commit/78e48f3bf15ef79032ee7f3fb5fb3172cc35221f))
* **guard:** allow reading installed package and toolchain source below hidden home dirs ([#4532](https://github.com/hashgraph-online/hol-guard/issues/4532)) ([0cb9e53](https://github.com/hashgraph-online/hol-guard/commit/0cb9e535270a364436ad496c78b68f1125cfc5a8))
* **guard:** allow saving read output to a workspace scratch file ([#4543](https://github.com/hashgraph-online/hol-guard/issues/4543)) ([0485400](https://github.com/hashgraph-online/hol-guard/commit/048540083426f5b7aaf8e1ce0f6f5add5741aabb))
* **guard:** allow secret-free review conversation on the current repository ([#4545](https://github.com/hashgraph-online/hol-guard/issues/4545)) ([9643913](https://github.com/hashgraph-online/hol-guard/commit/964391316594a96b3fda6b766dfcc4ca54866153))
* **guard:** contain one command after a cd below a sibling repository root on Linux ([#4536](https://github.com/hashgraph-online/hol-guard/issues/4536)) ([a1af5f6](https://github.com/hashgraph-online/hol-guard/commit/a1af5f6eb4ced2494e1ba7d8fecd447c6b2cf799))
* **guard:** decide a trailing subshell group by its command list ([#4517](https://github.com/hashgraph-online/hol-guard/issues/4517)) ([2f3a092](https://github.com/hashgraph-online/hol-guard/commit/2f3a092543887240e5327f0c7103aa1f1ce1e6bc))
* **guard:** explain a denied write after a contained run fails ([#4642](https://github.com/hashgraph-online/hol-guard/issues/4642)) ([d80c5be](https://github.com/hashgraph-online/hol-guard/commit/d80c5bed5e7623c1f8a2c9c3d03fdac32d5c553d))
* **guard:** give bridged OMP eval shell calls their standalone containment ([#4630](https://github.com/hashgraph-online/hol-guard/issues/4630)) ([be3b405](https://github.com/hashgraph-online/hol-guard/commit/be3b405aa8b3056272fe9cea20ab304834868834))
* **guard:** honor refused retries and avoid impossible approval waits ([#4634](https://github.com/hashgraph-online/hol-guard/issues/4634)) ([f15903f](https://github.com/hashgraph-online/hol-guard/commit/f15903f9e55c80381ba3b0d8a49c5f0c85a1d9c2))
* **guard:** judge cd-chained Git reads where the shell runs them ([#4590](https://github.com/hashgraph-online/hol-guard/issues/4590)) ([5086497](https://github.com/hashgraph-online/hol-guard/commit/50864978a9c14475323f9a2a8432e3397c4dc9cd))
* **guard:** judge Oh My Pi bash commands in their directory and explain missing paths ([#4565](https://github.com/hashgraph-online/hol-guard/issues/4565)) ([63a971d](https://github.com/hashgraph-online/hol-guard/commit/63a971d3faa3ee110b68567312d1299999849d34))
* **guard:** judge work in a linked worktree beside the checkout ([#4577](https://github.com/hashgraph-online/hol-guard/issues/4577)) ([78aef15](https://github.com/hashgraph-online/hol-guard/commit/78aef15fc81a561cc2bce4c3b855793aadaa3e2d))
* **guard:** keep a Git read's proof after a proven worktree add ([#4650](https://github.com/hashgraph-online/hol-guard/issues/4650)) ([152199f](https://github.com/hashgraph-online/hol-guard/commit/152199f69b11e5f1af34c0e20a908efaf5b46dbf))
* **guard:** keep agent plan documents readable outside the workspace ([#4544](https://github.com/hashgraph-online/hol-guard/issues/4544)) ([2600d71](https://github.com/hashgraph-online/hol-guard/commit/2600d71a72080388f739719e3ee586f780c4dfaf))
* **guard:** keep contained-test requests for backgrounded OMP calls ([#4649](https://github.com/hashgraph-online/hol-guard/issues/4649)) ([a0d0fea](https://github.com/hashgraph-online/hol-guard/commit/a0d0fea4773244d4b59f4a075fcc701132d89c40))
* **guard:** keep the worktree commit proof after removing its dependency link ([#4598](https://github.com/hashgraph-online/hol-guard/issues/4598)) ([6ce914c](https://github.com/hashgraph-online/hol-guard/commit/6ce914c55831e676426feae1aee2831496f90bda))
* **guard:** let agents inspect a scratch checkout through a rooted parent path ([#4538](https://github.com/hashgraph-online/hol-guard/issues/4538)) ([39d81c9](https://github.com/hashgraph-online/hol-guard/commit/39d81c96d5ef50431f236f2b3ba8e21cb32ba853))
* **guard:** let agents start existing Docker containers without review ([#4620](https://github.com/hashgraph-online/hol-guard/issues/4620)) ([d40f693](https://github.com/hashgraph-online/hol-guard/commit/d40f69350fd7900dca1cb34d6208535d6d4f31c8))
* **guard:** let an explicit extension Allow take precedence over native command review ([#4554](https://github.com/hashgraph-online/hol-guard/issues/4554)) ([daf63d2](https://github.com/hashgraph-online/hol-guard/commit/daf63d2d6cdd166d9889eccabafe862f692e0c0f))
* **guard:** let an Oh My Pi glob list name files that do not exist ([#4647](https://github.com/hashgraph-online/hol-guard/issues/4647)) ([1846434](https://github.com/hashgraph-online/hol-guard/commit/18464343df2a3b94d7e7445674ee958695120bf9))
* **guard:** let an Oh My Pi grep take a file line range ([#4648](https://github.com/hashgraph-online/hol-guard/issues/4648)) ([ddf1275](https://github.com/hashgraph-online/hol-guard/commit/ddf1275bcc2b34970161fe068b4913344b6472d2))
* **guard:** let Codex apply_patch edit sibling projects in the home directory ([#4594](https://github.com/hashgraph-online/hol-guard/issues/4594)) ([d80e0e9](https://github.com/hashgraph-online/hol-guard/commit/d80e0e98a3d8591df910f717542eba9adfa0eaa0))
* **guard:** let npm cache ls run as a read-only query ([#4597](https://github.com/hashgraph-online/hol-guard/issues/4597)) ([3293ad4](https://github.com/hashgraph-online/hol-guard/commit/3293ad4b99116644c10fb58e08b5820da12c8d0c))
* **guard:** let Oh My Pi search and list ordinary workspaces ([#4627](https://github.com/hashgraph-online/hol-guard/issues/4627)) ([4dd0a9e](https://github.com/hashgraph-online/hol-guard/commit/4dd0a9ea45029f191d5b9d48d32b81a85c646cb1))
* **guard:** let proven Git commands share a chain with mkdir ([#4574](https://github.com/hashgraph-online/hol-guard/issues/4574)) ([e899e55](https://github.com/hashgraph-online/hol-guard/commit/e899e55c006ec2c325dd48dedb8b30315ad17c32))
* **guard:** let test files use values that say they are fake ([#4625](https://github.com/hashgraph-online/hol-guard/issues/4625)) ([4e04e6e](https://github.com/hashgraph-online/hol-guard/commit/4e04e6e18b6722cdc588f5ecb3a28c091f9d2322))
* **guard:** let the workspace sandbox list the directories above it ([#4652](https://github.com/hashgraph-online/hol-guard/issues/4652)) ([2fea681](https://github.com/hashgraph-online/hol-guard/commit/2fea6814533b0cc429f6c8defbea30126641da34))
* **guard:** name the no-script install when the package script setting holds an install ([#4623](https://github.com/hashgraph-online/hol-guard/issues/4623)) ([290e7d1](https://github.com/hashgraph-online/hol-guard/commit/290e7d19f1ca13d4ba5a2f4150b8c7880e466d2f))
* **guard:** name the sensitive file behind an Oh My Pi search review ([#4646](https://github.com/hashgraph-online/hol-guard/issues/4646)) ([81d1ab1](https://github.com/hashgraph-online/hol-guard/commit/81d1ab1433aa8a70e856369ddb74728f88c8e552))
* **guard:** pass the host's error through when a read names a missing file ([#4613](https://github.com/hashgraph-online/hol-guard/issues/4613)) ([0f68b79](https://github.com/hashgraph-online/hol-guard/commit/0f68b79ff7727ce1223691236c91b5b7e6af0188))
* **guard:** point a held omp eval to the bash tool ([#4637](https://github.com/hashgraph-online/hol-guard/issues/4637)) ([06b4659](https://github.com/hashgraph-online/hol-guard/commit/06b4659f94075f901b9c7115f50201613767b283))
* **guard:** prove git show-ref and for-each-ref listings as reads ([#4587](https://github.com/hashgraph-online/hol-guard/issues/4587)) ([9aad1b2](https://github.com/hashgraph-online/hol-guard/commit/9aad1b22725b89cba82909e7907e4dc997d65b4f))
* **guard:** prove merges, cherry-picks and merge pulls in sibling checkouts ([#4585](https://github.com/hashgraph-online/hol-guard/issues/4585)) ([d5825ce](https://github.com/hashgraph-online/hol-guard/commit/d5825ce3b01fd16973e3270d242d0091041b1b4a))
* **guard:** prove Oh My Pi globs for a literal file name in the session ([#4645](https://github.com/hashgraph-online/hol-guard/issues/4645)) ([dac591f](https://github.com/hashgraph-online/hol-guard/commit/dac591f99e0020790b2bca8a43a300d96c06760f))
* **guard:** prove plain git rev-list commit walks read-only ([#4643](https://github.com/hashgraph-online/hol-guard/issues/4643)) ([0f9e0e9](https://github.com/hashgraph-online/hol-guard/commit/0f9e0e904869662f82bb5b92aebc894041785818))
* **guard:** prove publish chains behind a TLS proxy and identity-only git -c commits ([#4578](https://github.com/hashgraph-online/hol-guard/issues/4578)) ([7613367](https://github.com/hashgraph-online/hol-guard/commit/7613367b79090ea432b18e42ca274b54d992c351))
* **guard:** prove read fallbacks, scratch log captures, glob copies and home worktrees ([#4601](https://github.com/hashgraph-online/hol-guard/issues/4601)) ([b302841](https://github.com/hashgraph-online/hol-guard/commit/b30284187e8fb6b28dd20fbcf22919540df43e6d))
* **guard:** prove routine Oh My Pi hashline edits ([#4640](https://github.com/hashgraph-online/hol-guard/issues/4640)) ([4c664bc](https://github.com/hashgraph-online/hol-guard/commit/4c664bcf7464ac5185e2199126cdeb88f743965d))
* **guard:** prove semicolon path lists and brace globs in Oh My Pi search tools ([#4559](https://github.com/hashgraph-online/hol-guard/issues/4559)) ([23c29b8](https://github.com/hashgraph-online/hol-guard/commit/23c29b8565cdda2844b7d9d468c5ea373bd74d1b))
* **guard:** publish the current policy-integrity state with the direct lane ([#4580](https://github.com/hashgraph-online/hol-guard/issues/4580)) ([5a0d710](https://github.com/hashgraph-online/hol-guard/commit/5a0d710a6bedc7726cf4454bbf168d086cd86837))
* **guard:** read quoted brackets and escaped code spans in gh comment bodies as text ([#4602](https://github.com/hashgraph-online/hol-guard/issues/4602)) ([b73e755](https://github.com/hashgraph-online/hol-guard/commit/b73e755ce503f4a119d05e2181b23d1474d5bf16))
* **guard:** retire resident client streams left idle for 30 seconds ([#4626](https://github.com/hashgraph-online/hol-guard/issues/4626)) ([b7541f0](https://github.com/hashgraph-online/hol-guard/commit/b7541f084d4c4622377793ebdf2e081cb89a013c))
* **guard:** review a line-numbered source slice by the lines it shows ([#4584](https://github.com/hashgraph-online/hol-guard/issues/4584)) ([9ac60c8](https://github.com/hashgraph-online/hol-guard/commit/9ac60c8580fd19e4e2019e62b92753c94a313abe))
* **guard:** review an anchored source slice one run of lines at a time ([#4635](https://github.com/hashgraph-online/hol-guard/issues/4635)) ([a81b15e](https://github.com/hashgraph-online/hol-guard/commit/a81b15ed444447d5c1a8bf14be9316f9ec975050))
* **guard:** review shell reads of secrets reached through a symbolic link ([#4568](https://github.com/hashgraph-online/hol-guard/issues/4568)) ([9808583](https://github.com/hashgraph-online/hol-guard/commit/98085837e867584eeaa6ebaf3c3b8dde10e5a186))
* **guard:** review writes into a repository's configured hooks directory ([#4551](https://github.com/hashgraph-online/hol-guard/issues/4551)) ([303ec66](https://github.com/hashgraph-online/hol-guard/commit/303ec66f5e9fb0ce9824b3b8d7c8691c1ea23be8))
* **guard:** run a contained test in the directory Oh My Pi's bash names ([#4618](https://github.com/hashgraph-online/hol-guard/issues/4618)) ([cd82b93](https://github.com/hashgraph-online/hol-guard/commit/cd82b93dfc8bb5fbcccef7fa160cd7d8daa13593))
* **guard:** run commands that write under $TMPDIR in the workspace sandbox ([#4651](https://github.com/hashgraph-online/hol-guard/issues/4651)) ([45d6fbe](https://github.com/hashgraph-online/hol-guard/commit/45d6fbefb94ddddc2c12f78f99eac0e1866dabd3))
* **guard:** run contained Python tests from an active virtual environment ([#4592](https://github.com/hashgraph-online/hol-guard/issues/4592)) ([c9cf15c](https://github.com/hashgraph-online/hol-guard/commit/c9cf15cbbeb4a5bb921541fee54b079ae760eadb))
* **guard:** say when an Oh My Pi grep list names a missing path ([#4621](https://github.com/hashgraph-online/hol-guard/issues/4621)) ([4e6e1fe](https://github.com/hashgraph-online/hol-guard/commit/4e6e1fe7e5feab930810d5cb619c01352d935b84))
* **guard:** screen host file-tool writes that name a parent folder ([#4629](https://github.com/hashgraph-online/hol-guard/issues/4629)) ([00bc052](https://github.com/hashgraph-online/hol-guard/commit/00bc052b7a4846087c4df5ea1378dc1e0cd23dc7))
* **guard:** stop flagging credential field copies as secrets ([#4655](https://github.com/hashgraph-online/hol-guard/issues/4655)) ([b9caaac](https://github.com/hashgraph-online/hol-guard/commit/b9caaac416acca95338c46c882d064a5dc4cac45))
* **guard:** stop flagging credential references in source as secrets ([#4582](https://github.com/hashgraph-online/hol-guard/issues/4582)) ([603a2e5](https://github.com/hashgraph-online/hol-guard/commit/603a2e55c661910f43dd4994dc804e79edda6963))
* **guard:** stop treating stand-in fixture credentials as secret output ([#4624](https://github.com/hashgraph-online/hol-guard/issues/4624)) ([6cfd07a](https://github.com/hashgraph-online/hol-guard/commit/6cfd07a010ee822d824b042a71ccbcddd41947da))
* **guard:** tell agents how to narrow a held search ([#4632](https://github.com/hashgraph-online/hol-guard/issues/4632)) ([60f093f](https://github.com/hashgraph-online/hol-guard/commit/60f093f82bb6c3c32362221b0cee8c06e67374a1))
* **guard:** treat `test -x`, `test -s` and `[ ... ]` probes as reads ([#4654](https://github.com/hashgraph-online/hol-guard/issues/4654)) ([7e4c84a](https://github.com/hashgraph-online/hol-guard/commit/7e4c84a8c2ff2d55c19d85a71efa3ad6249b45e3))
* **guard:** treat clearing Git commit identity as an inert env prefix ([#4653](https://github.com/hashgraph-online/hol-guard/issues/4653)) ([1d6abc8](https://github.com/hashgraph-online/hol-guard/commit/1d6abc8f10cccf225c7f414a36611228f6b52c2b))
* **guard:** treat git remote get-url as a read-only Git command ([#4562](https://github.com/hashgraph-online/hol-guard/issues/4562)) ([1015575](https://github.com/hashgraph-online/hol-guard/commit/101557508105a64555daef20d44f875398aecdc8))
* **guard:** treat tr and base64 as stdin filters after a proven read ([#4552](https://github.com/hashgraph-online/hol-guard/issues/4552)) ([4e66ade](https://github.com/hashgraph-online/hol-guard/commit/4e66ade03dba68679fa15c817f92a98d255af454))
* **pi:** run routine test and build commands contained instead of asking ([#4614](https://github.com/hashgraph-online/hol-guard/issues/4614)) ([32f69e8](https://github.com/hashgraph-online/hol-guard/commit/32f69e87bf9452f253a0a25620b5972245a194b9))
* **release:** give native wheel jobs time to compile on repair dispatches ([#4557](https://github.com/hashgraph-online/hol-guard/issues/4557)) ([888a22f](https://github.com/hashgraph-online/hol-guard/commit/888a22f8e2b7e49bfa6cd3d8072fa6e72c5a08eb))
* **release:** raise native wheel size budgets so 3.44 can publish ([#4553](https://github.com/hashgraph-online/hol-guard/issues/4553)) ([64b5fdf](https://github.com/hashgraph-online/hol-guard/commit/64b5fdf03e37cf2167a0bb75764defe3ffaaa83b))
* **runtime:** bind the Claude hook bridge to Windows Guard homes ([#4558](https://github.com/hashgraph-online/hol-guard/issues/4558)) ([ab3acad](https://github.com/hashgraph-online/hol-guard/commit/ab3acad65507ef76cb7e40079bf959832c7364cf))
* **windows:** run Claude Code Python test scripts in an AppContainer ([#4573](https://github.com/hashgraph-online/hol-guard/issues/4573)) ([74da922](https://github.com/hashgraph-online/hol-guard/commit/74da922013315c3750d675ea43a328282ff8f3d6))


### Performance Improvements

* **bench:** attribute warm-path service CPU and memory per process role ([#4638](https://github.com/hashgraph-online/hol-guard/issues/4638)) ([bec6bab](https://github.com/hashgraph-online/hol-guard/commit/bec6babd47806e2ee6ae2e134768975d63fd404a))
* **claude:** answer no-op Claude session starts from the native runtime ([#4599](https://github.com/hashgraph-online/hol-guard/issues/4599)) ([a063dff](https://github.com/hashgraph-online/hol-guard/commit/a063dfffbc12865a09099359a923138deb24f32f))
* **cli:** show hol-guard help without loading the Guard runtime ([#4631](https://github.com/hashgraph-online/hol-guard/issues/4631)) ([d02b6fc](https://github.com/hashgraph-online/hol-guard/commit/d02b6fc8f843b2a63f7e1afb2d2b53b9c5089e3f))
* **codex:** answer Codex tool blocks without starting Python ([#4591](https://github.com/hashgraph-online/hol-guard/issues/4591)) ([2fd9f51](https://github.com/hashgraph-online/hol-guard/commit/2fd9f519c1c6cc9a9338a2be78d41430a348f24a))
* **guard:** answer hooks run from a plain project subdirectory without starting Python ([#4593](https://github.com/hashgraph-online/hol-guard/issues/4593)) ([8570458](https://github.com/hashgraph-online/hol-guard/commit/8570458479a99205489fe3aa1ad643465458870c))
* **guard:** count how direct hooks are answered or deferred, for diagnostics ([#4595](https://github.com/hashgraph-online/hol-guard/issues/4595)) ([285a808](https://github.com/hashgraph-online/hol-guard/commit/285a808d3dc915fb9398d4d96ebe50be70318e2d))
* **runtime:** embed command data compressed and hash rule sources at build time ([#4563](https://github.com/hashgraph-online/hol-guard/issues/4563)) ([f3fbd2f](https://github.com/hashgraph-online/hol-guard/commit/f3fbd2fef67e608999aafae8fd6736cdf810bc38))

## [3.44.0](https://github.com/hashgraph-online/hol-guard/compare/v3.43.1...v3.44.0) (2026-10-14)


### Features

* **guard:** answer allowed Cursor hooks from the resident ([#4368](https://github.com/hashgraph-online/hol-guard/issues/4368)) ([da836f2](https://github.com/hashgraph-online/hol-guard/commit/da836f265f574865eadd575c6d44041c5934a4ed))
* **guard:** answer bounded CLI hooks from the native runtime ([#4313](https://github.com/hashgraph-online/hol-guard/issues/4313)) ([32965d1](https://github.com/hashgraph-online/hol-guard/commit/32965d19b3563da3f6f609ee819d66558385fa0a))
* **guard:** answer bounded harness hooks from the resident ([#4373](https://github.com/hashgraph-online/hol-guard/issues/4373)) ([dffbc65](https://github.com/hashgraph-online/hol-guard/commit/dffbc65a6bd2959dcb13f96f20002d8fcd979f53))
* **guard:** answer Claude permission dialogs without a Guard notice from the resident ([#4395](https://github.com/hashgraph-online/hol-guard/issues/4395)) ([55a0e9e](https://github.com/hashgraph-online/hol-guard/commit/55a0e9e56433248094e6a8a58c403bbaa3a47a9c))
* **guard:** answer Claude permission prompt notifications from the resident ([#4403](https://github.com/hashgraph-online/hol-guard/issues/4403)) ([956987b](https://github.com/hashgraph-online/hol-guard/commit/956987b8b9431e8c8407a1edc691c856018f143c))
* **guard:** answer Claude permission requests with a pending notice from the resident ([#4399](https://github.com/hashgraph-online/hol-guard/issues/4399)) ([2a4f5f9](https://github.com/hashgraph-online/hol-guard/commit/2a4f5f918105170f68b4966229a8711c1f500e67))
* **guard:** answer Claude prompts that carry Guard's notice from the resident ([#4405](https://github.com/hashgraph-online/hol-guard/issues/4405)) ([220c3b9](https://github.com/hashgraph-online/hol-guard/commit/220c3b9c4195e4d09e51f3a13580985501315dbd))
* **guard:** answer Cline hooks from the native bounded bridge ([#4316](https://github.com/hashgraph-online/hol-guard/issues/4316)) ([653dcfa](https://github.com/hashgraph-online/hol-guard/commit/653dcfa829d260ead89b5863936c441fa97cd8aa))
* **guard:** answer Codex pre-tool allows from the resident ([#4326](https://github.com/hashgraph-online/hol-guard/issues/4326)) ([bac4a5c](https://github.com/hashgraph-online/hol-guard/commit/bac4a5c5cefd7555ca8c613982ff1901d0df2cba))
* **guard:** answer Cursor after-shell and after-MCP observers in the native bridge ([#4416](https://github.com/hashgraph-online/hol-guard/issues/4416)) ([551d693](https://github.com/hashgraph-online/hol-guard/commit/551d693e9630c21c450fd58de19616db91d587ef))
* **guard:** answer Cursor reviews and prompts from the resident ([#4488](https://github.com/hashgraph-online/hol-guard/issues/4488)) ([9d117de](https://github.com/hashgraph-online/hol-guard/commit/9d117de466f2cbecfe205c81ee6db00a25b62097))
* **guard:** answer Cursor terminal denials from the resident ([#4369](https://github.com/hashgraph-online/hol-guard/issues/4369)) ([69185e2](https://github.com/hashgraph-online/hol-guard/commit/69185e2d92caee2d2f3a15020571818e58b11d58))
* **guard:** answer custom extension blocks in the resident direct hook lane ([#4406](https://github.com/hashgraph-online/hol-guard/issues/4406)) ([2a1804e](https://github.com/hashgraph-online/hol-guard/commit/2a1804ec9ae2f22003c72507605bb1c16fcfc0b1))
* **guard:** answer Grok hooks from the native bounded bridge ([#4319](https://github.com/hashgraph-online/hol-guard/issues/4319)) ([44ceee2](https://github.com/hashgraph-online/hol-guard/commit/44ceee24fe73ed5c8300526f6a3917dec2454038))
* **guard:** answer Grok hooks from the resident ([#4389](https://github.com/hashgraph-online/hol-guard/issues/4389)) ([f3fb11e](https://github.com/hashgraph-online/hol-guard/commit/f3fb11ece1e2deb57a2da75feaf6404661f60d33))
* **guard:** answer Hermes hooks from the native bounded bridge ([#4315](https://github.com/hashgraph-online/hol-guard/issues/4315)) ([cd5583a](https://github.com/hashgraph-online/hol-guard/commit/cd5583a2ddaab914ae61e4792dec90844ca86388))
* **guard:** answer lifecycle hooks from the resident ([#4384](https://github.com/hashgraph-online/hol-guard/issues/4384)) ([bb5af05](https://github.com/hashgraph-online/hol-guard/commit/bb5af051802bb95873411608a357846b936e8fc0))
* **guard:** answer Oh My Pi hooks from the native resident ([#4486](https://github.com/hashgraph-online/hol-guard/issues/4486)) ([cf5f5be](https://github.com/hashgraph-online/hol-guard/commit/cf5f5be73c7a3fd8726d34d3feaea4c804ed7846))
* **guard:** answer OpenCode shell reviews from the native bounded bridge ([#4317](https://github.com/hashgraph-online/hol-guard/issues/4317)) ([383acb7](https://github.com/hashgraph-online/hol-guard/commit/383acb73d33299d4b3871321ca36dc9d5ca36120))
* **guard:** answer PreToolUse hooks under custom extension rules when no local CLI launches ([#4355](https://github.com/hashgraph-online/hol-guard/issues/4355)) ([a39b034](https://github.com/hashgraph-online/hol-guard/commit/a39b03402ac94c854f363e9c3a120d213008816b))
* **guard:** answer reviewed PostToolUse hooks from the resident ([#4337](https://github.com/hashgraph-online/hol-guard/issues/4337)) ([b6e5e53](https://github.com/hashgraph-online/hol-guard/commit/b6e5e536ed93210c46b27fd7ab929af85d235b4d))
* **guard:** answer reviewed UserPromptSubmit hooks from the resident ([#4340](https://github.com/hashgraph-online/hol-guard/issues/4340)) ([d62aab5](https://github.com/hashgraph-online/hol-guard/commit/d62aab544eda1b6b4a71d5ad60e2f2ec05a898b2))
* **guard:** answer saved exact-action decisions for reviewed PreToolUse from the resident ([#4429](https://github.com/hashgraph-online/hol-guard/issues/4429)) ([b2129b7](https://github.com/hashgraph-online/hol-guard/commit/b2129b73b2e3acebd90e74cf250929b6e9474643))
* **guard:** answer sensitive-request classifiers in the native resident ([#4300](https://github.com/hashgraph-online/hol-guard/issues/4300)) ([617cf4c](https://github.com/hashgraph-online/hol-guard/commit/617cf4c4b816bbf9115451c35c449cda87b9e564))
* **guard:** answer terminal PreToolUse blocks from the resident ([#4349](https://github.com/hashgraph-online/hol-guard/issues/4349)) ([216da78](https://github.com/hashgraph-online/hol-guard/commit/216da781694772a2218c703bb8d933b2a13a95fe))
* **guard:** answer warned PreToolUse allows from the resident ([#4347](https://github.com/hashgraph-online/hol-guard/issues/4347)) ([8a35cc5](https://github.com/hashgraph-online/hol-guard/commit/8a35cc53470489ecadecb8dec60d57c7ffb55e69))
* **guard:** answer Watch PreToolUse hooks from the resident ([#4354](https://github.com/hashgraph-online/hol-guard/issues/4354)) ([1230cbc](https://github.com/hashgraph-online/hol-guard/commit/1230cbc5b0a9d855e7245c76dd841a8678b5b2d0))
* **guard:** answer ZCode hooks from the resident ([#4386](https://github.com/hashgraph-online/hol-guard/issues/4386)) ([f1b42fb](https://github.com/hashgraph-online/hol-guard/commit/f1b42fb77f148585961ca41eee7700335d3ca253))
* **guard:** bind policy snapshots to a freshness proof for direct resident hooks ([#4324](https://github.com/hashgraph-online/hol-guard/issues/4324)) ([8bc5ada](https://github.com/hashgraph-online/hol-guard/commit/8bc5adae09d599b72d394816ef76aecee81d504f))
* **guard:** build memory pattern fingerprints in the native runtime ([#4291](https://github.com/hashgraph-online/hol-guard/issues/4291)) ([f8effe3](https://github.com/hashgraph-online/hol-guard/commit/f8effe34b8a51e5854eed7dd50aba8c1444c62b6))
* **guard:** build the reviewed PreToolUse approval request in the resident ([#4452](https://github.com/hashgraph-online/hol-guard/issues/4452)) ([138873e](https://github.com/hashgraph-online/hol-guard/commit/138873e22e015cc8e039372fa2d5a18998d105dc))
* **guard:** compose generic-hook saved decisions in one resident call ([#4397](https://github.com/hashgraph-online/hol-guard/issues/4397)) ([bf37871](https://github.com/hashgraph-online/hol-guard/commit/bf37871219df89d48cd9d30c5c199c30948c3b4a))
* **guard:** fall through temporary workspace roots in the resident direct hook lane ([#4415](https://github.com/hashgraph-online/hol-guard/issues/4415)) ([57bc043](https://github.com/hashgraph-online/hol-guard/commit/57bc04327225225fb553e178a0f51ed3d193803f))
* **guard:** let agents create a private GitHub repository without a prompt ([#4308](https://github.com/hashgraph-online/hol-guard/issues/4308)) ([4829d5d](https://github.com/hashgraph-online/hol-guard/commit/4829d5d2ef91d669d8b00fa405776fb40ea4cf31))
* **guard:** let agents look up npm packages without a prompt ([#4333](https://github.com/hashgraph-online/hol-guard/issues/4333)) ([6451a45](https://github.com/hashgraph-online/hol-guard/commit/6451a459e32aebdfd65ece359cc40bbf64eaf209))
* **guard:** let npm installs that run no package code continue without review ([#4321](https://github.com/hashgraph-online/hol-guard/issues/4321)) ([2baeec7](https://github.com/hashgraph-online/hol-guard/commit/2baeec77853ac1cc7c98fd4390859ec695a27248))
* **guard:** let script-free npm installs with trimmed output continue without review ([#4338](https://github.com/hashgraph-online/hol-guard/issues/4338)) ([07ec707](https://github.com/hashgraph-online/hol-guard/commit/07ec7075f677532a842b3ecc854d2eb3a69a96f4))
* **guard:** pause reviewed PreToolUse hooks with a queued approval from the resident ([#4466](https://github.com/hashgraph-online/hol-guard/issues/4466)) ([90f117d](https://github.com/hashgraph-online/hol-guard/commit/90f117d9dcdfb68f9c918900cf66784863c51acf))
* **guard:** publish the review queue facts in the direct-lane binding ([#4449](https://github.com/hashgraph-online/hol-guard/issues/4449)) ([c8d1d12](https://github.com/hashgraph-online/hol-guard/commit/c8d1d12ce4b5bbe5757be72bd1f22dd35c844db6))
* **guard:** review Cline plugin tool calls through the bounded hook bridge ([#4318](https://github.com/hashgraph-online/hol-guard/issues/4318)) ([787b41c](https://github.com/hashgraph-online/hol-guard/commit/787b41cbe7904afeb63c09fb1c5c37dda1553b9d))
* **guard:** route Claude Code sandbox requirements from the resident ([#4363](https://github.com/hashgraph-online/hol-guard/issues/4363)) ([574bae2](https://github.com/hashgraph-online/hol-guard/commit/574bae2681cf47e287b9c9196bb53df3f3f353e8))
* **guard:** run the Claude hook bridge in the native runtime ([#4305](https://github.com/hashgraph-online/hol-guard/issues/4305)) ([8475a4c](https://github.com/hashgraph-online/hol-guard/commit/8475a4cd9c0c58eb53b164a2e4240c7a15d82552))
* **guard:** run the Codex hook bridge in the native runtime ([#4307](https://github.com/hashgraph-online/hol-guard/issues/4307)) ([b945c4d](https://github.com/hashgraph-online/hol-guard/commit/b945c4d489178467f73fd0cfb7a5fa389eac5872))
* **guard:** run unproven local commands in a workspace sandbox instead of asking ([#4299](https://github.com/hashgraph-online/hol-guard/issues/4299)) ([2dfae61](https://github.com/hashgraph-online/hol-guard/commit/2dfae61af1ac0f068afa08a150dd5b9f00c4e624))
* **guard:** run workspace-contained commands under bubblewrap on Linux ([#4304](https://github.com/hashgraph-online/hol-guard/issues/4304)) ([234d70c](https://github.com/hashgraph-online/hol-guard/commit/234d70c6a216c92b3a73d30da72184443849bb2a))
* **guard:** ship the source compiler inside the native runtime ([#4306](https://github.com/hashgraph-online/hol-guard/issues/4306)) ([04df190](https://github.com/hashgraph-online/hol-guard/commit/04df190a17e138213498693bfabf413d57d6aa2f))
* **guard:** sign native review approval links in the resident ([#4453](https://github.com/hashgraph-online/hol-guard/issues/4453)) ([566f9d4](https://github.com/hashgraph-online/hol-guard/commit/566f9d4c59f8659537082509ce40921a9e9a279f))
* **guard:** spend an approve-once for a reviewed PreToolUse in the resident ([#4437](https://github.com/hashgraph-online/hol-guard/issues/4437)) ([10fb56d](https://github.com/hashgraph-online/hol-guard/commit/10fb56d9e4b2ec9915918ba507e2302492255180))
* **guard:** verify and sign policy rows in the native resident ([#4522](https://github.com/hashgraph-online/hol-guard/issues/4522)) ([1841910](https://github.com/hashgraph-online/hol-guard/commit/18419109134d7c0e18bb5556ecee631ab5b51452))
* **guard:** write Guard events from the resident store ([#4457](https://github.com/hashgraph-online/hol-guard/issues/4457)) ([cb62343](https://github.com/hashgraph-online/hol-guard/commit/cb62343688bd7c6d42c79a52539c3dafbcd6e931))
* **guard:** write reviewed approval requests from the resident store ([#4447](https://github.com/hashgraph-online/hol-guard/issues/4447)) ([c130158](https://github.com/hashgraph-online/hol-guard/commit/c130158cc79d0a75818f6b5668eb98b2debd3d67))
* **mcp:** relay MCP stdio traffic natively behind a fail-closed decision seam ([#4528](https://github.com/hashgraph-online/hol-guard/issues/4528)) ([6f219c9](https://github.com/hashgraph-online/hol-guard/commit/6f219c9370ff4ed37cb111e248a66ebf7b573256))
* **mcp:** require review for FTP directory deletion ([#4514](https://github.com/hashgraph-online/hol-guard/issues/4514)) ([277501f](https://github.com/hashgraph-online/hol-guard/commit/277501fdc39da766d54dcfdcfb2fd8a397829fec))
* move portable policy compilation and YAML admission to Rust ([#4239](https://github.com/hashgraph-online/hol-guard/issues/4239)) ([906306d](https://github.com/hashgraph-online/hol-guard/commit/906306dfe62d9c1c35006793915b865d1a548d11))
* **runtime:** check Guard's private files on Windows before the bridges trust them ([#4501](https://github.com/hashgraph-online/hol-guard/issues/4501)) ([f9996d0](https://github.com/hashgraph-online/hol-guard/commit/f9996d01f3d7639a9c0e12c4264e7216271d9e35))
* **runtime:** compile native hook bridges on Windows ([#4500](https://github.com/hashgraph-online/hol-guard/issues/4500)) ([edf5ac6](https://github.com/hashgraph-online/hol-guard/commit/edf5ac664e9071e4b05038d1f50577028b4046dc))
* **runtime:** launch the native hook bridges on Windows ([#4510](https://github.com/hashgraph-online/hol-guard/issues/4510)) ([c34fdec](https://github.com/hashgraph-online/hol-guard/commit/c34fdece1c59185050101147a71f4003bf0b3949))
* **runtime:** prepare contained execution plans in Rust ([#4280](https://github.com/hashgraph-online/hol-guard/issues/4280)) ([5c7a4ae](https://github.com/hashgraph-online/hol-guard/commit/5c7a4ae00438afc4b8c250ac277f9acdc3ad587a))
* **runtime:** prove bridge and resident identity on Windows ([#4502](https://github.com/hashgraph-online/hol-guard/issues/4502)) ([f435427](https://github.com/hashgraph-online/hol-guard/commit/f435427943b8936feb4d0a3e80a4338f0eb52e79))


### Bug Fixes

* **approvals:** show inbox approvals of tool calls as the user's decision ([#4341](https://github.com/hashgraph-online/hol-guard/issues/4341)) ([2f067ed](https://github.com/hashgraph-online/hol-guard/commit/2f067ede9b9125836f7cf29ecb2fa2a7b7595b73))
* **ci:** give the native command evaluator job room for the larger replay gate ([#4323](https://github.com/hashgraph-online/hol-guard/issues/4323)) ([9d7c83c](https://github.com/hashgraph-online/hol-guard/commit/9d7c83c933910828eaf303fd9b6e18268f94facf))
* **codex:** leave Codex approval requests to Codex's own prompt ([#4491](https://github.com/hashgraph-online/hol-guard/issues/4491)) ([b67a6a0](https://github.com/hashgraph-online/hol-guard/commit/b67a6a03e03c55b62e2a21d107f48afc7f330484))
* **daemon:** wait for republish after stale control authority or expired snapshot ([#4404](https://github.com/hashgraph-online/hol-guard/issues/4404)) ([9127107](https://github.com/hashgraph-online/hol-guard/commit/912710737d1907f09ea9a8032f7d5f325fc72ce1))
* **dashboard:** calm the Extensions page hierarchy ([#4423](https://github.com/hashgraph-online/hol-guard/issues/4423)) ([3f43d69](https://github.com/hashgraph-online/hol-guard/commit/3f43d697c52b7b01ac20507fa04da500767e5f5d))
* **dashboard:** simplify local approval setup and restore its return path ([#4529](https://github.com/hashgraph-online/hol-guard/issues/4529)) ([4658932](https://github.com/hashgraph-online/hol-guard/commit/4658932bddaa63138ed9a2822263eb04c7f649cc))
* **gauntlet:** accept contained runs that use the agent's own home directory ([#4390](https://github.com/hashgraph-online/hol-guard/issues/4390)) ([b831154](https://github.com/hashgraph-online/hol-guard/commit/b831154d3afdd6eac7af29b2a0a92495b7b51142))
* **gauntlet:** await startup publication before binding Watch evidence ([2804aa0](https://github.com/hashgraph-online/hol-guard/commit/2804aa00715e367e04a8c661fd80cfd2443f8c8b))
* **gauntlet:** build Docker full tasks in the container user's own home ([#4376](https://github.com/hashgraph-online/hol-guard/issues/4376)) ([6cb884b](https://github.com/hashgraph-online/hol-guard/commit/6cb884b7ca2adfe721eb55dfe278cf943d9fee35))
* **gauntlet:** count a full task's failed contained command as Guard's only when the sandbox refused it ([#4361](https://github.com/hashgraph-online/hol-guard/issues/4361)) ([cf047e5](https://github.com/hashgraph-online/hol-guard/commit/cf047e5df9ebd215bdf3708b5700dfedec4747cb))
* **gauntlet:** judge the Python full task's tests by what they import ([#4372](https://github.com/hashgraph-online/hol-guard/issues/4372)) ([c305f90](https://github.com/hashgraph-online/hol-guard/commit/c305f906929bcddf091b8bfc97f0836a0c82e501))
* **gauntlet:** keep a case's Guard observations when one row cannot be verified ([#4330](https://github.com/hashgraph-online/hol-guard/issues/4330)) ([2cf1197](https://github.com/hashgraph-online/hol-guard/commit/2cf11978f1809dbab65192c5afdeecb9b300812a))
* **gauntlet:** list required commands as plain lines in the agent prompt ([#4287](https://github.com/hashgraph-online/hol-guard/issues/4287)) ([225df27](https://github.com/hashgraph-online/hol-guard/commit/225df27eac6b8291eebd00f6722540cd33dbd872))
* **gauntlet:** stop exporting a Unix loader path in the Windows realistic environment ([#4266](https://github.com/hashgraph-online/hol-guard/issues/4266)) ([0efdcd5](https://github.com/hashgraph-online/hol-guard/commit/0efdcd50b597a1fb3446eb8c1912ab48b61ab0b6))
* **guard-command:** allow missing .git probes with Windows home paths ([#4472](https://github.com/hashgraph-online/hol-guard/issues/4472)) ([5d05196](https://github.com/hashgraph-online/hol-guard/commit/5d0519671313aa9c9fd8f47329441d48c8302de0))
* **guard:** accept a trailing command terminator and version checks after cd ([#4513](https://github.com/hashgraph-online/hol-guard/issues/4513)) ([a90db64](https://github.com/hashgraph-online/hol-guard/commit/a90db64c6ba329ad838a18e4db4ad63bcafcee71))
* **guard:** accept bounded task result contents without review ([02b8500](https://github.com/hashgraph-online/hol-guard/commit/02b8500c50980fca60aad831e7d55f12691da447))
* **guard:** accept every Oh My Pi line selector on reads Guard already allows ([#4379](https://github.com/hashgraph-online/hol-guard/issues/4379)) ([b9d1788](https://github.com/hashgraph-online/hol-guard/commit/b9d1788fd16fe09170c8b4c4327b8c4798d10d25))
* **guard:** accept the guard prefix in contained runs on the Desktop launcher ([#4289](https://github.com/hashgraph-online/hol-guard/issues/4289)) ([759cac9](https://github.com/hashgraph-online/hol-guard/commit/759cac99a2b8676cf0e892b0a44962a26ab540fd))
* **guard:** accept Windows home spellings in Oh My Pi agent-root listings ([#4296](https://github.com/hashgraph-online/hol-guard/issues/4296)) ([591b219](https://github.com/hashgraph-online/hol-guard/commit/591b2190ec42caba9e15dab858359dc1bf0c2cf0))
* **guard:** admit bare builtins and object filters in jq file reads ([#4518](https://github.com/hashgraph-online/hol-guard/issues/4518)) ([d6f0d81](https://github.com/hashgraph-online/hol-guard/commit/d6f0d814f71aafb816b512d4019e4b7f7147e39a))
* **guard:** admit empty work-tree markers and read prefixes before cd ([#4370](https://github.com/hashgraph-online/hol-guard/issues/4370)) ([4b8d8a0](https://github.com/hashgraph-online/hol-guard/commit/4b8d8a0e5410e89a150c20c55afa3b2afc19f63e))
* **guard:** admit file-less subdirectories on the current policy snapshot ([#4477](https://github.com/hashgraph-online/hol-guard/issues/4477)) ([871e3ba](https://github.com/hashgraph-online/hol-guard/commit/871e3ba4db63ee19a8394e093f5b4cbaf5abd601))
* **guard:** admit read-only for loops over literal words by unrolling them ([#4391](https://github.com/hashgraph-online/hol-guard/issues/4391)) ([34cd91f](https://github.com/hashgraph-online/hol-guard/commit/34cd91f07dd84e2d8ee0a2dade71366d32b04a09))
* **guard:** allow a workspace file write chained with a local git commit ([#4537](https://github.com/hashgraph-online/hol-guard/issues/4537)) ([6e67823](https://github.com/hashgraph-online/hol-guard/commit/6e67823391546a0bc5d0d4a760a0c5c443e25d04))
* **guard:** allow bounded in-place sed substitutions on workspace files ([#4482](https://github.com/hashgraph-online/hol-guard/issues/4482)) ([6eaed8c](https://github.com/hashgraph-online/hol-guard/commit/6eaed8c67c21d9c8fdb89fcf6a364568e981dd68))
* **guard:** allow chains that copy readable files into private temp files ([#4492](https://github.com/hashgraph-online/hol-guard/issues/4492)) ([257bafe](https://github.com/hashgraph-online/hol-guard/commit/257bafe23def6c6b6bbb462845c9a5ad2ec45b44))
* **guard:** allow chains that stage and reuse private temp files ([#4473](https://github.com/hashgraph-online/hol-guard/issues/4473)) ([dce7cbc](https://github.com/hashgraph-online/hol-guard/commit/dce7cbc5c5b12858d7d4f6327fa9ab796b034620))
* **guard:** allow docker listings, loopback nc probes and guard-prefixed help ([#4479](https://github.com/hashgraph-online/hol-guard/issues/4479)) ([f8db749](https://github.com/hashgraph-online/hol-guard/commit/f8db749122b88471ba85a742da445428765e43b3))
* **guard:** allow frozen, script-free installs from registry-only lockfiles ([#4366](https://github.com/hashgraph-online/hol-guard/issues/4366)) ([86821cc](https://github.com/hashgraph-online/hol-guard/commit/86821ccf6a12bf453317877526987c9b73e58c8f))
* **guard:** allow gh api reads that merge stderr into stdout ([#4523](https://github.com/hashgraph-online/hol-guard/issues/4523)) ([e8caefd](https://github.com/hashgraph-online/hol-guard/commit/e8caefd9e32e8893e9442ebb15cc207c997a05e6))
* **guard:** allow git worktree add for an existing branch ([#4524](https://github.com/hashgraph-online/hol-guard/issues/4524)) ([bd851fc](https://github.com/hashgraph-online/hol-guard/commit/bd851fc7d27aa1ca49fd3444988f6724d2a3ad63))
* **guard:** allow host file-tool writes into bracket and $ route files ([#4471](https://github.com/hashgraph-online/hol-guard/issues/4471)) ([445b8a5](https://github.com/hashgraph-online/hol-guard/commit/445b8a5a07b6694ca74a9064e4f345f432663f2f))
* **guard:** allow jq key listings and literal filters in file reads ([#4516](https://github.com/hashgraph-online/hol-guard/issues/4516)) ([40eb5bd](https://github.com/hashgraph-online/hol-guard/commit/40eb5bd350dcaec4143ac098bae337fa31e946c8))
* **guard:** allow local Git writes in proven sibling repositories ([#4487](https://github.com/hashgraph-online/hol-guard/issues/4487)) ([cd57bcd](https://github.com/hashgraph-online/hol-guard/commit/cd57bcd68ba569c1051cc1c819744eb2c0b067cf))
* **guard:** allow name-only listings of home dot-directories outside credential stores ([#4526](https://github.com/hashgraph-online/hol-guard/issues/4526)) ([6a00275](https://github.com/hashgraph-online/hol-guard/commit/6a002756686e8671a9c6295fa7650309cfc6bcb0))
* **guard:** allow ordinary file work outside the workspace while credential contents and tool config stay reviewed ([#4422](https://github.com/hashgraph-online/hol-guard/issues/4422)) ([450122d](https://github.com/hashgraph-online/hol-guard/commit/450122db3b68f4044e81ab68ac36975cabc42205))
* **guard:** allow plain curl reads and read-only kubectl queries ([#4421](https://github.com/hashgraph-online/hol-guard/issues/4421)) ([a53239b](https://github.com/hashgraph-online/hol-guard/commit/a53239b68b49be7b3c4e078c5a9e446ce1844d33))
* **guard:** allow plain Git config writes, grep and start-point branches in proven repositories ([#4431](https://github.com/hashgraph-online/hol-guard/issues/4431)) ([655f775](https://github.com/hashgraph-online/hol-guard/commit/655f7757df5fea96c12b649ed7088ca908112498))
* **guard:** allow proven git publish chains ([#4441](https://github.com/hashgraph-online/hol-guard/issues/4441)) ([d293896](https://github.com/hashgraph-online/hol-guard/commit/d29389624b41fd8dbe2894b6c0b58fbf74ec7cef))
* **guard:** allow sibling repository reads with print filters, globs and several directories ([#4478](https://github.com/hashgraph-online/hol-guard/issues/4478)) ([3cdbecd](https://github.com/hashgraph-online/hol-guard/commit/3cdbecd4d18789415699e299f14e913cf914d034))
* **guard:** allow sibling worktree add and linked-worktree fetch with Apple Git ([#4448](https://github.com/hashgraph-online/hol-guard/issues/4448)) ([3ce6caf](https://github.com/hashgraph-online/hol-guard/commit/3ce6cafdb96c6f752e42aaa0c55f03c43718cf77))
* **guard:** contain linked worktree runs with the shared Git directory writable ([#4367](https://github.com/hashgraph-online/hol-guard/issues/4367)) ([aac8410](https://github.com/hashgraph-online/hol-guard/commit/aac8410a562820e742534bbe0165d3800a2006b8))
* **guard:** give content sensitivity checks time to start the native resident ([#4348](https://github.com/hashgraph-online/hol-guard/issues/4348)) ([9a68040](https://github.com/hashgraph-online/hol-guard/commit/9a680409a5b70f82c3d3305354a2c635839ef25c))
* **guard:** give du of a missing sibling path the ls absent-path proof ([#4511](https://github.com/hashgraph-online/hol-guard/issues/4511)) ([58d89af](https://github.com/hashgraph-online/hol-guard/commit/58d89afdc055213749a48dd810379e7e3a8a54c9))
* **guard:** give warm content-sensitivity queries room on a loaded machine ([#4531](https://github.com/hashgraph-online/hol-guard/issues/4531)) ([cfcd6a8](https://github.com/hashgraph-online/hol-guard/commit/cfcd6a8dc9fd6bea3fc6a5617b737e8e9fd4bc67))
* **guard:** judge chained $VAR uses by their literal in-chain assignment ([#4445](https://github.com/hashgraph-online/hol-guard/issues/4445)) ([39c9b86](https://github.com/hashgraph-online/hol-guard/commit/39c9b861cfe38ee32a3618ef4d2e8cd3728cc985))
* **guard:** keep Cargo builds out of the workspace sandbox and document why ([#4483](https://github.com/hashgraph-online/hol-guard/issues/4483)) ([e47c04b](https://github.com/hashgraph-online/hol-guard/commit/e47c04bb84323004ad393fcb737d920a06c45ec8))
* **guard:** keep Git commands that write repository metadata out of the workspace sandbox ([#4345](https://github.com/hashgraph-online/hol-guard/issues/4345)) ([9e5973f](https://github.com/hashgraph-online/hol-guard/commit/9e5973fc18adf6bbc60208030af09b18caa1dc05))
* **guard:** keep git read proofs after a glob-pathspec log in the same command ([#4417](https://github.com/hashgraph-online/hol-guard/issues/4417)) ([14f3a88](https://github.com/hashgraph-online/hol-guard/commit/14f3a88aa42bc971777e36209b79b4bb07300d19))
* **guard:** keep lifecycle hooks from opening the native circuit breaker ([#4380](https://github.com/hashgraph-online/hol-guard/issues/4380)) ([4c207c3](https://github.com/hashgraph-online/hol-guard/commit/4c207c326704be1e9be23a9f2ca5de666f1bca4b))
* **guard:** keep macOS sandbox patterns within Seatbelt's string limit ([#4463](https://github.com/hashgraph-online/hol-guard/issues/4463)) ([51e0819](https://github.com/hashgraph-online/hol-guard/commit/51e08192da0a9ef255a5769b507ac406805768d2))
* **guard:** keep network clients out of containment and fix macOS containment regressions ([#4392](https://github.com/hashgraph-online/hol-guard/issues/4392)) ([08f2491](https://github.com/hashgraph-online/hol-guard/commit/08f2491b9ae31b4b36d5303b503371a9fc584ad2))
* **guard:** keep npm read and install proofs when the session trusts an extra CA ([#4359](https://github.com/hashgraph-online/hol-guard/issues/4359)) ([a67ae72](https://github.com/hashgraph-online/hol-guard/commit/a67ae72e9ac0308b07c7d215f474cb5459b2b824))
* **guard:** keep quoted regex alternation from posing as a synthesized program ([#4388](https://github.com/hashgraph-online/hol-guard/issues/4388)) ([f01d484](https://github.com/hashgraph-online/hol-guard/commit/f01d484dd69705225ad6b6d13c3dde2facbe66d0))
* **guard:** keep sync working on stores with more than 4,096 events ([#4485](https://github.com/hashgraph-online/hol-guard/issues/4485)) ([0de5281](https://github.com/hashgraph-online/hol-guard/commit/0de5281bee5f9a5656e40affedcc9bc1091f41a3))
* **guard:** keep the direct lane bound when the daemon's listen origin lands ([#4462](https://github.com/hashgraph-online/hol-guard/issues/4462)) ([404b399](https://github.com/hashgraph-online/hol-guard/commit/404b3995846ea0913049185742266af88e945028))
* **guard:** keep the evidence drain from tripping the restart circuit ([#4382](https://github.com/hashgraph-online/hol-guard/issues/4382)) ([78bf338](https://github.com/hashgraph-online/hol-guard/commit/78bf338eb4ded132e57bae6b0c65f38b29d6ffbd))
* **guard:** keep the git push proof when the session trusts a company CA bundle ([#4364](https://github.com/hashgraph-online/hol-guard/issues/4364)) ([d2f4afd](https://github.com/hashgraph-online/hol-guard/commit/d2f4afdbdfed2ec0de7895e1b1318973ab064495))
* **guard:** let --ignore-scripts installs of a git-free tree continue on npm 11.9 and later ([#4377](https://github.com/hashgraph-online/hol-guard/issues/4377)) ([cb68521](https://github.com/hashgraph-online/hol-guard/commit/cb6852166739fbaf7d3d0d889f9406f3b9098269))
* **guard:** let agent-home listings, sibling-repo grep and mktemp scratch dirs proceed ([#4255](https://github.com/hashgraph-online/hol-guard/issues/4255)) ([18786e5](https://github.com/hashgraph-online/hol-guard/commit/18786e5bfb0dba524937fb75acf43e0f3b656ead))
* **guard:** let agents create a private GitHub repository without review ([#4360](https://github.com/hashgraph-online/hol-guard/issues/4360)) ([0c560b0](https://github.com/hashgraph-online/hol-guard/commit/0c560b0e6eb7c781b498b23c8e319876a9948296))
* **guard:** let agents read a sibling checkout through a relative parent path ([#4430](https://github.com/hashgraph-online/hol-guard/issues/4430)) ([44dfe6d](https://github.com/hashgraph-online/hol-guard/commit/44dfe6d803e736e1f9c6625e9a5565a5407ae96c))
* **guard:** let agents read and write .gitignore and rename branches without review ([#4427](https://github.com/hashgraph-online/hol-guard/issues/4427)) ([b886130](https://github.com/hashgraph-online/hol-guard/commit/b886130d140d38e5ee49c3f2c50255957b0f71a7))
* **guard:** let agents read files found with find -exec or xargs -0 without review ([#4396](https://github.com/hashgraph-online/hol-guard/issues/4396)) ([0891a40](https://github.com/hashgraph-online/hol-guard/commit/0891a40cb5af02b2ba0a046dafdc2c97ea9efdb3))
* **guard:** let agents read their own plan notes and evidence ([#4295](https://github.com/hashgraph-online/hol-guard/issues/4295)) ([98065f4](https://github.com/hashgraph-online/hol-guard/commit/98065f4d39aeb37985b886d28b923925c42c435c))
* **guard:** let command lookups, Guard help, merge-base and chained Git reads proceed ([#4281](https://github.com/hashgraph-online/hol-guard/issues/4281)) ([3eb5e17](https://github.com/hashgraph-online/hol-guard/commit/3eb5e17cf1dbd6fc5656d3d682e1d79fb221057f))
* **guard:** let commits in a contained linked worktree clear AUTO_MERGE ([#4371](https://github.com/hashgraph-online/hol-guard/issues/4371)) ([4aac5d6](https://github.com/hashgraph-online/hol-guard/commit/4aac5d6d827e773b4440081434e25e5aeec4399e))
* **guard:** let constant bun -e prints run when no Bun preload can load ([#4286](https://github.com/hashgraph-online/hol-guard/issues/4286)) ([7d5b3a4](https://github.com/hashgraph-online/hol-guard/commit/7d5b3a41fac33927d663ea06f2ef6d33dcdb3c38))
* **guard:** let contained pytest on macOS load packages installed with pip --user ([#4336](https://github.com/hashgraph-online/hol-guard/issues/4336)) ([f8c953d](https://github.com/hashgraph-online/hol-guard/commit/f8c953d52367d1f12b03fd810c8f3f257ad0a4a5))
* **guard:** let contained test runs pipe output through grep ([#4534](https://github.com/hashgraph-online/hol-guard/issues/4534)) ([d842bb2](https://github.com/hashgraph-online/hol-guard/commit/d842bb2928ecf545100d67ea70c35c97f8e44cf0))
* **guard:** let frozen lockfile installs without scripts run without review ([#4444](https://github.com/hashgraph-online/hol-guard/issues/4444)) ([58b55d7](https://github.com/hashgraph-online/hol-guard/commit/58b55d7f1144b50dcda8ddd25471b575104472f1))
* **guard:** let frozen script-free installs, local package runners and plain printenv proceed ([#4436](https://github.com/hashgraph-online/hol-guard/issues/4436)) ([56c5a89](https://github.com/hashgraph-online/hol-guard/commit/56c5a89e9e7b963956427becdd94bb546f0c730d))
* **guard:** let git merge-base object names feed a Git read through xargs ([#4434](https://github.com/hashgraph-online/hol-guard/issues/4434)) ([d51a4a0](https://github.com/hashgraph-online/hol-guard/commit/d51a4a02f766788b061d3fa3190a94f3a4188ba6))
* **guard:** let names-only listings of skill directories and missing paths proceed ([#4298](https://github.com/hashgraph-online/hol-guard/issues/4298)) ([c789512](https://github.com/hashgraph-online/hol-guard/commit/c78951271d159e489d8318b73804e6b63b877a9b))
* **guard:** let ordinary variables on build commands run ([#4328](https://github.com/hashgraph-online/hol-guard/issues/4328)) ([8d6b3ba](https://github.com/hashgraph-online/hol-guard/commit/8d6b3baee8a07a5cebb1933922c445046c149ac9))
* **guard:** let pushes of the checked-out branch to a GitHub origin proceed natively ([#4285](https://github.com/hashgraph-online/hol-guard/issues/4285)) ([5f62907](https://github.com/hashgraph-online/hol-guard/commit/5f62907303a78f8f147c4f9be24791c11a865e3f))
* **guard:** let read-only brew and pg_ctl status queries run without review ([#4506](https://github.com/hashgraph-online/hol-guard/issues/4506)) ([32621ab](https://github.com/hashgraph-online/hol-guard/commit/32621abb3f21f330ee0ff68ecb32380df5ac4a7a))
* **guard:** let read-only git grep searches proceed without review ([#4439](https://github.com/hashgraph-online/hol-guard/issues/4439)) ([d345e72](https://github.com/hashgraph-online/hol-guard/commit/d345e72980390c8dae96fbc2cd5a05678f5968d9))
* **guard:** let recursive search read feature directories named after secrets ([#4378](https://github.com/hashgraph-online/hol-guard/issues/4378)) ([98b5bca](https://github.com/hashgraph-online/hol-guard/commit/98b5bca1b6047e964077d87efdd39fcdc9383133))
* **guard:** let routine agent sessions run without false stops ([#4311](https://github.com/hashgraph-online/hol-guard/issues/4311)) ([d0b1784](https://github.com/hashgraph-online/hol-guard/commit/d0b17842850881a48c34059bcab7fdd3167b9c32))
* **guard:** let script-free npm installs continue from ordinary developer shells ([#4374](https://github.com/hashgraph-online/hol-guard/issues/4374)) ([3856b99](https://github.com/hashgraph-online/hol-guard/commit/3856b994b9efc4c39c66a92ad27a9fd2b018003c))
* **guard:** let script-free npm installs continue on npm releases before 11.9 ([#4365](https://github.com/hashgraph-online/hol-guard/issues/4365)) ([3441199](https://github.com/hashgraph-online/hol-guard/commit/3441199b27934d7e3274a5d205c51e7d191b2df0))
* **guard:** let sibling worktree probes, pwd paths and cd-then-run steps proceed ([#4468](https://github.com/hashgraph-online/hol-guard/issues/4468)) ([e22f1b1](https://github.com/hashgraph-online/hol-guard/commit/e22f1b1742a48846cbd25f35584b6add461924d5))
* **guard:** let the macOS workspace sandbox run Xcode, Homebrew and python.org tools, pipelines and file deletes ([#4325](https://github.com/hashgraph-online/hol-guard/issues/4325)) ([82d643d](https://github.com/hashgraph-online/hol-guard/commit/82d643de37be6dcb762ad90941ffb1ad0cb39921))
* **guard:** mark tool input cut to an excerpt in the action envelope ([#4342](https://github.com/hashgraph-online/hol-guard/issues/4342)) ([9e347df](https://github.com/hashgraph-online/hol-guard/commit/9e347df9ee25a78244bf88d387af217ee75ade43))
* **guard:** model command, time and env prefixes on ordinary programs ([#4293](https://github.com/hashgraph-online/hol-guard/issues/4293)) ([9efd096](https://github.com/hashgraph-online/hol-guard/commit/9efd096240349e6358074a4bb960b61e8fd18fae))
* **guard:** name the home-directory bound when git worktree add leaves home ([#4375](https://github.com/hashgraph-online/hol-guard/issues/4375)) ([9da5916](https://github.com/hashgraph-online/hol-guard/commit/9da591652b5cb9e2eeb05d0e0954fe44a48c1b14))
* **guard:** point agents at a private repository when gh repo create needs review ([#4352](https://github.com/hashgraph-online/hol-guard/issues/4352)) ([0446e23](https://github.com/hashgraph-online/hol-guard/commit/0446e23199810ade74cb80b2e8696258b4cd419c))
* **guard:** point chained public repo creates to the private alternative ([#4394](https://github.com/hashgraph-online/hol-guard/issues/4394)) ([759302e](https://github.com/hashgraph-online/hol-guard/commit/759302e90a88201b262bcd6fe5202b001da8f36c))
* **guard:** point package reviews at the frozen lockfile install ([#4525](https://github.com/hashgraph-online/hol-guard/issues/4525)) ([8cbd39c](https://github.com/hashgraph-online/hol-guard/commit/8cbd39cb577e42797ed0dab70911ccce024340bc))
* **guard:** prove cd ~/ prefixes and relative node_modules entrypoints ([#4278](https://github.com/hashgraph-online/hol-guard/issues/4278)) ([11f9e30](https://github.com/hashgraph-online/hol-guard/commit/11f9e30d082df6590483b8a50274e7d19d10f9f9))
* **guard:** prove git ls-tree and plain cat-file object reads ([#4496](https://github.com/hashgraph-online/hol-guard/issues/4496)) ([8baffb4](https://github.com/hashgraph-online/hol-guard/commit/8baffb44e058fb36ad165649845389755cd75372))
* **guard:** prove git worktree add for sibling paths and ordinary Git sessions ([#4358](https://github.com/hashgraph-online/hol-guard/issues/4358)) ([e56ca0e](https://github.com/hashgraph-online/hol-guard/commit/e56ca0e9837d4fcbd5ba0ce59ef842da68341b5d))
* **guard:** prove grep and ls globs across sibling repositories ([#4512](https://github.com/hashgraph-online/hol-guard/issues/4512)) ([6c2e75d](https://github.com/hashgraph-online/hol-guard/commit/6c2e75dd286553e5259d103fe2be0f4ef06de66f))
* **guard:** prove names-only git log reads with glob pathspecs ([#4456](https://github.com/hashgraph-online/hol-guard/issues/4456)) ([773ab07](https://github.com/hashgraph-online/hol-guard/commit/773ab07a1464e103cefc0309c38f26d63a063632))
* **guard:** prove process probes natively so outside reads can chain with them ([#4509](https://github.com/hashgraph-online/hol-guard/issues/4509)) ([b75fef7](https://github.com/hashgraph-online/hol-guard/commit/b75fef7c7342c246dceb775da819a2c7f6d161a7))
* **guard:** prove reads in a new worktree, detached adds, Apple Git helpers and Git read prefixes ([#4467](https://github.com/hashgraph-online/hol-guard/issues/4467)) ([054e792](https://github.com/hashgraph-online/hol-guard/commit/054e79268326bc64e0a044b2aeb85cc102713ced))
* **guard:** prove relative cd and profile temp writes on Windows ([#4332](https://github.com/hashgraph-online/hol-guard/issues/4332)) ([b78ba5d](https://github.com/hashgraph-online/hol-guard/commit/b78ba5dbd48ef0a8cd66e26c48610ce3fa9a7d4f))
* **guard:** prove sibling glob reads and admit read-only command inspection ([#4464](https://github.com/hashgraph-online/hol-guard/issues/4464)) ([9d0113e](https://github.com/hashgraph-online/hol-guard/commit/9d0113ebbac4ce749e2467ead5494f08da4b7a61))
* **guard:** prove workspace symlinks and plain file removals natively ([#4297](https://github.com/hashgraph-online/hol-guard/issues/4297)) ([0d5d2e7](https://github.com/hashgraph-online/hol-guard/commit/0d5d2e760dc59756f84f86250e412aca8aca4f43))
* **guard:** prove worktree add with -C, global hook managers and LFS filters ([#4387](https://github.com/hashgraph-online/hol-guard/issues/4387)) ([1a6e9b5](https://github.com/hashgraph-online/hol-guard/commit/1a6e9b50d228b3a7bc8b34b07732e9482886e42e))
* **guard:** release approved Oh My Pi learn results ([b3f9716](https://github.com/hashgraph-online/hol-guard/commit/b3f971651153120f1362b5bec08aa4082221916f))
* **guard:** release Oh My Pi eval output for proved shell calls ([#4541](https://github.com/hashgraph-online/hol-guard/issues/4541)) ([cf6e39e](https://github.com/hashgraph-online/hol-guard/commit/cf6e39e2c66f421399586ef5584f8bdd878474d8))
* **guard:** release proven Oh My Pi directory listings ([6b3abc6](https://github.com/hashgraph-online/hol-guard/commit/6b3abc6331048a29a3d579583b413aa88f314f1a))
* **guard:** report a Cloudflare block of Guard Cloud as a network failure, not an expired sign-in ([#4521](https://github.com/hashgraph-online/hol-guard/issues/4521)) ([599c7f5](https://github.com/hashgraph-online/hol-guard/commit/599c7f5f210fde89093b5f5ad69020d23be3f6d0))
* **guard:** review writes to harness configuration inside the workspace ([#4446](https://github.com/hashgraph-online/hol-guard/issues/4446)) ([042a7b3](https://github.com/hashgraph-online/hol-guard/commit/042a7b36393412cae3c888a5fd81af2c3a2cbaa0))
* **guard:** run `python -m unittest` and status-echo test commands in the read-only sandbox ([#4277](https://github.com/hashgraph-online/hol-guard/issues/4277)) ([68558a5](https://github.com/hashgraph-online/hol-guard/commit/68558a59d9e8b6d4a8a86ef9de9263de41248068))
* **guard:** run a command list in a sibling worktree in that worktree's sandbox ([#4432](https://github.com/hashgraph-online/hol-guard/issues/4432)) ([9893126](https://github.com/hashgraph-online/hol-guard/commit/98931263866a93a30859a79f6b8f28b0e3ea949d))
* **guard:** run checks contained, then the proven Git steps, for check-then-publish chains ([#4470](https://github.com/hashgraph-online/hol-guard/issues/4470)) ([c521140](https://github.com/hashgraph-online/hol-guard/commit/c5211408537a0d0f7c7db2cfe0265785e30105b9))
* **guard:** run contained pytest in a project that only has source and test modules ([#4334](https://github.com/hashgraph-online/hol-guard/issues/4334)) ([08cfc87](https://github.com/hashgraph-online/hol-guard/commit/08cfc87121d4395f3a9b9efa86d72298caeef855))
* **guard:** run contained Vite builds from a package directory with their declared output, esbuild, and config bundle ([#4383](https://github.com/hashgraph-online/hol-guard/issues/4383)) ([0c317c9](https://github.com/hashgraph-online/hol-guard/commit/0c317c93f9afac0227df758fc3f2f32cab9fc15d))
* **guard:** run read-only bun eval scripts in the read-only runner ([#4460](https://github.com/hashgraph-online/hol-guard/issues/4460)) ([f0e1111](https://github.com/hashgraph-online/hol-guard/commit/f0e11119e2745d5d4f912f63dd6ee8b8b415b94b))
* **guard:** scope Protect-screen per-app protection to apps Guard manages ([#4250](https://github.com/hashgraph-online/hol-guard/issues/4250)) ([36b51d1](https://github.com/hashgraph-online/hol-guard/commit/36b51d1428a816cb2c2cc2ac6ea4a3fdea1a6abe))
* **guard:** stop asking before git init, git reads after a listing, and git status outside a repository ([#4329](https://github.com/hashgraph-online/hol-guard/issues/4329)) ([fd0ad09](https://github.com/hashgraph-online/hol-guard/commit/fd0ad0915ac0568a1ad2ee349a27e9227acd21d1))
* **guard:** stop blocking login status output that shows only a masked token ([#4343](https://github.com/hashgraph-online/hol-guard/issues/4343)) ([3a08674](https://github.com/hashgraph-online/hol-guard/commit/3a0867431bea897aeb48eaf32b3ac5538b8aaf1c))
* **guard:** stop false blocks on routine git, listing and web-fetch work in agent sessions ([#4357](https://github.com/hashgraph-online/hol-guard/issues/4357)) ([c1ca078](https://github.com/hashgraph-online/hol-guard/commit/c1ca0787ee1d4acdf4cc823a76f9666f2cb0d8a4))
* **guard:** stop flagging everyday search, process, push and env-prefixed build commands ([#4350](https://github.com/hashgraph-online/hol-guard/issues/4350)) ([890cee2](https://github.com/hashgraph-online/hol-guard/commit/890cee2d75efe98a5fae4194dee899d4a98dd991))
* **guard:** stop hard-blocking commands that set an environment variable ([#4294](https://github.com/hashgraph-online/hol-guard/issues/4294)) ([df45cbe](https://github.com/hashgraph-online/hol-guard/commit/df45cbe92295a632f3ec3287ad6a3dd8d14ec9be))
* **guard:** stop offering --ignore-scripts as the way past a package review ([#4381](https://github.com/hashgraph-online/hol-guard/issues/4381)) ([12f3dcc](https://github.com/hashgraph-online/hol-guard/commit/12f3dccb6c38154d2bbe2a735a5a28c517a5e0e7))
* **guard:** stop reviewing grep includes such as *.test.ts ([#4443](https://github.com/hashgraph-online/hol-guard/issues/4443)) ([1e8220d](https://github.com/hashgraph-online/hol-guard/commit/1e8220d9fc221ef0a58fc0dc37ebb330b9389068))
* **guard:** stop telling agents to wait for an approval that cannot unblock them ([#4461](https://github.com/hashgraph-online/hol-guard/issues/4461)) ([b455346](https://github.com/hashgraph-online/hol-guard/commit/b4553465e7434971b28c63442ddd9567ad8e91aa))
* **guard:** stop telling headless Oh My Pi agents to approve a stop that has no request ([#4339](https://github.com/hashgraph-online/hol-guard/issues/4339)) ([ec0c6fb](https://github.com/hashgraph-online/hol-guard/commit/ec0c6fbafbc4a357a58b6d92ff6b1d7709f5f51b))
* **guard:** tell agents to push separately when a private gh repo create adds the remote ([#4465](https://github.com/hashgraph-online/hol-guard/issues/4465)) ([161f594](https://github.com/hashgraph-online/hol-guard/commit/161f594c5a75632edff2574cdbc982690f5147b3))
* **guard:** tell agents to retry when the native policy is not ready ([#4393](https://github.com/hashgraph-online/hol-guard/issues/4393)) ([3c63f9d](https://github.com/hashgraph-online/hol-guard/commit/3c63f9df23ccd433e6e6fe5dc1097bef95693ba1))
* **guard:** treat git search patterns as search text, not paths ([#4520](https://github.com/hashgraph-online/hol-guard/issues/4520)) ([52a9692](https://github.com/hashgraph-online/hol-guard/commit/52a9692a4c854fff303df33914bd49b7ed1ba2b7))
* **guard:** treat package-manager directory flags like cd into that directory ([#4489](https://github.com/hashgraph-online/hol-guard/issues/4489)) ([1aa19ba](https://github.com/hashgraph-online/hol-guard/commit/1aa19baaba8359ee2ec8ef5cf9627a7c593b2320))
* **guard:** treat Unix loader search paths as inert for Windows Git proofs ([#4275](https://github.com/hashgraph-online/hol-guard/issues/4275)) ([faedd08](https://github.com/hashgraph-online/hol-guard/commit/faedd08d1c4ce0c4a791cb73ec3f2ed8625f96cb))
* **release:** optimize Windows alpha workspace code ([a82b426](https://github.com/hashgraph-online/hol-guard/commit/a82b4260dcb8c3f5c20535b0ed531a5968fc2d40))
* **runtime:** stop orphaned Windows residents once their owner and clients exit ([#4455](https://github.com/hashgraph-online/hol-guard/issues/4455)) ([5d220a2](https://github.com/hashgraph-online/hol-guard/commit/5d220a257ec7cc79c24dc87322ae62beeec3be65))
* **updates:** publish and select Linux Desktop alpha Core releases ([#4424](https://github.com/hashgraph-online/hol-guard/issues/4424)) ([6d097dd](https://github.com/hashgraph-online/hol-guard/commit/6d097dd4156fb8ce6f3fcf04075b0a99802dc6cd))


### Performance Improvements

* **ci:** parallelize Rust compilation and prioritize slow tests ([#4400](https://github.com/hashgraph-online/hol-guard/issues/4400)) ([cce5d3b](https://github.com/hashgraph-online/hol-guard/commit/cce5d3b7c2e5e79f70bdac2385d74b480bad11b9))
* **ci:** skip fallback downloads after partial Rust cache restores ([#4410](https://github.com/hashgraph-online/hol-guard/issues/4410)) ([f877332](https://github.com/hashgraph-online/hol-guard/commit/f8773323fd03086737fcb542fc9cfaf014fc1b73))
* **gauntlet:** scale qualification workers and preserve linked-write protection ([#4426](https://github.com/hashgraph-online/hol-guard/issues/4426)) ([c1c5b76](https://github.com/hashgraph-online/hol-guard/commit/c1c5b76f8ead4879bf6bb8550b767a57a762c3ec))
* **guard:** build the generic hook's approval context token in the saved-decision lookup ([#4407](https://github.com/hashgraph-online/hol-guard/issues/4407)) ([82b8421](https://github.com/hashgraph-online/hol-guard/commit/82b842170954ebfc86796b6976f3060787f45aeb))
* **guard:** compose generic-hook approval reuse in the grouped saved-decision call ([#4402](https://github.com/hashgraph-online/hol-guard/issues/4402)) ([6097977](https://github.com/hashgraph-online/hol-guard/commit/6097977d6811cebdec9b3e09b23b0079af7af72e))
* **guard:** fetch each registry document once per package review ([#4438](https://github.com/hashgraph-online/hol-guard/issues/4438)) ([bf01ab1](https://github.com/hashgraph-online/hol-guard/commit/bf01ab1cc64745f10d398c3d1a3caa756fd66db0))
* **guard:** find and record observed MCP connections in the resident store op ([#4412](https://github.com/hashgraph-online/hol-guard/issues/4412)) ([4127124](https://github.com/hashgraph-online/hol-guard/commit/4127124aadb42d91966b4d74874f191837f4490e))
* **guard:** read custom-extension grants and command choices in the resident store op ([#4414](https://github.com/hashgraph-online/hol-guard/issues/4414)) ([a8faa5d](https://github.com/hashgraph-online/hol-guard/commit/a8faa5d7c30d4610ab520a4e8c0d23eb997b5abf))
* **guard:** record and forget observed custom extensions in the resident store op ([#4409](https://github.com/hashgraph-online/hol-guard/issues/4409)) ([0229f96](https://github.com/hashgraph-online/hol-guard/commit/0229f967dece2a26aec0435a197d8f9a50d9521e))
* **guard:** reuse registry metadata between npm install reviews ([#4440](https://github.com/hashgraph-online/hol-guard/issues/4440)) ([0a5b916](https://github.com/hashgraph-online/hol-guard/commit/0a5b916d0344633628c3f4e1c101c22507393bcb))
* **guard:** share identical git probe queries within one evaluation ([#4507](https://github.com/hashgraph-online/hol-guard/issues/4507)) ([ecc226d](https://github.com/hashgraph-online/hol-guard/commit/ecc226dc6afb9e78b8166665e4eccfd5827c1d83))
* **guard:** write and read the Cloud advisory cache in the resident store op ([#4435](https://github.com/hashgraph-online/hol-guard/issues/4435)) ([1a98ae8](https://github.com/hashgraph-online/hol-guard/commit/1a98ae83105d18169055080d314739e0a1785c16))
* **hooks:** skip runtime hashing when the native bridge finds its resident ([#4530](https://github.com/hashgraph-online/hol-guard/issues/4530)) ([793fd84](https://github.com/hashgraph-online/hol-guard/commit/793fd84e9dac090ba9c81422e8ffcbcfc8e494cc))

## [3.43.1](https://github.com/hashgraph-online/hol-guard/compare/v3.43.0...v3.43.1) (2026-10-12)


### Bug Fixes

* **ci:** stage external contribution trust before native builds ([#3604](https://github.com/hashgraph-online/hol-guard/issues/3604)) ([a1215d2](https://github.com/hashgraph-online/hol-guard/commit/a1215d2766d66f3d5c3c4a1d6279b0d08fd8fdf0))
* **release:** raise native wheel size budgets so 3.43 can publish ([#4273](https://github.com/hashgraph-online/hol-guard/issues/4273)) ([91d4838](https://github.com/hashgraph-online/hol-guard/commit/91d483808db35766673c52d905a5687dcf2d6017))

## [3.43.0](https://github.com/hashgraph-online/hol-guard/compare/v3.42.0...v3.43.0) (2026-10-12)


### Features

* **cli:** resolve Copilot server identities in Rust ([#4235](https://github.com/hashgraph-online/hol-guard/issues/4235)) ([22af1c6](https://github.com/hashgraph-online/hol-guard/commit/22af1c6649e2329f4384e4a1a60b8e986d6856df))
* **guard:** acquire restricted archives in the native resident ([#4101](https://github.com/hashgraph-online/hol-guard/issues/4101)) ([4090b17](https://github.com/hashgraph-online/hol-guard/commit/4090b17d122ed938956b5c414acb83eedb3afdd3))
* **guard:** add hol-guard repair and step-up gated hook removal ([#3956](https://github.com/hashgraph-online/hol-guard/issues/3956)) ([6258ae0](https://github.com/hashgraph-online/hol-guard/commit/6258ae05284a106acd6ad813921f8449322a0634))
* **guard:** build hook approval-context tokens in the native runtime ([#4223](https://github.com/hashgraph-online/hol-guard/issues/4223)) ([da75713](https://github.com/hashgraph-online/hol-guard/commit/da757133b7093a52862b558621dd40a11a761c91))
* **guard:** build the MCP tool-call artifact and approval hash in the native resident ([#4234](https://github.com/hashgraph-online/hol-guard/issues/4234)) ([be91b4b](https://github.com/hashgraph-online/hol-guard/commit/be91b4b3c5aa55ebe82cd7f6c33e38f69ec6a684))
* **guard:** build workspace scan targets in the native resident ([#4048](https://github.com/hashgraph-online/hol-guard/issues/4048)) ([e5e66ee](https://github.com/hashgraph-online/hol-guard/commit/e5e66ee5340dd615ceab2047422ec4a10b6bc176))
* **guard:** classify sensitive file read and write requests in Rust ([#4073](https://github.com/hashgraph-online/hol-guard/issues/4073)) ([c9ab19e](https://github.com/hashgraph-online/hol-guard/commit/c9ab19ec9ab66626f71bb069e959ccd1c8f7e78a))
* **guard:** compile observed MCP tool actions in the guard store resident ([#4159](https://github.com/hashgraph-online/hol-guard/issues/4159)) ([c2a059c](https://github.com/hashgraph-online/hol-guard/commit/c2a059c3dfc28f1c65338094bbe5fefac9102b7b))
* **guard:** consume native-review approvals in the resident store ([#4194](https://github.com/hashgraph-online/hol-guard/issues/4194)) ([0320660](https://github.com/hashgraph-online/hol-guard/commit/0320660063205e4f9209187d0794c94be3d21a8c))
* **guard:** decide approval-reuse claims and miss diagnosis in the resident ([#3962](https://github.com/hashgraph-online/hol-guard/issues/3962)) ([e68d93c](https://github.com/hashgraph-online/hol-guard/commit/e68d93c2bd81c83596f1714c3f658380fda4cbf8))
* **guard:** decide bulk approve-once eligibility in the native resident ([#4020](https://github.com/hashgraph-online/hol-guard/issues/4020)) ([52eb843](https://github.com/hashgraph-online/hol-guard/commit/52eb843f873f249344d578c470a4dad9bf3b49c9))
* **guard:** decide Codex tool-output review in the native resident ([#3950](https://github.com/hashgraph-online/hol-guard/issues/3950)) ([dac48ab](https://github.com/hashgraph-online/hol-guard/commit/dac48ab1d4e21b89032f7fa1cdb1dd160ff5a0a4))
* **guard:** decide daemon lifecycle in the native resident ([#3969](https://github.com/hashgraph-online/hol-guard/issues/3969)) ([8ffeeb3](https://github.com/hashgraph-online/hol-guard/commit/8ffeeb3992afd47c0a321e1989c83e4b732793ea))
* **guard:** decide daemon route, origin and session policy in the native resident ([#3936](https://github.com/hashgraph-online/hol-guard/issues/3936)) ([3a6c5d1](https://github.com/hashgraph-online/hol-guard/commit/3a6c5d128146b3218f475f2731a8833f73f99e5e))
* **guard:** decide headless app action responses in the native resident ([#3989](https://github.com/hashgraph-online/hol-guard/issues/3989)) ([0c50011](https://github.com/hashgraph-online/hol-guard/commit/0c50011f96b1e883053788c6ad6a98566864f242))
* **guard:** derive and compose the effective native policy in Rust ([#4127](https://github.com/hashgraph-online/hol-guard/issues/4127)) ([f14d8f1](https://github.com/hashgraph-online/hol-guard/commit/f14d8f1fe604c4fd01b96c24b379b4d1128a88a5))
* **guard:** derive approval queue identity in the native resident ([#4001](https://github.com/hashgraph-online/hol-guard/issues/4001)) ([83cafc3](https://github.com/hashgraph-online/hol-guard/commit/83cafc35d37505bee4306d021786e2af22e52a3a))
* **guard:** derive approval scope contracts in the native resident ([#4015](https://github.com/hashgraph-online/hol-guard/issues/4015)) ([352803d](https://github.com/hashgraph-online/hol-guard/commit/352803d4373e8694c1372dd3255983456fe215cd))
* **guard:** derive the local supply-chain posture in the native resident ([#4007](https://github.com/hashgraph-online/hol-guard/issues/4007)) ([66a6fae](https://github.com/hashgraph-online/hol-guard/commit/66a6faec93601108c08bd8e03a666ac549df2ee9))
* **guard:** derive the workspace dependency inventory in the native resident ([#4027](https://github.com/hashgraph-online/hol-guard/issues/4027)) ([07c5f61](https://github.com/hashgraph-online/hol-guard/commit/07c5f61bce61f3a98e76f2c927dd297ae1b7ebef))
* **guard:** evaluate Cloud-connected package supply chain in the resident ([#3933](https://github.com/hashgraph-online/hol-guard/issues/3933)) ([5fea854](https://github.com/hashgraph-online/hol-guard/commit/5fea8543cbd062b9595b6094a929b0907adf9d28))
* **guard:** evaluate local package requests in the native resident ([#3987](https://github.com/hashgraph-online/hol-guard/issues/3987)) ([baab299](https://github.com/hashgraph-online/hol-guard/commit/baab2990e14ceabad0fab8f7707abf979d8fcd39))
* **guard:** fold the configured policy action into the native policy_stack query ([#4254](https://github.com/hashgraph-online/hol-guard/issues/4254)) ([90d293e](https://github.com/hashgraph-online/hol-guard/commit/90d293e0be35d2ba2616a88a47482ed1779261f3))
* **guard:** give per-app protection its own tab and Protect-screen controls ([c9cf0af](https://github.com/hashgraph-online/hol-guard/commit/c9cf0af96c3ec0df0285e9932fb2c17f3f963f42))
* **guard:** identify unlisted local CLIs in the native resident ([#4237](https://github.com/hashgraph-online/hol-guard/issues/4237)) ([33cb25c](https://github.com/hashgraph-online/hol-guard/commit/33cb25c1f5cdc0bb64b263b904e2c8f836be5ad5))
* **guard:** model Windows paths in the native shim admin ([#4232](https://github.com/hashgraph-online/hol-guard/issues/4232)) ([c339d9d](https://github.com/hashgraph-online/hol-guard/commit/c339d9db720c85664f6bbdc08167e5b750a713bc))
* **guard:** move AIBOM workspace detection to the native resident ([#4207](https://github.com/hashgraph-online/hol-guard/issues/4207)) ([6849601](https://github.com/hashgraph-online/hol-guard/commit/6849601573064a98d60cd2cfb9272f9c33487aff))
* **guard:** move artifact inventory store writes to the native resident ([#4022](https://github.com/hashgraph-online/hol-guard/issues/4022)) ([d2ecb5f](https://github.com/hashgraph-online/hol-guard/commit/d2ecb5fefdf00ec5c92941ba169e0f4d5d1f5c16))
* **guard:** move Cisco preflight authority to the native resident ([#4042](https://github.com/hashgraph-online/hol-guard/issues/4042)) ([aed675c](https://github.com/hashgraph-online/hol-guard/commit/aed675c118430b38bfd2828c0e21d9985bad28ba))
* **guard:** move command-activity store into the native resident ([#3997](https://github.com/hashgraph-online/hol-guard/issues/3997)) ([3813f32](https://github.com/hashgraph-online/hol-guard/commit/3813f321cd140c23f59cd05769573b1fec0e7a39))
* **guard:** move consumer artifact decision composition to the native runtime ([#4108](https://github.com/hashgraph-online/hol-guard/issues/4108)) ([36f5994](https://github.com/hashgraph-online/hol-guard/commit/36f5994462cf549d2d184b1be3b07a6e8fc1965b))
* **guard:** move direct-tool context authority into the native resident ([#4137](https://github.com/hashgraph-online/hol-guard/issues/4137)) ([3558b3b](https://github.com/hashgraph-online/hol-guard/commit/3558b3bb65afc722ae79e812e26ca28ef56501e6))
* **guard:** move hook payload preparation and the action envelope to the native resident ([#3940](https://github.com/hashgraph-online/hol-guard/issues/3940)) ([b3f185b](https://github.com/hashgraph-online/hol-guard/commit/b3f185b772b3412acc37101744c97197c302fc14))
* **guard:** move MCP archive binding and package signals into the resident ([#4063](https://github.com/hashgraph-online/hol-guard/issues/4063)) ([94a01c7](https://github.com/hashgraph-online/hol-guard/commit/94a01c7d3e313c00bb951d303865c44761ded957))
* **guard:** move package audit projections to the native resident ([#4083](https://github.com/hashgraph-online/hol-guard/issues/4083)) ([4144bb5](https://github.com/hashgraph-online/hol-guard/commit/4144bb556fff0f2c0b24497669b4aa3727f69972))
* **guard:** move package execution context build to the native resident ([#4231](https://github.com/hashgraph-online/hol-guard/issues/4231)) ([32cfe23](https://github.com/hashgraph-online/hol-guard/commit/32cfe23f49b697c7542e3d96d4d56d37ac5a7ba5))
* **guard:** move runner cloud-sync decisions into the native resident ([#3978](https://github.com/hashgraph-online/hol-guard/issues/3978)) ([efeb1c3](https://github.com/hashgraph-online/hol-guard/commit/efeb1c30b1197a8412cb905611f46c9f5c99f7e9))
* **guard:** move session, operation and client-lease store into the native resident ([#4012](https://github.com/hashgraph-online/hol-guard/issues/4012)) ([086110c](https://github.com/hashgraph-online/hol-guard/commit/086110cb6a69b091a7e6a20638b6d7fc7cd2d7bf))
* **guard:** move signed Claude/Cursor hook authority state to the native resident ([#4113](https://github.com/hashgraph-online/hol-guard/issues/4113)) ([d658157](https://github.com/hashgraph-online/hol-guard/commit/d65815731ad7d2928cfb89e34db861ba46a9ac53))
* **guard:** move storage maintenance into the native resident ([#4053](https://github.com/hashgraph-online/hol-guard/issues/4053)) ([00b113e](https://github.com/hashgraph-online/hol-guard/commit/00b113e33931b7b477e6d5fe26dd275a574d3974))
* **guard:** move the Codex request-resume record to the native resident ([#4147](https://github.com/hashgraph-online/hol-guard/issues/4147)) ([72aedb0](https://github.com/hashgraph-online/hol-guard/commit/72aedb0dd2bd8793f7116b327f204060cc533263))
* **guard:** move the receipt store, rollups and analytics into the resident ([#4072](https://github.com/hashgraph-online/hol-guard/issues/4072)) ([94ab442](https://github.com/hashgraph-online/hol-guard/commit/94ab442d5b2ddd2c620b4086818934d81ac24d81))
* **guard:** move workflow-capability authority to the native resident ([#4092](https://github.com/hashgraph-online/hol-guard/issues/4092)) ([c790f64](https://github.com/hashgraph-online/hol-guard/commit/c790f64bd5f1a6b3dc6fa7e42872a3897569f6af))
* **guard:** native Codex harness detection at exact Python parity ([#4264](https://github.com/hashgraph-online/hol-guard/issues/4264)) ([ffa8f4f](https://github.com/hashgraph-online/hol-guard/commit/ffa8f4f3c7492a41bf45eb601f4703d3d60e02f8))
* **guard:** native Hermes harness detection at exact Python parity ([#4233](https://github.com/hashgraph-online/hol-guard/issues/4233)) ([e5f7e37](https://github.com/hashgraph-online/hol-guard/commit/e5f7e379bd20c384b5350426cfce8093bff80c21))
* **guard:** native package-shim administration at exact Python parity ([#4205](https://github.com/hashgraph-online/hol-guard/issues/4205)) ([067a066](https://github.com/hashgraph-online/hol-guard/commit/067a066cfa586f0491220b163c3eea190f06dded))
* **guard:** offer exact-action Always for read-only git, file reads and proven compound commands ([#3961](https://github.com/hashgraph-online/hol-guard/issues/3961)) ([19b0f8a](https://github.com/hashgraph-online/hol-guard/commit/19b0f8a3e2c8a83363de4ee95142ab6c1dc47ea2))
* **guard:** offer exact-action Always for todo tools and refuse it for risk-signal reviews ([#4043](https://github.com/hashgraph-online/hol-guard/issues/4043)) ([ed0d602](https://github.com/hashgraph-online/hol-guard/commit/ed0d602f12f624df870db32989366bb5cb415e40))
* **guard:** plan approval resolutions in the native resident ([#3994](https://github.com/hashgraph-online/hol-guard/issues/3994)) ([5e15ac6](https://github.com/hashgraph-online/hol-guard/commit/5e15ac6a9d15894463edd3854ae8f45e3af7be5f))
* **guard:** port docker requests, jq filters and static shell safety to Rust ([#4081](https://github.com/hashgraph-online/hol-guard/issues/4081)) ([1f2a4c2](https://github.com/hashgraph-online/hol-guard/commit/1f2a4c260171ea62237639c1831091d68d7b42f2))
* **guard:** port GitHub shell helpers, developer graph, index inspection and source edits to Rust ([#4123](https://github.com/hashgraph-online/hol-guard/issues/4123)) ([75b8545](https://github.com/hashgraph-online/hol-guard/commit/75b85450835c9539de048609ac70a86a8f1b29ba))
* **guard:** port the benign native file read check to Rust ([#4075](https://github.com/hashgraph-online/hol-guard/issues/4075)) ([f877083](https://github.com/hashgraph-online/hol-guard/commit/f877083ec7f514a63a345a1ba34cd44312c5983a))
* **guard:** port the contained node, TypeScript and Bun script runners to the resident ([#4078](https://github.com/hashgraph-online/hol-guard/issues/4078)) ([67a358c](https://github.com/hashgraph-online/hol-guard/commit/67a358c905f33606edbde86bece22c5218e4b560))
* **guard:** port the sensitive tool-action dispatcher to Rust ([#4246](https://github.com/hashgraph-online/hol-guard/issues/4246)) ([a32ac6d](https://github.com/hashgraph-online/hol-guard/commit/a32ac6d5a2881e10e3d449d5c0e6a25fd5bbf8c2))
* **guard:** port ZCode harness detection to the native runtime ([#4218](https://github.com/hashgraph-online/hol-guard/issues/4218)) ([c50f1e4](https://github.com/hashgraph-online/hol-guard/commit/c50f1e482e335cf1d27529af9d004b5faed75d46))
* **guard:** prepare restricted test execution with native authority ([#4213](https://github.com/hashgraph-online/hol-guard/issues/4213)) ([73c7eb5](https://github.com/hashgraph-online/hol-guard/commit/73c7eb505982534733587df5942c56647b519c9d))
* **guard:** record bounded startup phase timings in the daemon diagnostics ([#4076](https://github.com/hashgraph-online/hol-guard/issues/4076)) ([f529350](https://github.com/hashgraph-online/hol-guard/commit/f529350341ba357e322b4d628af2862725c19de4))
* **guard:** render CLI hook responses and documents in the native resident ([#4172](https://github.com/hashgraph-online/hol-guard/issues/4172)) ([5b5ac3f](https://github.com/hashgraph-online/hol-guard/commit/5b5ac3f9b47ee3c3161d2661ab637570572ffbb0))
* **guard:** render hook harness responses in the native resident ([#4054](https://github.com/hashgraph-online/hol-guard/issues/4054)) ([7e1a027](https://github.com/hashgraph-online/hol-guard/commit/7e1a027d981675418cd53c13421e6de23ccc3fd5))
* **guard:** route package-shim admin through the resident shim_admin op ([#4215](https://github.com/hashgraph-online/hol-guard/issues/4215)) ([1971ab7](https://github.com/hashgraph-online/hol-guard/commit/1971ab7e62493b0f2a5d7a310c1624cfeace4768))
* **guard:** run Codex test commands in the contained runner ([#4170](https://github.com/hashgraph-online/hol-guard/issues/4170)) ([d75f7f7](https://github.com/hashgraph-online/hol-guard/commit/d75f7f7c590536b3116bd03643033e19ca4117f9))
* **guard:** run hol-guard secrets scans and hooks in the native runtime ([#4182](https://github.com/hashgraph-online/hol-guard/issues/4182)) ([78be1d8](https://github.com/hashgraph-online/hol-guard/commit/78be1d8ba27b832891e63acc29e2ff949c468fbd))
* **guard:** send Codex thread continuations from the native resident ([#4125](https://github.com/hashgraph-online/hol-guard/issues/4125)) ([3b9e855](https://github.com/hashgraph-online/hol-guard/commit/3b9e855bb1989263b492e886278998302168e312))
* **guard:** set Watch or Protected per app ([#3952](https://github.com/hashgraph-online/hol-guard/issues/3952)) ([5ff8c0d](https://github.com/hashgraph-online/hol-guard/commit/5ff8c0d93947be66ea32624bfda1d9d0f7b20191))
* **guard:** settle Copilot tool calls in the native resident ([#4209](https://github.com/hashgraph-online/hol-guard/issues/4209)) ([df9e43e](https://github.com/hashgraph-online/hol-guard/commit/df9e43e5689a72418db7eda451a075620869cf44))
* **guard:** validate daemon handler requests in the native resident ([#3979](https://github.com/hashgraph-online/hol-guard/issues/3979)) ([17c2338](https://github.com/hashgraph-online/hol-guard/commit/17c2338034d6bdbf3b11ca5198b34eaed48319e3))
* **guard:** verify Cursor after-observer proofs in the native resident ([#4006](https://github.com/hashgraph-online/hol-guard/issues/4006)) ([bf7bf79](https://github.com/hashgraph-online/hol-guard/commit/bf7bf79c95b7946c7b64e7166952b18c687a6a91))
* **protect:** parse install commands and match cached advisories in the native resident ([#4160](https://github.com/hashgraph-online/hol-guard/issues/4160)) ([4e0c1cd](https://github.com/hashgraph-online/hol-guard/commit/4e0c1cd0cd2116867ce7908c1fc00227ac6a460a))
* **release:** cut optional alpha releases from main through Release Please ([#4099](https://github.com/hashgraph-online/hol-guard/issues/4099)) ([a23f859](https://github.com/hashgraph-online/hol-guard/commit/a23f8596bf023914da8875045d60f4e0bd0ee12a))
* **release:** publish signed Desktop Core sidecars for alpha prereleases ([#4100](https://github.com/hashgraph-online/hol-guard/issues/4100)) ([2f8ffac](https://github.com/hashgraph-online/hol-guard/commit/2f8ffacec49cd8dc17e412ac1970b80ef14a43c3))
* **runtime:** add pinned native process custody and capture ([#3751](https://github.com/hashgraph-online/hol-guard/issues/3751)) ([a3a8148](https://github.com/hashgraph-online/hol-guard/commit/a3a814802a03efe250be70c54b7ad69a355596ef))
* **runtime:** native skill-directory identity on all platforms ([e3807d9](https://github.com/hashgraph-online/hol-guard/commit/e3807d944094262e706664544fa976c3c50aa1e8))
* **runtime:** run the default runtime detectors in the native resident ([#4145](https://github.com/hashgraph-online/hol-guard/issues/4145)) ([dce33e7](https://github.com/hashgraph-online/hol-guard/commit/dce33e717bbab48c288bdd6b287a51fcfc3604f3))


### Bug Fixes

* **ci:** accept the compact native PostToolUse shape in the legacy-mode probe ([#4087](https://github.com/hashgraph-online/hol-guard/issues/4087)) ([99c1ce3](https://github.com/hashgraph-online/hol-guard/commit/99c1ce3f7ad62bccfcea5f6b6aeba0af498f102a))
* **ci:** check the pre-tool command dispatch where it now lives ([#4003](https://github.com/hashgraph-online/hol-guard/issues/4003)) ([3a0b25a](https://github.com/hashgraph-online/hol-guard/commit/3a0b25a9007ef4f4a898016130c17a682de5c6ea))
* **ci:** clear Windows clippy, regression-list and format drift from the native lanes ([#4036](https://github.com/hashgraph-online/hol-guard/issues/4036)) ([139168d](https://github.com/hashgraph-online/hol-guard/commit/139168de795b09609e4c233eb19611276df29385))
* **claude:** give the hook bridge four seconds to reach the daemon ([#4068](https://github.com/hashgraph-online/hol-guard/issues/4068)) ([f584ad3](https://github.com/hashgraph-online/hol-guard/commit/f584ad3b9f7ccccc1ea2ccfd7d012dc5a0ebf8e3))
* **claude:** time the hook from its own request, not the identity challenge ([#4124](https://github.com/hashgraph-online/hol-guard/issues/4124)) ([61e958e](https://github.com/hashgraph-online/hol-guard/commit/61e958ebd019f31efbeab68b1af02c5d1c97526e))
* **cli:** drop an always-true workspace check in Copilot root resolution ([#4258](https://github.com/hashgraph-online/hol-guard/issues/4258)) ([2c3f927](https://github.com/hashgraph-online/hol-guard/commit/2c3f92798ff3cfbef44f2303450a82fc1a599942))
* **cloud-review:** recover expired sign-in without redundant approval ([#3111](https://github.com/hashgraph-online/hol-guard/issues/3111)) ([644faea](https://github.com/hashgraph-online/hol-guard/commit/644faeac5228a3a46eb4ec203dacdffba56ea3ad))
* **codex:** name the real cause when the hook bridge cannot reach the daemon ([#4155](https://github.com/hashgraph-online/hol-guard/issues/4155)) ([bae1805](https://github.com/hashgraph-online/hol-guard/commit/bae1805632ba27e63f7c9f4f6f6cdec78f500a63))
* **contained-process:** stop probing Windows Lib paths on case-insensitive macOS volumes ([#4038](https://github.com/hashgraph-online/hol-guard/issues/4038)) ([7bfb9d0](https://github.com/hashgraph-online/hol-guard/commit/7bfb9d044acec8c72444d6b9a6588e82af811d1e))
* **dashboard:** retry a failed screen once before showing the error page ([#4193](https://github.com/hashgraph-online/hol-guard/issues/4193)) ([9987159](https://github.com/hashgraph-online/hol-guard/commit/9987159fc866119d06bed1ba698dc49d06d1a6a1))
* **extensions:** invite introducing contributors to claim automatically ([#3985](https://github.com/hashgraph-online/hol-guard/issues/3985)) ([b8028fc](https://github.com/hashgraph-online/hol-guard/commit/b8028fcd1d84c16aa11898eb042a70896f20b39e))
* **gauntlet:** accept OMP contained-test runs in core cases only when fully bound ([#4267](https://github.com/hashgraph-online/hol-guard/issues/4267)) ([f189056](https://github.com/hashgraph-online/hol-guard/commit/f18905678a8e386395e53a64ebfb2b54084be7e1))
* **gauntlet:** ask for each listed command as its own Bash call ([#4270](https://github.com/hashgraph-online/hol-guard/issues/4270)) ([1210e0c](https://github.com/hashgraph-online/hol-guard/commit/1210e0c9924fdd30a53fbf6ea39f898bf0776774))
* **gauntlet:** bind OMP raw reads to their resolved source ([#4045](https://github.com/hashgraph-online/hol-guard/issues/4045)) ([1bf30fd](https://github.com/hashgraph-online/hol-guard/commit/1bf30fd5d4396c508f765f87a6bfda6360db8fb8))
* **gauntlet:** bind scratch-directory output to SDK timing metadata ([#4031](https://github.com/hashgraph-online/hol-guard/issues/4031)) ([bddeb22](https://github.com/hashgraph-online/hol-guard/commit/bddeb2244e5f43f137aaca3c6a111faf74227905))
* **gauntlet:** keep Luna inference streams alive ([45d8b4b](https://github.com/hashgraph-online/hol-guard/commit/45d8b4be5cbeb54ee6cbc1ed7824cfe9efcc5c6c))
* **gauntlet:** match the native session-tool contract ([#3995](https://github.com/hashgraph-online/hol-guard/issues/3995)) ([e23ab57](https://github.com/hashgraph-online/hol-guard/commit/e23ab5725ed2e3611010ac00ba7668411ebb141d))
* **gauntlet:** reconcile delegated model and tool evidence ([af4a627](https://github.com/hashgraph-online/hol-guard/commit/af4a627652a60343ddb1af83917bd5972d44ee10))
* **gauntlet:** stop the Guard tap from serializing parallel reviews ([#4149](https://github.com/hashgraph-online/hol-guard/issues/4149)) ([a3c6c11](https://github.com/hashgraph-online/hol-guard/commit/a3c6c11793f2be3e231882657e35d19489c8d9c7))
* **gauntlet:** verify SDK eval bridge execution ([ab2ec13](https://github.com/hashgraph-online/hol-guard/commit/ab2ec138dd24504066e319ba5fbd0657597e3fac))
* **guard:** accept constant text encodings in PowerShell file calls ([#3970](https://github.com/hashgraph-online/hol-guard/issues/3970)) ([291afeb](https://github.com/hashgraph-online/hol-guard/commit/291afebffd36dfaa0f4a585297e6a256eb679cc8))
* **guard:** accept Promise.all reads and console.log output in Oh My Pi eval ([#4139](https://github.com/hashgraph-online/hol-guard/issues/4139)) ([919b5cc](https://github.com/hashgraph-online/hol-guard/commit/919b5cc91dbfe726ad9c7acbc328ece309e92d12))
* **guard:** accept repeated separators in exact Windows drive targets ([#4033](https://github.com/hashgraph-online/hol-guard/issues/4033)) ([bce3218](https://github.com/hashgraph-online/hol-guard/commit/bce3218f9c25ef523467efa0c8a1e1d38231fd1e))
* **guard:** accept the ZCode managed-hook marker when cmd.exe passes it as arguments ([#3992](https://github.com/hashgraph-online/hol-guard/issues/3992)) ([8794a77](https://github.com/hashgraph-online/hol-guard/commit/8794a77aa7561966be4feb075754efe4f85383be))
* **guard:** admit bounded read-only shell probes in the native proof ([#3973](https://github.com/hashgraph-online/hol-guard/issues/3973)) ([d9fc01e](https://github.com/hashgraph-online/hol-guard/commit/d9fc01e9f4c33d26944dcc8844eb74ffb5d04ca1))
* **guard:** allow bounded Oh My Pi task, eval, listing, skill and artifact reads ([#3959](https://github.com/hashgraph-online/hol-guard/issues/3959)) ([180b0af](https://github.com/hashgraph-online/hol-guard/commit/180b0af9f8e2dc793fba9a93d48ea77e935156e2))
* **guard:** allow file reads of Git HEAD and ref files in workspace repositories ([#4134](https://github.com/hashgraph-online/hol-guard/issues/4134)) ([21eeb08](https://github.com/hashgraph-online/hol-guard/commit/21eeb08cc01021545d08248aeea54f10e7231069))
* **guard:** allow git reads with untracked nested repos and registered linked worktrees ([#3960](https://github.com/hashgraph-online/hol-guard/issues/3960)) ([0026040](https://github.com/hashgraph-online/hol-guard/commit/0026040967a4c6a906f101934b85cbe8f193f30f))
* **guard:** allow linked worktrees to read refs in their common git dir ([#4163](https://github.com/hashgraph-online/hol-guard/issues/4163)) ([fa2b79b](https://github.com/hashgraph-online/hol-guard/commit/fa2b79b2deb8c1c5c17ae1fff1599c92d7ec7180))
* **guard:** allow lone version queries for package tools and rustup-proxied cargo ([#4077](https://github.com/hashgraph-online/hol-guard/issues/4077)) ([ce2643e](https://github.com/hashgraph-online/hol-guard/commit/ce2643e09332d4eb7db7ece09f1c3621641f51ba))
* **guard:** allow names-only listings of the Oh My Pi agent root ([#4263](https://github.com/hashgraph-online/hol-guard/issues/4263)) ([f4b49e2](https://github.com/hashgraph-online/hol-guard/commit/f4b49e201135f5dce64f254b84e917c1ba6b2572))
* **guard:** allow read-only git branch listings and hash-object reads without approval ([#4056](https://github.com/hashgraph-online/hol-guard/issues/4056)) ([d4026a6](https://github.com/hashgraph-online/hol-guard/commit/d4026a673dfbe03de34f4e6303006f0177869f7e))
* **guard:** allow recursive copies that create a new workspace tree ([#4192](https://github.com/hashgraph-online/hol-guard/issues/4192)) ([738c6c7](https://github.com/hashgraph-online/hol-guard/commit/738c6c78a2d97b84f2aa72c6eb2f4737e3572d14))
* **guard:** allow rg searches of sibling repositories below home ([#4166](https://github.com/hashgraph-online/hol-guard/issues/4166)) ([6ea1954](https://github.com/hashgraph-online/hol-guard/commit/6ea1954a3478ac0c105cf2c31850f600e1a28189))
* **guard:** allow the contained pytest runner route Guard recommends ([#4044](https://github.com/hashgraph-online/hol-guard/issues/4044)) ([a057e07](https://github.com/hashgraph-online/hol-guard/commit/a057e07576b6bc12a44e9c64c4eabebc6eb6424b))
* **guard:** bound CLI-run hook native evaluation with a real deadline instead of 0.75s ([#4104](https://github.com/hashgraph-online/hol-guard/issues/4104)) ([d3bf08b](https://github.com/hashgraph-online/hol-guard/commit/d3bf08bbcacfcb8f1f8d5f2f8647c47ca3124e33))
* **guard:** carry a bounded reason when the resident prerequisite cannot be provisioned ([#4074](https://github.com/hashgraph-online/hol-guard/issues/4074)) ([e3f0206](https://github.com/hashgraph-online/hol-guard/commit/e3f0206722084b1c2bea18416849df4d5b1a15e1))
* **guard:** contain builds and tests run after cd into a sibling repository ([#4262](https://github.com/hashgraph-online/hol-guard/issues/4262)) ([f143996](https://github.com/hashgraph-online/hol-guard/commit/f14399633af333e520a8e7abbaa7932a58135db9))
* **guard:** contain test-named TypeScript and JavaScript scripts ([#4268](https://github.com/hashgraph-online/hol-guard/issues/4268)) ([8a621d4](https://github.com/hashgraph-online/hol-guard/commit/8a621d4fc5ce8f2606abf0ff29c338fe21bd4786))
* **guard:** daemon repair no longer fails when one lifecycle request lapses on a slow host ([#4115](https://github.com/hashgraph-online/hol-guard/issues/4115)) ([d38b591](https://github.com/hashgraph-online/hol-guard/commit/d38b591bac9396eb8f6f36201f200e10a79506e7))
* **guard:** expand named-user skill rules, widen aibom deadlines, back off MCP enrichment ([#4230](https://github.com/hashgraph-online/hol-guard/issues/4230)) ([084de22](https://github.com/hashgraph-online/hol-guard/commit/084de22a1f9f6f6566f9752ec7c77616eaf9b63c))
* **guard:** fail Codex hook health and update loudly when a Guard handler points at a deleted program ([#4089](https://github.com/hashgraph-online/hol-guard/issues/4089)) ([9ea8913](https://github.com/hashgraph-online/hol-guard/commit/9ea8913165750012d9cc44110241ed8841151c30))
* **guard:** give a cold resident spawn an allowance on daemon lifecycle verdicts ([#4023](https://github.com/hashgraph-online/hol-guard/issues/4023)) ([22d4a21](https://github.com/hashgraph-online/hol-guard/commit/22d4a2114c48e71839cf09918c3eaf844b2f7be7))
* **guard:** give Pi ls, find and grep the same bounded proofs as Oh My Pi ([#4082](https://github.com/hashgraph-online/hol-guard/issues/4082)) ([74bcb6f](https://github.com/hashgraph-online/hol-guard/commit/74bcb6fc67524a7788cb035733a786e3be1ee13e))
* **guard:** honor Extensions Allow for plain git fetch origin ([#3953](https://github.com/hashgraph-online/hol-guard/issues/3953)) ([29d2f37](https://github.com/hashgraph-online/hol-guard/commit/29d2f37b3238374ab59e1de9159c1c6e0c26392a))
* **guard:** keep a Codex hook waiting for a daemon that is still starting ([#4179](https://github.com/hashgraph-online/hol-guard/issues/4179)) ([d116a03](https://github.com/hashgraph-online/hol-guard/commit/d116a0320548eef15383223d7e4b629f9fea967d))
* **guard:** keep a slow-starting daemon alive instead of terminating it ([#4106](https://github.com/hashgraph-online/hol-guard/issues/4106)) ([4752bea](https://github.com/hashgraph-online/hol-guard/commit/4752beaf8438580ed7ed1e1980f9e05552e23148))
* **guard:** keep a slow-starting daemon alive when its start budget runs out ([#4168](https://github.com/hashgraph-online/hol-guard/issues/4168)) ([f15a541](https://github.com/hashgraph-online/hol-guard/commit/f15a54163b2c826cd190a13d74aadbd51bc9734e))
* **guard:** keep Git read proofs stable in large repositories and on busy hosts ([#4120](https://github.com/hashgraph-online/hol-guard/issues/4120)) ([00ccd7f](https://github.com/hashgraph-online/hol-guard/commit/00ccd7f9449ddcc7007ec302e3c1176cd6222dbd))
* **guard:** keep Git read proofs when loader search paths point at trusted system directories ([#4094](https://github.com/hashgraph-online/hol-guard/issues/4094)) ([cf00113](https://github.com/hashgraph-online/hol-guard/commit/cf0011371910cc63f6bc03817e2001cbaffbc9d2))
* **guard:** keep Git read proofs when the loader search path names a home toolchain directory ([#4144](https://github.com/hashgraph-online/hol-guard/issues/4144)) ([9773ed0](https://github.com/hashgraph-online/hol-guard/commit/9773ed047c491132a22d6a90d7330108ee0ab65e))
* **guard:** keep non-finite package-shim manifest fields ([#4265](https://github.com/hashgraph-online/hol-guard/issues/4265)) ([1302423](https://github.com/hashgraph-online/hol-guard/commit/1302423a2bc77e3c822f196bfb3fb8be352040e1))
* **guard:** keep read-only proofs through 2&gt;&1, allow Oh My Pi Python reads, and let the gate see real Git config ([#4035](https://github.com/hashgraph-online/hol-guard/issues/4035)) ([9562066](https://github.com/hashgraph-online/hol-guard/commit/9562066c9ef00712d7205be449a34ddd47944052))
* **guard:** keep the code from a framed resident refusal in policy bundle calls ([#4055](https://github.com/hashgraph-online/hol-guard/issues/4055)) ([00be9ff](https://github.com/hashgraph-online/hol-guard/commit/00be9ffcadb54092cfce7aebaac5e94a6da0342d))
* **guard:** keep the policy-floor warning silent on proven-safe tool output ([#4251](https://github.com/hashgraph-online/hol-guard/issues/4251)) ([c25c379](https://github.com/hashgraph-online/hol-guard/commit/c25c3794520bd4cc3b4044d94ffec5930e34849e))
* **guard:** let bounded staged diffs use the ordinary git read proof ([#4269](https://github.com/hashgraph-online/hol-guard/issues/4269)) ([7d84b0d](https://github.com/hashgraph-online/hol-guard/commit/7d84b0d1ad09822f2797500ebe97b130863986a0))
* **guard:** let du, df, diff and git config reads run without review ([#4260](https://github.com/hashgraph-online/hol-guard/issues/4260)) ([ccb9d14](https://github.com/hashgraph-online/hol-guard/commit/ccb9d149d7c9e45ae420cd5682fab265f40ecbee))
* **guard:** let enabled GitHub permissions cover GraphQL mutations and [@mentions](https://github.com/mentions) ([#4202](https://github.com/hashgraph-online/hol-guard/issues/4202)) ([6f2876a](https://github.com/hashgraph-online/hol-guard/commit/6f2876a1198d5d3c0919662a72c009f743591611))
* **guard:** let Oh My Pi search its own artifact reports ([#4165](https://github.com/hashgraph-online/hol-guard/issues/4165)) ([322fae8](https://github.com/hashgraph-online/hol-guard/commit/322fae8186ed008e47d1570cef7d960fa3cc8b1b))
* **guard:** let prompts that only name a credential stay benign ([#3955](https://github.com/hashgraph-online/hol-guard/issues/3955)) ([53cc010](https://github.com/hashgraph-online/hol-guard/commit/53cc0103e95d5fcb9d457163d3c895e46faedd9e))
* **guard:** list Next.js bracket route folders without review ([#4161](https://github.com/hashgraph-online/hol-guard/issues/4161)) ([83bf7e7](https://github.com/hashgraph-online/hol-guard/commit/83bf7e7d9d2320047251d9df1cc6091b8c1a6067))
* **guard:** make the dead-daemon fast path and hook-removal floor work end to end ([#3984](https://github.com/hashgraph-online/hol-guard/issues/3984)) ([5d09b78](https://github.com/hashgraph-online/hol-guard/commit/5d09b782e7b1c9f79e661d9ed11897b0095d1623))
* **guard:** prove benign omp/zcode reads, globs and constant evals natively ([#4052](https://github.com/hashgraph-online/hol-guard/issues/4052)) ([db12664](https://github.com/hashgraph-online/hol-guard/commit/db12664aebe2a4a4ca6da2cd5274b3f97948e528))
* **guard:** prove cd-compound and -C git history reads as read-only ([#4047](https://github.com/hashgraph-online/hol-guard/issues/4047)) ([541316a](https://github.com/hashgraph-online/hol-guard/commit/541316a3e88feb125bf925755cd0e0f7b0236c9a))
* **guard:** prove each file in a multi-file cat read ([#4050](https://github.com/hashgraph-online/hol-guard/issues/4050)) ([b1efe28](https://github.com/hashgraph-online/hol-guard/commit/b1efe285461acf879939608dd9c530e06011c980))
* **guard:** prove read-only rg, fd and git -C across repositories below home ([#4112](https://github.com/hashgraph-online/hol-guard/issues/4112)) ([02aac58](https://github.com/hashgraph-online/hol-guard/commit/02aac58e8d98e0229a546e833d2bcc6308c2988c))
* **guard:** prove rg glob operands by expanding them like the shell ([#4069](https://github.com/hashgraph-online/hol-guard/issues/4069)) ([4a73814](https://github.com/hashgraph-online/hol-guard/commit/4a738143b6dca7db58b387bc0ab20bf6d35b5c68))
* **guard:** publish the verifier key atomically on first provision ([#4096](https://github.com/hashgraph-online/hol-guard/issues/4096)) ([bf767c3](https://github.com/hashgraph-online/hol-guard/commit/bf767c3807105be3e6290b5554cc71543b3d18e2))
* **guard:** read hook stdin as UTF-8 on every platform ([#4066](https://github.com/hashgraph-online/hol-guard/issues/4066)) ([e76a3b0](https://github.com/hashgraph-online/hol-guard/commit/e76a3b054408ce2900d7c922f46429abe4ad2cc8))
* **guard:** recover the native runtime after it dies and fail hooks fast ([#4058](https://github.com/hashgraph-online/hol-guard/issues/4058)) ([0efe479](https://github.com/hashgraph-online/hol-guard/commit/0efe47992500d1d7504d2727a94e3f494b4f2a13))
* **guard:** refresh a superseded policy snapshot before failing a daemon hook ([#4131](https://github.com/hashgraph-online/hol-guard/issues/4131)) ([4bf0c32](https://github.com/hashgraph-online/hol-guard/commit/4bf0c3225ccdec4bb72186a9bbf7aa3815cae004))
* **guard:** resolve new-code Sonar findings in hook removal, state prune and Windows capture ([#4032](https://github.com/hashgraph-online/hol-guard/issues/4032)) ([ef0f876](https://github.com/hashgraph-online/hol-guard/commit/ef0f8760146aa4b9466a1d94f7d1bfa368692756))
* **guard:** retry truncated daemon GET bodies read through read1 ([#3981](https://github.com/hashgraph-online/hol-guard/issues/3981)) ([8c3b1a7](https://github.com/hashgraph-online/hol-guard/commit/8c3b1a710d4edd833988efde228f802b53d6f52e))
* **guard:** reuse the native review binding when queueing a review ([#4243](https://github.com/hashgraph-online/hol-guard/issues/4243)) ([ab46ac6](https://github.com/hashgraph-online/hol-guard/commit/ab46ac68d4c967a2a20b28a8b9c9877873796e86))
* **guard:** review PostToolUse results after a contained test supersedes the policy snapshot ([#4272](https://github.com/hashgraph-online/hol-guard/issues/4272)) ([f905512](https://github.com/hashgraph-online/hol-guard/commit/f9055129f882448f18f3784f65fbce8a1e265e05))
* **guard:** review writes that place a shared library below home ([#4154](https://github.com/hashgraph-online/hol-guard/issues/4154)) ([d38713c](https://github.com/hashgraph-online/hol-guard/commit/d38713c995886f53404aa4fa89250591f75e06dc))
* **guard:** run Claude Code test commands in the contained runner on macOS ([#4157](https://github.com/hashgraph-online/hol-guard/issues/4157)) ([3449d43](https://github.com/hashgraph-online/hol-guard/commit/3449d43cb604aed34bdd1dc9cbf6cb071906f62a))
* **guard:** run test-named Python scripts in the read-only inline-eval boundary ([#4199](https://github.com/hashgraph-online/hol-guard/issues/4199)) ([120f87b](https://github.com/hashgraph-online/hol-guard/commit/120f87bce027f823fc39c03e69bfcb09aebfa64a))
* **guard:** scale the resident client handshake window with the request budget ([#4062](https://github.com/hashgraph-online/hol-guard/issues/4062)) ([75d40b2](https://github.com/hashgraph-online/hol-guard/commit/75d40b2ae8c39c41089ae209942c8cbf5e36b502))
* **guard:** skip the unknown-publisher review for proven constant MCP evals ([#4177](https://github.com/hashgraph-online/hol-guard/issues/4177)) ([805d5d3](https://github.com/hashgraph-online/hol-guard/commit/805d5d3e96925e2192062962b8e4c29e11dd048f))
* **guard:** stop rendering the policy-floor warning on proven-safe tool calls ([#4060](https://github.com/hashgraph-online/hol-guard/issues/4060)) ([807c953](https://github.com/hashgraph-online/hol-guard/commit/807c9531daf468b4a2516c596062d45eada9cc4f))
* **guard:** stop reviewing ordinary git reads for a configured textconv driver ([#4107](https://github.com/hashgraph-online/hol-guard/issues/4107)) ([6c4e51d](https://github.com/hashgraph-online/hol-guard/commit/6c4e51d88b63cc9a89232935b7f04449185b2fbf))
* **guard:** treat a workspace in the macOS per-user temporary directory as a workspace ([#4126](https://github.com/hashgraph-online/hol-guard/issues/4126)) ([c939823](https://github.com/hashgraph-online/hol-guard/commit/c939823167621abe1e6bc6084f89847a9c63622d))
* **guard:** treat writes into user-owned temp directories as bounded file writes ([#3958](https://github.com/hashgraph-online/hol-guard/issues/3958)) ([53853e5](https://github.com/hashgraph-online/hol-guard/commit/53853e53410a17d4dc1a2f0f50d304f666ac2749))
* **omp:** admit bounded reads and scan typed reports before submission ([#3998](https://github.com/hashgraph-online/hol-guard/issues/3998)) ([08ebbe1](https://github.com/hashgraph-online/hol-guard/commit/08ebbe12fd107a50dbe0a3751966cbd948989b01))
* **omp:** let ordinary skill, artifact, scratch and raw reads complete ([#4017](https://github.com/hashgraph-online/hol-guard/issues/4017)) ([4136e0a](https://github.com/hashgraph-online/hol-guard/commit/4136e0ac62febc7a89404f2e680099949e8cdce7))
* **release:** give release jobs their own GitHub App token and retry rate-limited API calls ([#4143](https://github.com/hashgraph-online/hol-guard/issues/4143)) ([00b066d](https://github.com/hashgraph-online/hol-guard/commit/00b066dc8b5aa42a67d269042c15cde3827844c4))
* **release:** read the PyPI publish job from the first publish attempt ([#3972](https://github.com/hashgraph-online/hol-guard/issues/3972)) ([626e4f1](https://github.com/hashgraph-online/hol-guard/commit/626e4f118bf01817eeb6ba5fef62fda854ee4d1c))
* **release:** verify alpha Core sidecar wheels against the GitHub prerelease ([#4117](https://github.com/hashgraph-online/hol-guard/issues/4117)) ([d7759da](https://github.com/hashgraph-online/hol-guard/commit/d7759da490fe1b98cf1d7eb1fb1a8cae7bba4c84))
* **runtime:** gate the remaining Unix-only imports for Windows clippy ([#4051](https://github.com/hashgraph-online/hol-guard/issues/4051)) ([ec4936f](https://github.com/hashgraph-online/hol-guard/commit/ec4936f9f81c2e392dd63153b07a65a7dfe4ee67))
* **update:** install the native alpha wheel from the GitHub prerelease ([#4118](https://github.com/hashgraph-online/hol-guard/issues/4118)) ([df3fad4](https://github.com/hashgraph-online/hol-guard/commit/df3fad42e6acf3f317a21f7ea796c05f70815d52))
* **update:** only offer alpha releases whose GitHub prerelease tag is still live ([#4097](https://github.com/hashgraph-online/hol-guard/issues/4097)) ([8d96ae7](https://github.com/hashgraph-online/hol-guard/commit/8d96ae755a1d4906394d387cd3af4068c533a848))


### Performance Improvements

* **gauntlet:** build qualification wheels with a fast development profile ([#4252](https://github.com/hashgraph-online/hol-guard/issues/4252)) ([71de248](https://github.com/hashgraph-online/hol-guard/commit/71de2489aead0c75b5c31e09064d64023015eca3))
* **guard:** build the warm MCP tools/call identity in one resident call ([#4247](https://github.com/hashgraph-online/hol-guard/issues/4247)) ([c87c25c](https://github.com/hashgraph-online/hol-guard/commit/c87c25c1af0b35b3cd1dda20c2ee9341413d4552))
* **guard:** cut hook client import closure for codex and bounded bridges ([#4176](https://github.com/hashgraph-online/hol-guard/issues/4176)) ([c191daa](https://github.com/hashgraph-online/hol-guard/commit/c191daafc36d9f3f4aee87a4db54a536719229fb))
* **guard:** decide MCP extension grants in the resident, delete Python hops ([#4171](https://github.com/hashgraph-online/hol-guard/issues/4171)) ([bb3f452](https://github.com/hashgraph-online/hol-guard/commit/bb3f452bb6add4bf98d2744f4b90c6a5f8743eeb))
* **guard:** discover the native runtime once per hook request ([#4224](https://github.com/hashgraph-online/hol-guard/issues/4224)) ([9d38526](https://github.com/hashgraph-online/hol-guard/commit/9d38526b2afa543b7aca7fa371cc83e28f835775))
* **guard:** fuse the MCP tools/call quiet edge, write and response into one resident exchange ([#4206](https://github.com/hashgraph-online/hol-guard/issues/4206)) ([9559124](https://github.com/hashgraph-online/hol-guard/commit/9559124b48b254e5711c1cfc6ed46cc2117d39c1))
* **guard:** give the pi hook hot path latency headroom ([#3990](https://github.com/hashgraph-online/hol-guard/issues/3990)) ([472d54e](https://github.com/hashgraph-online/hol-guard/commit/472d54e61aa8b6b3423d6c6f611a0070af026486))
* **guard:** keep the Claude hook bridge off the daemon manager and adapter imports ([#4136](https://github.com/hashgraph-online/hol-guard/issues/4136)) ([ff5a07c](https://github.com/hashgraph-online/hol-guard/commit/ff5a07c48e3849834cfb67cd5aaed9214754f8b4))
* **guard:** move OCI bundle evidence, verdict and plan digest to the native resident ([#4013](https://github.com/hashgraph-online/hol-guard/issues/4013)) ([4708a70](https://github.com/hashgraph-online/hol-guard/commit/4708a7011bfd02ea61652ca71c206db3bfa68282))
* **guard:** move stdio sensitive-read decisions into the native resident ([#3986](https://github.com/hashgraph-online/hol-guard/issues/3986)) ([4fda2b7](https://github.com/hashgraph-online/hol-guard/commit/4fda2b7b05af968626b374962c2acf3dc41bb61a))
* **guard:** one resident store call for MCP tool-call evidence ([e9814d7](https://github.com/hashgraph-online/hol-guard/commit/e9814d78ea81b24fe0c343b03d7fa5621d9bc452))
* **guard:** read saved MCP tool policy inside the resident decide op ([#4211](https://github.com/hashgraph-online/hol-guard/issues/4211)) ([7b93e73](https://github.com/hashgraph-online/hol-guard/commit/7b93e735c8f07984fddf8954143902374a9d9142))
* **guard:** reuse the verified runtime status when a review needs approval ([#4169](https://github.com/hashgraph-online/hol-guard/issues/4169)) ([da723a4](https://github.com/hashgraph-online/hol-guard/commit/da723a48b221c135cbce3bade1bab3ddb4959044))
* **guard:** skip the unused invocation-preview round trip for command-less hook records ([#4225](https://github.com/hashgraph-online/hol-guard/issues/4225)) ([1b76783](https://github.com/hashgraph-online/hol-guard/commit/1b76783140a37e849645f943984f587acaa52cfa))
* **guard:** speed up cached path re-checks and measure daemon workloads after the client pool warms ([#4222](https://github.com/hashgraph-online/hol-guard/issues/4222)) ([d50c973](https://github.com/hashgraph-online/hol-guard/commit/d50c973ce640ab2fbfbd19c7710f87301b30248c))
* **guard:** validate the native runtime once per hook request ([3547733](https://github.com/hashgraph-online/hol-guard/commit/354773377a2476bdb1b77fba7052b4912ee6325b))
* **release:** compile alpha native binaries in parallel with fast codegen ([#4152](https://github.com/hashgraph-online/hol-guard/issues/4152)) ([f5f4d6d](https://github.com/hashgraph-online/hol-guard/commit/f5f4d6df0f81ab0fb87521e8b2aecc506af20c79))
* **release:** overlap the alpha prerelease with PyPI and compile Windows alpha crates at opt-level 0 ([#4174](https://github.com/hashgraph-online/hol-guard/issues/4174)) ([4470271](https://github.com/hashgraph-online/hol-guard/commit/4470271d2ef55bc072e8473203db6f407304a7bc))

## [3.42.0](https://github.com/hashgraph-online/hol-guard/compare/v3.41.0...v3.42.0) (2026-10-10)


### Features

* **guard:** move policy bundle authority to the native resident ([#3938](https://github.com/hashgraph-online/hol-guard/issues/3938)) ([acc0451](https://github.com/hashgraph-online/hol-guard/commit/acc0451a4e025e65d9f1799a95e83941ced18e5b))
* **guard:** move review event outbox persistence into the native resident ([#3935](https://github.com/hashgraph-online/hol-guard/issues/3935)) ([692072d](https://github.com/hashgraph-online/hol-guard/commit/692072d00ca9b05110a04a084a05677967bd7af3))
* **guard:** parse a bounded PowerShell subset for Windows command controls ([#3948](https://github.com/hashgraph-online/hol-guard/issues/3948)) ([adb624f](https://github.com/hashgraph-online/hol-guard/commit/adb624fea3378bba9e5cdda4b40c73b8a0943285))


### Bug Fixes

* **extensions:** preserve public records and isolate generated outputs ([#3882](https://github.com/hashgraph-online/hol-guard/issues/3882)) ([11f7380](https://github.com/hashgraph-online/hol-guard/commit/11f73801e1582363a3fc2e0b96f7cfde448b528c))
* **guard:** back off Guard Cloud token refresh after any rejected refresh request ([#3944](https://github.com/hashgraph-online/hol-guard/issues/3944)) ([20a475b](https://github.com/hashgraph-online/hol-guard/commit/20a475b30fd81dbd4c12ae0f078461a91fd2cd20))
* **guard:** flag prompts that request secret values, not ones that name them ([#3947](https://github.com/hashgraph-online/hol-guard/issues/3947)) ([5df7c36](https://github.com/hashgraph-online/hol-guard/commit/5df7c36cb4d1ce10544e5985988b601f86e81eaf))
* **guard:** treat a missing Windows state directory as an unprovisioned home ([#3957](https://github.com/hashgraph-online/hol-guard/issues/3957)) ([8fe5569](https://github.com/hashgraph-online/hol-guard/commit/8fe55699c4c0420677cd96ec24c0d880e42c4b4a))


### Performance Improvements

* **ci:** dedupe decision-diff corpus evals and raise eval parallelism ([#3941](https://github.com/hashgraph-online/hol-guard/issues/3941)) ([d9d76ba](https://github.com/hashgraph-online/hol-guard/commit/d9d76ba0b3928552ced5bef36ca14717ea0332ed))
* **ci:** isolate 131s capability-cleanup gate to serial lane ([#3946](https://github.com/hashgraph-online/hol-guard/issues/3946)) ([53eda59](https://github.com/hashgraph-online/hol-guard/commit/53eda59b09a8f7d640a0a94863c7666d2b6592f3))
* **guard:** reuse verified business source and exact-action token in native review ([#3954](https://github.com/hashgraph-online/hol-guard/issues/3954)) ([5d52b80](https://github.com/hashgraph-online/hol-guard/commit/5d52b800a959cc3c1a4436932b8597adfce21d12))
* **guard:** share one store connection across desktop bootstrap ([#3945](https://github.com/hashgraph-online/hol-guard/issues/3945)) ([8b8671c](https://github.com/hashgraph-online/hol-guard/commit/8b8671cc3b179b19d965ce18564230105198a0d9))

## [3.41.0](https://github.com/hashgraph-online/hol-guard/compare/v3.40.0...v3.41.0) (2026-10-10)


### Features

* **guard:** move approval gate decisions into the native resident ([#3927](https://github.com/hashgraph-online/hol-guard/issues/3927)) ([e0acddb](https://github.com/hashgraph-online/hol-guard/commit/e0acddbedc96dd7fbc886e6824476551f2452f08))


### Bug Fixes

* **release:** raise the Windows wheel size budget ([#3937](https://github.com/hashgraph-online/hol-guard/issues/3937)) ([10cd298](https://github.com/hashgraph-online/hol-guard/commit/10cd298e085e9f7b0a99cc812dea7aa2e8e473bc))

## [3.40.0](https://github.com/hashgraph-online/hol-guard/compare/v3.39.0...v3.40.0) (2026-10-10)


### Features

* **ci:** add runtime majority-share report ([#3924](https://github.com/hashgraph-online/hol-guard/issues/3924)) ([4e920f1](https://github.com/hashgraph-online/hol-guard/commit/4e920f1781984e88ee237e7110ffb5d26fdf489c))
* **guard:** build request shell context in the Rust resident ([#3909](https://github.com/hashgraph-online/hol-guard/issues/3909)) ([00a8570](https://github.com/hashgraph-online/hol-guard/commit/00a8570ec2b48775774c5d109211ca0f0b47bed8))
* **guard:** classify detector false positives in the Rust resident ([#3900](https://github.com/hashgraph-online/hol-guard/issues/3900)) ([87654ca](https://github.com/hashgraph-online/hol-guard/commit/87654cab725dcbd8c737c62a95362a2ee80ab0f6))
* **guard:** compose artifact hook decisions in the Rust resident ([#3916](https://github.com/hashgraph-online/hol-guard/issues/3916)) ([702f83a](https://github.com/hashgraph-online/hol-guard/commit/702f83a0d159a6f215c09d917d9b815a4147222d))
* **guard:** compose command effects in the Rust resident ([#3914](https://github.com/hashgraph-online/hol-guard/issues/3914)) ([641bfec](https://github.com/hashgraph-online/hol-guard/commit/641bfecb488e5a82a761799927987d2333db40b2))
* **guard:** decide contributed MCP policy in the Rust resident ([#3913](https://github.com/hashgraph-online/hol-guard/issues/3913)) ([79754cd](https://github.com/hashgraph-online/hol-guard/commit/79754cdcb04a391ffe164d0443d6384b2f90193e))
* **guard:** decide generic hook payloads in the Rust resident ([#3915](https://github.com/hashgraph-online/hol-guard/issues/3915)) ([a3b4f6b](https://github.com/hashgraph-online/hol-guard/commit/a3b4f6b52323432151bec694b510e548cc88385f))
* **guard:** decide MCP proxy routing and package composition in the resident ([#3930](https://github.com/hashgraph-online/hol-guard/issues/3930)) ([0980ca4](https://github.com/hashgraph-online/hol-guard/commit/0980ca455a5cba731df4683e272f259ec0ed25f6))
* **guard:** decide MCP tool-call policy in the Rust resident ([#3912](https://github.com/hashgraph-online/hol-guard/issues/3912)) ([43f343e](https://github.com/hashgraph-online/hol-guard/commit/43f343edee463f84ea6e4cff97971d9fab3718f4))
* **guard:** evaluate package supply-chain requests in the resident ([#3901](https://github.com/hashgraph-online/hol-guard/issues/3901)) ([2fd62a5](https://github.com/hashgraph-online/hol-guard/commit/2fd62a5e4e4bc4f20d1da2471d83aae526fb4668))
* **guard:** inspect compound git commands in the Rust resident ([#3904](https://github.com/hashgraph-online/hol-guard/issues/3904)) ([0732820](https://github.com/hashgraph-online/hol-guard/commit/0732820797c0fb64360b82ad7fbb2ac89b0cbb74))
* **guard:** move guard run authority transforms into the native resident ([#3925](https://github.com/hashgraph-online/hol-guard/issues/3925)) ([2fc5df5](https://github.com/hashgraph-online/hol-guard/commit/2fc5df5f8621c148acd306c67affe90bdd4f8dda))
* **guard:** Rust-owned catalog read model behind authenticated /v2 routes ([#3859](https://github.com/hashgraph-online/hol-guard/issues/3859)) ([8d2387a](https://github.com/hashgraph-online/hol-guard/commit/8d2387a8c57663f21eb85749636d4c9d8b63498e))


### Bug Fixes

* **archive:** bound tar metadata and bind policy passes to the archive digest ([#3905](https://github.com/hashgraph-online/hol-guard/issues/3905)) ([0a3be4d](https://github.com/hashgraph-online/hol-guard/commit/0a3be4d808487175888a2e46904b8cb943891d46))
* **ci:** bind the native source compiler in the scheduling-sensitive lane ([#3931](https://github.com/hashgraph-online/hol-guard/issues/3931)) ([0f6aecf](https://github.com/hashgraph-online/hol-guard/commit/0f6aecfb360a75f31325f97e614a52a9db020819))
* **ci:** raise coverage shard count 192 to 256 ([#3911](https://github.com/hashgraph-online/hol-guard/issues/3911)) ([50c3213](https://github.com/hashgraph-online/hol-guard/commit/50c3213b58f80671b2cba5c937534c48efc6d629))
* **ci:** reduce release API usage and repair Windows compilation ([c412d84](https://github.com/hashgraph-online/hol-guard/commit/c412d841caf0d085943fd3a8ae2cad2a82d63b32))
* **ci:** set native compiler env in serial lane for decision-diff isolation ([#3932](https://github.com/hashgraph-online/hol-guard/issues/3932)) ([c54095b](https://github.com/hashgraph-online/hol-guard/commit/c54095bc3b6a3b2a45280e9eb3b32d7af20d5075))
* **ci:** warm native resident for saved_v1; re-isolate flaky bridge daemon tests ([#3898](https://github.com/hashgraph-online/hol-guard/issues/3898)) ([47ed52c](https://github.com/hashgraph-online/hol-guard/commit/47ed52cb20050406b99aa0a5b1ac6c747b92e685))
* **guard:** evaluate PowerShell type-literal commands instead of blocking them as malformed ([#3918](https://github.com/hashgraph-online/hol-guard/issues/3918)) ([d9e3655](https://github.com/hashgraph-online/hol-guard/commit/d9e36559769d48a3912b63a92f50df635ccff3d0))
* **guard:** retain business-policy sources in the Windows vault ([#3902](https://github.com/hashgraph-online/hol-guard/issues/3902)) ([74ccf04](https://github.com/hashgraph-online/hol-guard/commit/74ccf04b88067892b3194a5efe67004301a3a258))
* **release:** publish provenance for extension snapshots ([7a71222](https://github.com/hashgraph-online/hol-guard/commit/7a712222b1a7f4708218fe1487a430ae1502fb4f))
* **release:** raise native wheel size budgets for 3.40.0 growth ([#3920](https://github.com/hashgraph-online/hol-guard/issues/3920)) ([e95e5c3](https://github.com/hashgraph-online/hol-guard/commit/e95e5c3b1006da23aa8f4539f495978c9ad870f1))
* **release:** restore the uv.lock release-please version marker ([#3929](https://github.com/hashgraph-online/hol-guard/issues/3929)) ([7968561](https://github.com/hashgraph-online/hol-guard/commit/7968561669b88a273f628f7e7fbffd2ba9f585cb))
* **runtime:** keep resident test file under the release approval-file limit ([#3907](https://github.com/hashgraph-online/hol-guard/issues/3907)) ([6615adc](https://github.com/hashgraph-online/hol-guard/commit/6615adc7743d66f971c834a565903439bfd794d9))
* **scanner:** recognize LICENSE.md and standard license filename variants ([#3903](https://github.com/hashgraph-online/hol-guard/issues/3903)) ([48844ab](https://github.com/hashgraph-online/hol-guard/commit/48844ab044558a13c5dded95fd3391fc4b26e197))
* **test:** bind native evidence reports and bound worker memory ([c70865d](https://github.com/hashgraph-online/hol-guard/commit/c70865db8b0d4af8234148cc17ae2b19ef0c65fb))


### Performance Improvements

* **ci:** widen scheduling-sensitive lane to 4 slices ([#3919](https://github.com/hashgraph-online/hol-guard/issues/3919)) ([5612941](https://github.com/hashgraph-online/hol-guard/commit/561294184f8a78bfd5097c873b95ff43e32b1524))

## [3.39.0](https://github.com/hashgraph-online/hol-guard/compare/v3.38.0...v3.39.0) (2026-10-10)


### Features

* **approvals:** recommend extension permission with one-tap always-allow ([#3862](https://github.com/hashgraph-online/hol-guard/issues/3862)) ([34f88d7](https://github.com/hashgraph-online/hol-guard/commit/34f88d7cf9c1e8bbfa11d038cc8e984a9c377d6e))
* **extensions:** add MacScope MCP write-gate protection ([#2673](https://github.com/hashgraph-online/hol-guard/issues/2673)) ([367e521](https://github.com/hashgraph-online/hol-guard/commit/367e52180728b34c49aa9e119a5399299e2f2bba))
* **guard:** add Storage Clearer command extension ([#2706](https://github.com/hashgraph-online/hol-guard/issues/2706)) ([5139b3e](https://github.com/hashgraph-online/hol-guard/commit/5139b3e151d5a1570d94f0dcc339b6d124fdd554))
* **guard:** add where-are-we command-safety extension ([#2832](https://github.com/hashgraph-online/hol-guard/issues/2832)) ([b0c0c00](https://github.com/hashgraph-online/hol-guard/commit/b0c0c004e08d7c42d77e5f45e234c28f532597dc))
* **guard:** analyze shell data flow in the Rust resident ([#3896](https://github.com/hashgraph-online/hol-guard/issues/3896)) ([0ab98bd](https://github.com/hashgraph-online/hol-guard/commit/0ab98bde68a8dc9489056eafbb2e2ff1f3425385))
* **guard:** classify GitHub CLI commands in the Rust resident ([#3893](https://github.com/hashgraph-online/hol-guard/issues/3893)) ([a4f1899](https://github.com/hashgraph-online/hol-guard/commit/a4f1899b1f7abdc3bb465931285890af07a9c26a))
* **guard:** compute skill directory identity and discovery in the Rust resident ([#3885](https://github.com/hashgraph-online/hol-guard/issues/3885)) ([11fdcfa](https://github.com/hashgraph-online/hol-guard/commit/11fdcfada2313809719df1adfbe0630156ce6ac4))
* **guard:** decide approval-proof checks in the Rust resident ([#3891](https://github.com/hashgraph-online/hol-guard/issues/3891)) ([bd31641](https://github.com/hashgraph-online/hol-guard/commit/bd3164138dc79e8a25b196e7c8164ca45e14b878))
* **guard:** derive MCP tool risk and skill firewall evidence in the Rust resident ([#3897](https://github.com/hashgraph-online/hol-guard/issues/3897)) ([af8b56e](https://github.com/hashgraph-online/hol-guard/commit/af8b56e5b2400eabdd729bd92ff9a36ae5c7531d))
* **guard:** move git execution safety checks to the Rust resident ([#3883](https://github.com/hashgraph-online/hol-guard/issues/3883)) ([51a6140](https://github.com/hashgraph-online/hol-guard/commit/51a61408c751571634797422c52f6dda6fd3e019))
* **guard:** move MCP runtime evidence into the native resident ([#3866](https://github.com/hashgraph-online/hol-guard/issues/3866)) ([77a63a4](https://github.com/hashgraph-online/hol-guard/commit/77a63a43c38de0ad8e1e622adc61bbc80361f404))
* **native:** compose package verdict rewrites in the resident ([#3872](https://github.com/hashgraph-online/hol-guard/issues/3872)) ([51a520e](https://github.com/hashgraph-online/hol-guard/commit/51a520e398e7c0b8a18588ca60e4897876101f2c))
* **native:** decide local CLI grants in the resident ([#3860](https://github.com/hashgraph-online/hol-guard/issues/3860)) ([6fece8c](https://github.com/hashgraph-online/hol-guard/commit/6fece8c171b611f31b0b8506e1a7d0b2eff5f82f))
* **native:** decide local MCP server grants in the resident ([#3886](https://github.com/hashgraph-online/hol-guard/issues/3886)) ([e3fe452](https://github.com/hashgraph-online/hol-guard/commit/e3fe4520ea71ac3fb72f7c381ab611853280f830))


### Bug Fixes

* **approvals:** stop promising retries Guard cannot match, and fix review-inbox state bugs ([#3856](https://github.com/hashgraph-online/hol-guard/issues/3856)) ([2bba669](https://github.com/hashgraph-online/hol-guard/commit/2bba6692fa7b199c7f033fa0522aeb90ae0ffd4b))
* **ci:** rebalance coverage to 192 shards ([#3863](https://github.com/hashgraph-online/hol-guard/issues/3863)) ([4b2b438](https://github.com/hashgraph-online/hol-guard/commit/4b2b438e6b7282e00fb7104b53db9930f939ba36))
* **daemon:** share one auth token across daemons for a guard home ([#3864](https://github.com/hashgraph-online/hol-guard/issues/3864)) ([3d833f1](https://github.com/hashgraph-online/hol-guard/commit/3d833f1ead3193f5604e6675eec313380c93c00c))
* **gauntlet:** read Windows workspace paths in the harness judge ([#3895](https://github.com/hashgraph-online/hol-guard/issues/3895)) ([d12a024](https://github.com/hashgraph-online/hol-guard/commit/d12a02408b72727bd59532dae367f3ab7bf60dd5))
* **gauntlet:** seed Cursor's Windows login and match the omp business setup in the harness lane ([#3873](https://github.com/hashgraph-online/hol-guard/issues/3873)) ([ccc302d](https://github.com/hashgraph-online/hol-guard/commit/ccc302d327ab8ff16062a1612a72940209a71603))
* **gauntlet:** stop the Watch case from asking the model to type generated fixture paths ([#3870](https://github.com/hashgraph-online/hol-guard/issues/3870)) ([36de3c8](https://github.com/hashgraph-online/hol-guard/commit/36de3c8b54ae6c092cad8218e19e935134ca7db8))
* **guard:** check Cursor daemon liveness without a console signal on Windows ([#3888](https://github.com/hashgraph-online/hol-guard/issues/3888)) ([c4d2218](https://github.com/hashgraph-online/hol-guard/commit/c4d221853d9a2efd6f1db5c4b42d1d2081d3f71b))
* **guard:** give business policy installs a budget that fits slow process start ([#3887](https://github.com/hashgraph-online/hol-guard/issues/3887)) ([f588ca6](https://github.com/hashgraph-online/hol-guard/commit/f588ca6feaad8995170e19f5a5ae11fc6861f2e6))
* **guard:** give business-policy native calls a Windows-sized deadline ([#3880](https://github.com/hashgraph-online/hol-guard/issues/3880)) ([67992cf](https://github.com/hashgraph-online/hol-guard/commit/67992cf71cb8202025ff4ad8af77cc7bb46001b8))
* **guard:** keep an empty GIT_PAGER in the hook environment so git reads are not paused for review ([#3869](https://github.com/hashgraph-online/hol-guard/issues/3869)) ([eee4c85](https://github.com/hashgraph-online/hol-guard/commit/eee4c852e30334b8a6f645cecdbc1c34372ef086))
* **guard:** make Cursor hooks work on Windows ([#3881](https://github.com/hashgraph-online/hol-guard/issues/3881)) ([8ad612c](https://github.com/hashgraph-online/hol-guard/commit/8ad612ca070d4550227f52009aac87f13ba7571c))
* **guard:** model plain PowerShell Get-Content reads on Windows ([#3867](https://github.com/hashgraph-online/hol-guard/issues/3867)) ([93af8ce](https://github.com/hashgraph-online/hol-guard/commit/93af8ce55da579c596f67c69458d8023e56f956c))
* **guard:** resolve npx and local bin shims on Windows so Always is offered ([#3858](https://github.com/hashgraph-online/hol-guard/issues/3858)) ([0629982](https://github.com/hashgraph-online/hol-guard/commit/0629982bb34a4e9e07ec9a8c9d6770089b19a0cd))
* **guard:** restore extension controls when guard.db is re-created ([#3868](https://github.com/hashgraph-online/hol-guard/issues/3868)) ([6e19246](https://github.com/hashgraph-online/hol-guard/commit/6e19246f6d11510d163abf48470bc32e5484b830))
* **guard:** send the Cursor agent's environment with daemon hook requests ([#3894](https://github.com/hashgraph-online/hol-guard/issues/3894)) ([490437e](https://github.com/hashgraph-online/hol-guard/commit/490437ea737e3067bc473157a9f814a7e1a32cad))
* **guard:** split catalog byte budgets per representation ([#3854](https://github.com/hashgraph-online/hol-guard/issues/3854)) ([7059236](https://github.com/hashgraph-online/hol-guard/commit/705923623491869b3f45dd906e639a6d768f09cf))
* **guard:** stop catalog flip-flop revisions and roll back abandoned control changes ([#3871](https://github.com/hashgraph-online/hol-guard/issues/3871)) ([b9b9996](https://github.com/hashgraph-online/hol-guard/commit/b9b9996ef5a729de3de9820538d811ac9671fdc3))
* **release:** republish a repaired release's exact attested wheels to PyPI ([#3877](https://github.com/hashgraph-online/hol-guard/issues/3877)) ([b608511](https://github.com/hashgraph-online/hol-guard/commit/b608511125fc8f4655d4c1cb760c6b2a4be34a23))
* **store:** record page-1 evidence for corrupt stores and refuse to swap a database under a live WAL ([#3874](https://github.com/hashgraph-online/hol-guard/issues/3874)) ([f855c02](https://github.com/hashgraph-online/hol-guard/commit/f855c0236b3b50df469c2df3569f160991b2d273))


### Performance Improvements

* **ci:** return daemon hook-bridge tests to coverage shards ([#3890](https://github.com/hashgraph-online/hol-guard/issues/3890)) ([73fb59d](https://github.com/hashgraph-online/hol-guard/commit/73fb59d77f1a38835545ba5cdc3b31d258ad6ec1))
* **gauntlet:** qualify candidates with one cached command and far fewer reruns ([#3884](https://github.com/hashgraph-online/hol-guard/issues/3884)) ([550fec7](https://github.com/hashgraph-online/hol-guard/commit/550fec72ac15682b92700d22f5d78d35caf94ee6))
* **gauntlet:** run the Luna lane on gpt-6-luna with Oh My Pi 18.4.12 ([5d0f7d6](https://github.com/hashgraph-online/hol-guard/commit/5d0f7d63d4c8aae49095f97f577502fcef2d8400))

## [3.38.0](https://github.com/hashgraph-online/hol-guard/compare/v3.37.0...v3.38.0) (2026-10-09)


### Features

* **native:** derive local CLI grant identity in the resident ([#3842](https://github.com/hashgraph-online/hol-guard/issues/3842)) ([8b5ff88](https://github.com/hashgraph-online/hol-guard/commit/8b5ff88861f4857d7738a8bacc2957646147a921))


### Bug Fixes

* **ci:** isolate Win32-descriptor test that poisons process-global os.lstat ([#3848](https://github.com/hashgraph-online/hol-guard/issues/3848)) ([5a092b6](https://github.com/hashgraph-online/hol-guard/commit/5a092b6a3ad80b5b7a4af23899dd61ecdfe0aff1))
* **ci:** let xdist restart a crashed worker and bound corpus workers higher ([#3839](https://github.com/hashgraph-online/hol-guard/issues/3839)) ([f6e71e1](https://github.com/hashgraph-online/hol-guard/commit/f6e71e1275bc9f5ca341131a65ce0b72c9cb524c))
* **ci:** queue main runs instead of cancelling in-flight ([#3852](https://github.com/hashgraph-online/hol-guard/issues/3852)) ([f4f993d](https://github.com/hashgraph-online/hol-guard/commit/f4f993dd367f64925aa9b17b08b0dfc1f525f754))
* **codex:** stop Desktop installs from blocking plain Git reads and cd ([#3847](https://github.com/hashgraph-online/hol-guard/issues/3847)) ([d4e8b69](https://github.com/hashgraph-online/hol-guard/commit/d4e8b697957cc4ff6a6f0f0ded99c486f0524b87))
* **custom-extensions:** let detected connections be forgotten and age out unused ones ([#3828](https://github.com/hashgraph-online/hol-guard/issues/3828)) ([0a18798](https://github.com/hashgraph-online/hol-guard/commit/0a187983c2a1860fa05f17836be732acb0dfbe17))
* **daemon:** keep the daemon up while a request outlives the idle window ([#3845](https://github.com/hashgraph-online/hol-guard/issues/3845)) ([985e281](https://github.com/hashgraph-online/hol-guard/commit/985e28150ba5ae43c53b2076503606c70b8ab80b))
* **doctor:** warn when Codex skips untrusted Guard hooks or OMP code mode routes tools through eval ([#3843](https://github.com/hashgraph-online/hol-guard/issues/3843)) ([b8c52ee](https://github.com/hashgraph-online/hol-guard/commit/b8c52ee19bc956cc6cc1070f83c8ed76fbd11f47))
* **gauntlet:** accept Guard's observe-only answer to harness lifecycle hooks ([#3833](https://github.com/hashgraph-online/hol-guard/issues/3833)) ([99a6a82](https://github.com/hashgraph-online/hol-guard/commit/99a6a820bc79856959a4039e32dfe23454a644ce))
* **gauntlet:** keep Codex harness cases on the fixture's Codex home ([#3831](https://github.com/hashgraph-online/hol-guard/issues/3831)) ([b81d2c2](https://github.com/hashgraph-online/hol-guard/commit/b81d2c21596a19a2d9f60eabb328c92e78399ff4))
* **guard:** launch Codex hooks on Windows ([#3846](https://github.com/hashgraph-online/hol-guard/issues/3846)) ([60c6253](https://github.com/hashgraph-online/hol-guard/commit/60c6253533264731863fc3c6cecb6dc0f57c352a))
* **runtime:** refuse resident operations for another Guard home ([#3832](https://github.com/hashgraph-online/hol-guard/issues/3832)) ([7d3390d](https://github.com/hashgraph-online/hol-guard/commit/7d3390dcdad57e4c89375c6d7ce77bf3bf05c7e1))
* **sonar:** suppress S5856 false positive on fancy_regex lookbehind ([#3857](https://github.com/hashgraph-online/hol-guard/issues/3857)) ([9ed431e](https://github.com/hashgraph-online/hol-guard/commit/9ed431e3eb855fd9c74c7d35cc80b9571a07d130))

## [3.37.0](https://github.com/hashgraph-online/hol-guard/compare/v3.36.1...v3.37.0) (2026-10-09)


### Features

* **business:** classify business operations and add Drive export ([#3798](https://github.com/hashgraph-online/hol-guard/issues/3798)) ([9cc3b01](https://github.com/hashgraph-online/hol-guard/commit/9cc3b0152a4b3b62501df5121a4070d72e619c44))
* **extension:** add Formicx agent command safety extension ([#2914](https://github.com/hashgraph-online/hol-guard/issues/2914)) ([890037b](https://github.com/hashgraph-online/hol-guard/commit/890037b32b3aa4992c210d7ad567618c1deebd26))
* **extensions:** add mcp-mail-server publisher listing ([#3805](https://github.com/hashgraph-online/hol-guard/issues/3805)) ([4736564](https://github.com/hashgraph-online/hol-guard/commit/4736564cf782ae5c70f2ac9275742a3c97655b1d))
* **extensions:** add pyrig command protection ([#3674](https://github.com/hashgraph-online/hol-guard/issues/3674)) ([2431b20](https://github.com/hashgraph-online/hol-guard/commit/2431b20d8f3887395a114a7cf795b99dc1b378d8))
* **extensions:** require review for mcp-mail-server deletion ([#3278](https://github.com/hashgraph-online/hol-guard/issues/3278)) ([526d5b7](https://github.com/hashgraph-online/hol-guard/commit/526d5b79e67c9fc0b78411da558dfb28e4054623))
* **gauntlet:** run the catalog through Claude Code, Codex and Cursor ([#3818](https://github.com/hashgraph-online/hol-guard/issues/3818)) ([dba20ac](https://github.com/hashgraph-online/hol-guard/commit/dba20acc9aa9696a59acc812fbcf878ea14aaf1e))
* **guard:** add agi-memory command safety extension ([#2921](https://github.com/hashgraph-online/hol-guard/issues/2921)) ([10b0c36](https://github.com/hashgraph-online/hol-guard/commit/10b0c36bcb614fb28a7d00c724f0c651c839c10d))
* **guard:** add rungs command classification extension ([#2818](https://github.com/hashgraph-online/hol-guard/issues/2818)) ([1493513](https://github.com/hashgraph-online/hol-guard/commit/14935137911b54033590a49fa62f0dc17d452ff1))
* **guard:** detect package-runner CLIs such as npx wrangler ([#3792](https://github.com/hashgraph-online/hol-guard/issues/3792)) ([d5b645c](https://github.com/hashgraph-online/hol-guard/commit/d5b645ca58cd93550eafe699ea089887bb2922e1))
* **guard:** list detected CLIs and add a Cloudflare Wrangler profile ([#3795](https://github.com/hashgraph-online/hol-guard/issues/3795)) ([e1627da](https://github.com/hashgraph-online/hol-guard/commit/e1627daa9711e155296ba482daab5b1b09c55f05))
* **guard:** review Dispat release starts with an opt-in extension ([#2813](https://github.com/hashgraph-online/hol-guard/issues/2813)) ([de01030](https://github.com/hashgraph-online/hol-guard/commit/de01030a831a13c6cc60fa4b7acd6f28feeb282b))


### Bug Fixes

* **codex:** read app inventory from native daemons and bound tool summaries ([9ed4ba2](https://github.com/hashgraph-online/hol-guard/commit/9ed4ba2fbb5cc65ce09e800d6d93cd9617892bbc))
* **codex:** stop holding ordinary Codex Git reads and skill reads, and explain authority repair ([#3808](https://github.com/hashgraph-online/hol-guard/issues/3808)) ([e01a885](https://github.com/hashgraph-online/hol-guard/commit/e01a885efd7fa5c2775a2f3cd8c60895726df019))
* **contracts:** raise managed-controls catalog payload cap to 8MB ([#3816](https://github.com/hashgraph-online/hol-guard/issues/3816)) ([2eba910](https://github.com/hashgraph-online/hol-guard/commit/2eba910efced8e1c4fcccfb0836c11aadfe31f73))
* **daemon:** read camelCase toolInput from ZCode, Devin and Grok hooks ([#3820](https://github.com/hashgraph-online/hol-guard/issues/3820)) ([8e071fe](https://github.com/hashgraph-online/hol-guard/commit/8e071fea40431d98b7fe5857afa6e9f63011b2fd))
* **daemon:** retire a superseded same-install daemon after a native-only upgrade ([#3815](https://github.com/hashgraph-online/hol-guard/issues/3815)) ([4b48d35](https://github.com/hashgraph-online/hol-guard/commit/4b48d35875d891773a366fb30b75ecf5ebe15946))
* **dashboard:** keep extension inventory rendering when a launch kind is unknown ([#3811](https://github.com/hashgraph-online/hol-guard/issues/3811)) ([6c227f5](https://github.com/hashgraph-online/hol-guard/commit/6c227f5e1a9389b477501b21a6f32b0cf9190afb))
* **guard:** let routine Codex apply_patch edits pass native review ([#3821](https://github.com/hashgraph-online/hol-guard/issues/3821)) ([9b23c49](https://github.com/hashgraph-online/hol-guard/commit/9b23c4980554ca7da24bde123b59076da9739872))
* **guard:** load Cursor hooks by replacing unsupported beforeWriteFile ([#3825](https://github.com/hashgraph-online/hol-guard/issues/3825)) ([e80f605](https://github.com/hashgraph-online/hol-guard/commit/e80f6051806787ea89e3fd646a185d5da471a181))
* **guard:** recognize npx wrangler as a CLI and parse yargs help rows ([#3809](https://github.com/hashgraph-online/hol-guard/issues/3809)) ([f58b83e](https://github.com/hashgraph-online/hol-guard/commit/f58b83e8250b275c64a42c8f8e334e1a07379ce1))
* **guard:** repair extension-control catalog bound and error type ([#3817](https://github.com/hashgraph-online/hol-guard/issues/3817)) ([d8c0cda](https://github.com/hashgraph-online/hol-guard/commit/d8c0cda4a33237c16cf99faffe97a09b3e42254f))
* **package-shims:** judge the dashboard intercept test by shell-profile PATH ([#3827](https://github.com/hashgraph-online/hol-guard/issues/3827)) ([01f73f8](https://github.com/hashgraph-online/hol-guard/commit/01f73f8f3f2011b27b2ad33e73b15546063c4784))
* **runtime:** name the business context floor for shell-wrapped Workspace CLIs ([#3826](https://github.com/hashgraph-online/hol-guard/issues/3826)) ([329a7ea](https://github.com/hashgraph-online/hol-guard/commit/329a7ea63fb1e9ee8e38361b176d890c1558a560))
* **runtime:** recover a stale resident-update marker and report the real native failure ([#3812](https://github.com/hashgraph-online/hol-guard/issues/3812)) ([d7bfce7](https://github.com/hashgraph-online/hol-guard/commit/d7bfce750159df25a0f1de72f5bbcb4c2fb12bea))
* **runtime:** refuse multi-record business dispatch ([#3800](https://github.com/hashgraph-online/hol-guard/issues/3800)) ([77e849e](https://github.com/hashgraph-online/hol-guard/commit/77e849eef8cb5eb236f0578097ff0849e35d271c))
* **runtime:** require business context for local, Windows and launcher Google CLIs ([#3799](https://github.com/hashgraph-online/hol-guard/issues/3799)) ([94661ea](https://github.com/hashgraph-online/hol-guard/commit/94661ead768daa952ffd018bbe3da583c4b64018))
* **runtime:** retire the managed resident when its Guard home is deleted ([#3822](https://github.com/hashgraph-online/hol-guard/issues/3822)) ([d5cec22](https://github.com/hashgraph-online/hol-guard/commit/d5cec22eeddd6014a2df8ccc40eca1789aac994c))
* **supply-chain:** restore paid first-time protection without approval loops ([#3814](https://github.com/hashgraph-online/hol-guard/issues/3814)) ([29d9e6b](https://github.com/hashgraph-online/hol-guard/commit/29d9e6b985e8ad582a03764e04796e7085e9e535))
* **sync:** scrub CLI credential arguments from synced receipt commands ([#3824](https://github.com/hashgraph-online/hol-guard/issues/3824)) ([fe371f4](https://github.com/hashgraph-online/hol-guard/commit/fe371f48c3499c9d919a1a594b5b04ffa957d0bb))
* **uninstall:** rewrite group-writable user files and run self-uninstall from the desktop core ([#3813](https://github.com/hashgraph-online/hol-guard/issues/3813)) ([253cb46](https://github.com/hashgraph-online/hol-guard/commit/253cb4603e6bfa6bc968ffb409771e60586ce46b))


### Documentation

* **guard:** list business app compatibility by command and mode ([#3803](https://github.com/hashgraph-online/hol-guard/issues/3803)) ([3f37b9f](https://github.com/hashgraph-online/hol-guard/commit/3f37b9fed54da6d19ff9ed2c96c69344f7c072f0))

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
