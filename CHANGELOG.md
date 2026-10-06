# Changelog

All notable changes to HOL Guard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Older releases are preserved in the [changelog archive](docs/changelog-archive.md).

## Unreleased

### Features
* **policy:** the saved-package-approval claim now resolves inside the resident. The `apply_stored_package_policy` operation ships the evaluation, artifact and store path to `evaluate_apply_stored_package_policy`, which reuses the ported `resolve_stored_package_policy_override` and returns the evaluation unchanged when the store holds no usable saved approval. The previous `commands_hook_native_eval` bridge re-entered the Python override; it now routes through `apply_stored_package_policy_native` and, on transport failure, returns the evaluation unchanged — the resident's own no-saved-approval terminal — rather than re-running the Python override.

* **sync:** the resident reads OAuth credentials through the scoped secret authority. The `oauth_local_credentials` payload holds metadata only (`credentials_ref` + `credentials_sha256`), so the secret behind that ref is now resolved and verified before a sync starts — against the same fingerprints the Python store writes (scrypt, plus the legacy `pbkdf2-sha256$` and bare sha256 forms), implemented in Rust so the resident can reproduce them byte-for-byte. A record whose secret no longer matches its fingerprint now reads as `degraded` instead of being trusted, and a normally-provisioned store — which never inlines secret material — can start native sync.
* **mcp:** proxy the MCP server transport through a persistent native session when the resident advertises `mcp-stdio-session-v1`. The resident spawns the scrubbed child, owns newline JSON-RPC framing and cross-correlation, and tears down the process group; Python keeps the client stream and `tools/call` verdict authority. A reachable resident that fails to open a session is terminal — Python never substitutes its own subprocess.
* **policy:** native policy-decision lookup owns the complete guard store read in Rust, including once-only approvals, authority-kind claims, and one-shot remote consumption; unavailable native authority stops the lookup rather than falling back to Python selection.
* **mcp:** the resident owns the tools/list boundary — `_canonical_tool_catalog_entry`, `_normalized_tools_catalog_page`, and `_tool_catalog_fingerprint` delegate to the new `mcp_tool_catalog_fingerprint` context-digest kind. Rust canonicalizes each advertised entry (name-strip, `input_schema`→`inputSchema`, `output_schema`→`outputSchema`), rejects malformed pages (non-dict item, blank/non-trimmed/duplicate name, unserializable payload), and emits the sha256 fingerprint over `{state, tools(sorted), version}`. `validate_context_tokens` now treats byte-identical opaque tokens — including the `guard-context-unbound:*` sentinel — as unchanged instead of `approval_reuse_content_changed`.
* **mcp:** the resident owns MCP call-argument display safety — `_safe_mcp_arguments`/`_safe_mcp_params`/`_mcp_arguments_digest`/`_launch_target` and the stdio `_redact_json` traffic recorder delegate to `mcp_arguments_projection`/`mcp_redact_json` context-digest ops; Python keeps no fallback masking path.
* **sync:** port the Guard-Cloud sync transport into the resident — OAuth credential read, ES256 DPoP proof signing (ring PKCS#8→r||s JWT), issuer/sync-endpoint origin allowlisting, and the bounded `ureq` retry state machine (DPoP nonce fast-path, 429 waits, gateway retries, one longer-timeout retry). `GuardSyncRequest` carries the `retry_context` side-channel so nonce/timeout retries re-sign proofs without re-reading credentials. Token refresh and bundle-sync orchestration remain Python-owned until the secret-store write path is ported; an expired cached token resolves to the authorization-expired `ask` rather than a silent local-only downgrade, and `supply-chain-cloud-transport-v1` is not yet advertised so production evaluation keeps routing through the Python refresh path.

### Bug Fixes

* **native:** the context-digest transport now establishes the resident's on-disk prerequisite (the owner-private `policy-verifier.key` under `<guard-home>/native-runtime/`) before shipping a request, the way every native launch/session caller already did. Launch and executable identities became resident-owned, so a guard home that had never been provisioned — a fresh deployment, or a test home carrying a seeded key — failed closed on `native_runtime_launch_identity_unavailable`, `native_mcp_launch_environment_unavailable`, and `native_package_context_digest_unavailable`. An existing key file is accepted as satisfied without opening a store; only a missing key is provisioned, once per home per process.
* **native:** a digest request that arrives while the pool has no parked resident client is granted a cold-start allowance on top of the steady-state budget. The pooled resident is spawned lazily, and a contended runner can spend several hundred milliseconds faulting a 20 MB binary in before it answers; charging that startup to the 500 ms degradation budget made launch-identity and package-context callers — which have no fallback — fail closed on a resident that was merely still starting, or one that a killed process had taken with it. The allowance tracks the pool instead of remembering past answers, so it is granted again whenever the resident has to be spawned (fresh process, retired client, killed resident) and never in steady state.
* **native:** the `*_unavailable` errors the context-digest wrappers raise now carry the transport's reason (`native_context_digest_unsupported`, `..._prerequisite_unavailable`, `..._request_too_large`, `..._result_invalid`, `native_overloaded`, or the resident client's own code such as `native_client_timed_out`). A bare "unavailable" could not distinguish a missing runtime from an unprovisionable guard home, an oversized request, a slow spawn, or a malformed answer.
* **native:** a context-digest request whose deadline ran out — the client's `native_client_timed_out` or the resident's own `native_client_deadline_exceeded` — is retried once with twice the cold-start allowance. The pooled resident serves one request at a time, so a sibling's long RPC could consume the steady-state budget and fail a request that was neither slow nor dead, and the resident's own bound (which the request carries) must not make the retry hopeless. Only a request that has already failed pays for the retry; every other failure still fails after a single attempt, and the reason names the transport, the attempt count and the budget that actually failed.
* **native:** a package-intent parse now sends the caller's `PATH` to the resident. The resident is long-lived, so its own `PATH` is the one it was spawned with; a manager it cannot resolve (`npx` from a test or tool directory) made the TypeScript launch evidence incomplete and sent a contained typecheck back to review even though the caller resolved the manager fine.
* **native:** a resident that answers a context-digest request with its own error envelope is now reported by that code — and recorded against the resilience breaker — instead of being flattened into `native_context_digest_result_invalid`. An envelope outside the contract keeps its code in the rejection reason, and a rejected result names the contract clause that rejected it with the offending keys, so a foreign frame, a stale frame and a truncated read are no longer indistinguishable.

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
