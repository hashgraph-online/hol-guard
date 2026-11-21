# Declarative command extension authoring

Status: migration candidate. Canonical sources, generated catalog readers and builder writers have switched to the native compiler. Installed qualification, review and release gates remain required before delivery.

## Baseline and ownership

At `a9ede76dfbc17ca54bc568a352f06e4add41d701`, the native artifact contains 71 extensions, 234 rules, 248 permissions and 42 compatibility rules. These are inventory observations, not permanent acceptance constants. The unchanged focused suites pass (53 Python tests; 68 Rust tests with two ignored). A native macOS ARM64 wheel built with Rust 1.88.0 passed the installed extension probe: 22 cases, 22 persisted receipts, authenticated control changes, restart and marker-tamper rejection. Other platforms and interactive enrollment are not established by that proof.

Command extensions will have one canonical versioned JSON source per extension under `contributions/command-sources/`. Source owns descriptive metadata, stable extension/rule/permission/variant IDs, relationships and typed predicates. The trust-class map remains independent reviewed policy. Existing MCP contribution JSON remains canonical. Descriptors and public catalog metadata are generated projections, not independently editable inputs.

External publisher attribution, icons, homepage and license belong to the canonical source. Publisher attribution grants no trust or activation. First-party and trusted-library publishers remain derived from the separately reviewed trust map; sources cannot override those publishers or claim their reserved identities. The generated public catalog retains its existing metadata wire shape, while the generated contribution descriptor uses v2.

The source compiler belongs in guard-command. It lowers trees into the existing content-addressed native graph and calls existing node validation and program admission. It does not evaluate shell text or define another matcher implementation. Candidate indexes, hashes and coverage records are compiler output. No callbacks, includes, imports, author-selected native function names or contributor-provided optimization hints are accepted.

## Validation ownership

| Input | Authoritative validation |
| --- | --- |
| JSON bytes, duplicate keys, depth and total work | Bounded Rust source decoder before generic JSON conversion |
| Schema version and exact object fields | Rust source records; editor schema generated from the same field contract |
| IDs, versions, metadata and paths | Source semantic validators; retain namespace, URL, privacy and relative-path restrictions |
| Rule/permission/variant ownership | Catalog validator and native program admission; each rule belongs to exactly one permission |
| Dependencies, aliases, conflicts and implied permissions | Catalog relationship validator; dangling IDs and cycles rejected |
| Operation configuration | Existing typed native matcher validators; no separate Python interpretation |
| Graph hashes, references and depth | Compiler lowering and existing native graph validation |
| Compatibility capabilities | Closed native table bound to extension, rule, permission and executable applicability |
| Trust and activation | Existing separately reviewed trust map and authenticated control machinery |

Preserve current limits: program 4 MiB, catalog projection 1,000,000 bytes, 512 extensions, 512 permissions per extension, 1,024 rules, 16,384 nodes, matcher depth 32, 4,096 config items/string bytes, 64 variants per rule. JSON syntax nesting and total traversal work are separately bounded. The seven native common-CLI operations absent from the Python exporter must remain available through their existing Rust validators.

Every compatibility rule receives an explicit versioned closed capability, preserving its existing classifier, owning segments and uncertainty. Unknown or mismatched capabilities are rejected. Native permission-only attribution and independent intrinsic protections remain intact. A missing matcher is never lowered to an always/never-match placeholder.

## Authority and compatibility

Today the program digest covers the Python authoring fingerprint, catalog, trust, graph and coverage. Packaged-byte validation feeds program/catalog/trust into authenticated control bindings; native controls compare them against the resident's embedded program. Policy generation and resident acknowledgement bind effective control state. Decision receipts and approvals bind request, policy generation/digest and runtime identity. Runtime identity is the native binary SHA-256, independently checked against the packaged manifest and source identity.

The new compiler must replace Python source hashing with a domain-separated native implementation/operation-contract fingerprint plus source identity. Hash configuration and native semantics separately. Include relevant parser, matching, compatibility, Unicode and option-contract code and dependency lock identity. The existing guard-rules digest hashes a fixed string and is not sufficient as the implementation fingerprint. Never fabricate old hashes or reset saved controls to retain approvals.

Keep the existing Unicode tables and semantic profile while preserving behavior. Source format and implementation changes may legitimately change artifact identities; stable control target IDs remain unchanged. Test remembered-approval invalidation and authenticated state upgrades rather than assuming identical IDs imply identical authority.

| Input | Existing reader | Additive reader | Migrated reader |
| --- | --- | --- | --- |
| Existing v1 native program | Supported | Supported | Retain during supported rollback window |
| New JSON source | Unsupported | Build-time only | Build-time only |
| Existing Python kit | Existing workflow | Existing workflow during transition | Explicit offline conversion or diagnostic; no execution fallback |
| Descriptor v2 | Reject | Validate before writer switch | Default |
| Unsupported wire/profile | Reject before activation | Reject before activation | Reject before activation |

Invalid candidate artifacts preserve the previous verified installation. Tampered active authority keeps existing restrictive recovery. Never reinterpret enrolled machines as never-enrolled or reuse approvals across different semantic authority.

Native pre-tool classification and authenticated policy resolution are separate stages. An enabled permission may authorize a command classified for review; the diagnostic bridge retains the native classification separately and cannot relax a native hard block. It accepts only request-bound native observations and the matching protected control snapshot. Actual execution still requires the authoritative native pre-execution decision and receipt.

An uncertain native command model remains uncertain, with its native reason and empty segment evidence. Python must not parse or unwrap it to invent observations. If the native evaluator reports an evaluation error, inspection reports native evidence unavailable and does not manufacture an allow decision. The candidate preserves the bounded routine support introduced in upstream commit `5a076ded9182f4466b875effffae3b156fba9e04`: literal `2>&1` stderr duplication and the exact `cd ... && find src -name '*.py' -exec python -m py_compile {} +` form. The [native corpus contract](native-command-corpus-contract.md) records those supported forms separately from inherited limitations. Other unsupported redirects, substitutions, compound forms and transparent wrappers retain their native uncertainty; the authoring migration does not add general parser grammar support.

## Transition and retirement

Ship additive compiler support first. Prove one data-only synthetic contribution through native evaluation, then migrate every catalog item and compare baseline/candidate native outcomes and evidence. Preserve package/MCP delegation. Switch builder generation, validation, diff/apply, catalog consumers and packaging only after those gates pass.

Production catalog callers include command inspection, control projection, CLI inspection, daemon dashboard APIs, managed-policy delivery, MCP grants, store manifests and catalog sync. Packaging includes pyproject force-includes and frozen artifact staging. They must consume generated metadata/native interfaces without constructing Python matchers. Preserve builder review binding, deterministic plans, managed-file ownership, conflict detection and ordinary-write rollback.

The baseline exporter belongs only in isolated migration tooling; it must never execute PR code or become a release dependency. Backlog classification is structural, pinned to heads, and not a parity claim. Every relevant PR still needs a verified patch or a precise native-contract blocker. Remove legacy production matching and semantic hashing after consumers switch, with architecture tests preventing reintroduction.

Completion requires complete catalog/settings reconciliation, independent adversarial native parity, four-platform installed qualification, unchanged SLO/soak gates, normal review and release verification. The additive compiler alone does not complete the migration.

## Qualification contracts

Keep CLI launchers, daemon residents, and Desktop Core as distinct installation identities. A CLI version is not evidence of the resident or Desktop binary. The baseline proof identifies only its isolated installed wheel/resident; it neither updates nor attests the live Desktop installation.

The existing installed SLO runner uses `scripts/native_slo_contract.py` and `scripts/native_slo_reporting.py`: resident share at least 99%, zero safe-corpus failures and Python fallback decisions, installed adapter latency bounded by the production hook budget, cold p95 at most 150 ms, readiness p95 at most 400 ms, RSS growth at most 12%, and bounded 16/64-client concurrency with zero transport errors. Direct-native ceilings remain distinct: 20/50/120/350 ms for the four size classes and concurrent p99 100 ms. The workflow's soak requires 100,000 requests and 250,000 receipts, at most 128 threads and 512 descriptors, RSS growth at most 50%, and the existing bounded health-failure criterion. These gates are unchanged; baseline extension-probe success does not assert SLO or soak success.

Evidence records carry a schema version, exact source/artifact identities, explicit `passed`, `failed`, `blocked`, or `not-evaluated` status, and limitations. Baseline inventory owns complete extension/rule/permission/variant/delegate records and compatibility mappings. Backlog inventory owns repository/PR/base/head/blob identities, classification, conversion status and blockers. Migration reports own old/new IDs and digests, generated paths, unsupported records and intentional dispositions. Parity reports own baseline/candidate program identities, independent case IDs, decision/evidence/segment differences and dispositions. Installed reports own platform, wheel hash/version/source, installed module and resident identity, receipt/control-generation results and cleanup. Release reports own merged/published source identities, artifact hashes, signing results and actual invoked launcher follow-up. An absent platform or test remains `not-evaluated`.

Rollback qualification must cover an older supported reader rejecting an unsupported source/descriptor without changing its active verified program, an invalid candidate retaining the previous verified installation, and an authenticated upgrade preserving control target IDs while invalidating approvals bound to changed authority. No rollback test may clear enrollment or replace current authority with synthetic production credentials.
