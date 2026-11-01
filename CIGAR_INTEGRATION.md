# CIGAR 0.14.1 integration analysis

Use CIGAR to add **Context assistance** to HOL Guard: reusable, scoped evidence for clearer reviews, better agent guidance, and traceable explanations. Make it optional and off by default. Keep Guard's Rust runtime responsible for decisions and approval enforcement, and run CIGAR through a persistent, verified CPython 3.14 bridge outside the synchronous hook path.

The branch implements native configuration/runtime verification, bounded SDK transport, protected source admission, authenticated controls and React screens, scoped MCP sharing, private persistence and native execution association. The authorized local P0–P5 scope is now [accepted on macOS arm64](docs/guard/cigar-integration/ACCEPTANCE.md) at product source `ed5011ac`: matching source/backend/browser/frozen checks, complete off/on SLO and the original fixed relative cohort pass. The [execution log](docs/guard/cigar-integration/EXECUTION_LOG.md) retains the earlier failures and their exact artifact boundaries. External Desktop/application/platform/public-release and model/human outcome limits remain explicit. No exponential efficiency gain is established.

## Baseline

| Item | Inspected baseline |
| --- | --- |
| HOL Guard | v3.55.1, commit `35180b995cb27fdc9f92e1f68307a756c785f154` |
| Upstream | [hashgraph-online/hol-guard](https://github.com/hashgraph-online/hol-guard/releases/tag/v3.55.1) |
| Local branch | `feature/integrate-cigar-0.14.1` |
| CIGAR | Local 0.14.1 security candidate, commit `b47380e5a5cbeaaad5a61cab3372e9e67368732f` |
| Analysis date | 2026-10-22 |

The checkout was copied independently from an existing local repository because direct GitHub cloning was unavailable in the sandbox. Its starting commit matches the public release, and `origin` points to the public HOL Guard repository. The leading slash in the requested branch name was omitted because Git does not permit it.

## Recommended product decisions

1. Put **Context assistance (CIGAR)** in Settings → Protection. Show a small status entry on Home, scoped controls in Apps, additional context inside existing reviews, and source references inside Evidence. Keep the current navigation structure.
2. Require the **actual selected CIGAR process** to run qualified, final CPython 3.14. A machine can have several Python versions. Guard itself can continue using its supported Python versions while a separate selected 3.14 environment runs CIGAR.
3. Start with `hol-cigar`'s local graph and scoped views. Reuse workers and incremental source updates. Independent agent processes can use the broker in a later, separately enabled mode.
4. Preserve every supported review's **Allow once** and **Always allow** choices and their existing bindings. A CIGAR timeout, source change, or missing review must never veto an already authorized command.
5. Use deterministic briefs and cited source excerpts first. Model-written explanations need an independently evaluated reviewer and separate disclosure controls.
6. Keep source ingestion, settings validation, availability enforcement, and decision-critical I/O in Rust. Python should be thin SDK and transport glue.
7. Measure efficiency through context reuse, fewer repeated investigations, review completion time, resource use, and maintained safety outcomes. An exponential performance gain is not established by either codebase.

## Functionality and value

| User need | Integration | Expected benefit to validate | Delivery |
| --- | --- | --- | --- |
| Understand a paused action quickly | Brief combining the native reason, consequences, relevant policy, and citations | Less time interpreting a review | First release |
| See what changed since an earlier request | Compare exact admitted source revisions and native action identities | Less repeated investigation | First release |
| Keep repeated reviews consistent | Persistent workspace graph and scoped context reuse | Less redundant reading, parsing, and tokenization | First release |
| Recover from an unavailable feature | Clear runtime status and actionable repair | Fewer confusing or blocking failures | First release |
| Help an agent plan an acceptable operation | Explicit, scoped MCP context and explanation tools | Fewer avoidable review loops | Follow-on |
| Share context between cooperating agents | Host-owned broker, independent grants, quotas, and proposal admission | Avoid duplicated graph indexes while preserving scopes | Follow-on |
| Explain how evidence was selected | On-demand `selection_explanation.v1` trace | Inspectable retrieval behavior | Capability dependent |
| Connect reviewed recommendations to exact actions | Optional context-to-intent association, qualified against Guard's executor | Better traceability without replacing approval authority | Advanced follow-on |

## Read the design

| Document | Contents |
| --- | --- |
| [Architecture](docs/guard/cigar-integration/architecture.md) | Existing execution flow, integration options, ownership, source admission, caches, and failure behavior |
| [User experience](docs/guard/cigar-integration/experience.md) | Persona, onboarding, proposed screens, wireframes, copy, and accessibility |
| [Runtime and settings](docs/guard/cigar-integration/runtime-and-settings.md) | Python 3.14 enforcement, capability state, package handling, configuration, endpoints, and limits |
| [Native runtime implementation](docs/guard/cigar-integration/native-runtime-implementation.md) | Native verifier/SDK graph boundary, lifecycle evidence and qualification limits |
| [Delivery and validation](docs/guard/cigar-integration/delivery-and-validation.md) | Prioritized work packages, implementation seams, acceptance tests, benchmarks, and rollout |
| [Source evidence](docs/guard/cigar-integration/source-evidence.md) | Source references, release checks, current machine observations, and evidence limits |
| [Source manifest](docs/guard/cigar-integration/source-manifest.json) | Baseline identities and SHA-256 hashes of the referenced local source files |

## Release conditions

The inspected CIGAR notes describe 0.14.1 as an unpublished security candidate. On the analysis date, its [public PyPI version page](https://pypi.org/project/hol-cigar/0.14.1/) and [GitHub release page](https://github.com/hashgraph-online/hol-cigar/releases/tag/v0.14.1) both returned HTTP 404. Public installation must wait for approved, version-bound artifacts and new platform qualification. Development can use explicitly approved candidate artifacts; silently substituting 0.14.0 would change the security baseline.

This machine has final CPython **3.14.7** on macOS ARM64. A separate task-private environment contains the exact 0.14.1 candidate and matching worker. The [native verification receipt](docs/guard/cigar-integration/evidence/receipts.json) records a real handshake, compilation, scoped graphs, older-Python refusal and cleanup. Current [installed functional](docs/guard/cigar-integration/evidence/receipts.json), [frozen](docs/guard/cigar-integration/evidence/receipts.json) and [performance](docs/guard/cigar-integration/evidence/receipts.json) receipts qualify the listed local flows and unchanged gates. Historical Stop/RSS/relative failures remain retained. Public release, full Desktop/other platforms and actual model/human benefit remain outside this local acceptance; public availability has not been rechecked as a release authorization.

Ship the availability gate, local context service, and review UI together after their acceptance checks. Add agent tools and independent-process sharing only after their authentication and disclosure paths are proven. Keep the optional Honey effect-service bridge outside the first release.
