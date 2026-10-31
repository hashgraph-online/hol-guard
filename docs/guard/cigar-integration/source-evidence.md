# Source evidence and analysis limits

The analysis uses HOL Guard v3.55.1 at `35180b995cb27fdc9f92e1f68307a756c785f154` and the local CIGAR 0.14.1 security candidate at `b47380e5a5cbeaaad5a61cab3372e9e67368732f`. The [source manifest](source-manifest.json) records hashes for the referenced files so later source changes can be distinguished from this baseline.

Guard links below point into this checkout. CIGAR links point to the existing sibling candidate checkout; those relative links require the same workspace layout. The candidate commit is a local source identity, not a claim that a public release or installation exists.

## Guard evidence

| ID | Source | What it establishes |
| --- | --- | --- |
| G01 | [PRODUCT.md](../../../PRODUCT.md) | Local harness developer/operator persona, clear consequences, calm UX, local trust and accessibility |
| G02 | [AGENTS.md](../../../AGENTS.md) and [native ownership](../native-hook-data-plane-ownership.md) | Rust ownership direction, production authority boundaries, Python glue/oracle restrictions, platform and harness limitations |
| G03 | [Approval invariant](../approval-invariant.md) | Supported reviews retain Allow once and Always allow; saved approvals end under existing removal/hash rules |
| G04 | [Exact action token](../../../rust/crates/guard-runtime/src/native_exact_action_op/token.rs) | Native exact-action token and command-hash fallback; CIGAR must not invent an alternate authorization token |
| G05 | [Saved decisions](../../../rust/crates/guard-runtime/src/hook_direct_saved_decision.rs) | Native reuse of saved exact-action allows/blocks |
| G06 | [Direct hook evidence](../../../rust/crates/guard-runtime/src/hook_direct_evidence.rs) | Bounded native queue, acknowledgement/peek behavior; 1024 records and 8 MiB queue bounds |
| G07 | [Native evidence writer](../../../rust/crates/guard-runtime/src/hook_evidence_writer_op.rs), [Python transport](../../../src/codex_plugin_scanner/guard/native_hook_evidence_writer.py), [dispatch](../../../src/codex_plugin_scanner/guard/daemon/hook_evidence_dispatch.py) | Resident-owned writer and ordered background submission; optional assistance must not displace this authority |
| G08 | [Older enrichment queue](../../../src/codex_plugin_scanner/guard/runtime/hook_enrichment_queue.py) | Privacy-safe payload restrictions; `drain_once` is a placeholder that removes work rather than implementing enrichment |
| G09 | [Package metadata](../../../pyproject.toml) | Guard version 3.55.1, Python ≥3.10, optional-dependency conventions, Python 3.10 tooling target |
| G10 | [Native config writer](../../../rust/crates/guard-runtime/src/guard_config_update.rs), [editable settings](../../../rust/crates/guard-runtime/src/guard_config_update_settings.rs), [projection](../../../src/codex_plugin_scanner/guard/config.py) | Rust validation/writes, fixed supported settings keys, existing settings proof/managed-policy flow |
| G11 | [Settings navigation](../../../dashboard/src/settings/settings-ia.tsx), [settings workspace](../../../dashboard/src/settings-workspace.tsx) | Six tabs; Protection, Approval gate, Apps and Data & repair responsibilities |
| G12 | [Review card](../../../dashboard/src/review-decision-card.tsx), [review evidence](../../../dashboard/src/review-evidence.tsx), [explanation summary](../../../dashboard/src/action-explanation-summary.tsx) | Current approval UI, existing evidence expansion and consequence/recommendation presentation |
| G13 | [Evidence detail](../../../dashboard/src/evidence/evidence-action-detail.tsx) | Existing action detail and safe-next-step surface to extend |
| G14 | [MCP registry](../../../src/codex_plugin_scanner/guard/mcp/registry.py), [server](../../../src/codex_plugin_scanner/guard/mcp/server.py) | Shared typed tool catalog for list, direct calls and FastMCP; existing sanitized search/fetch/status tools |
| G15 | [Inventory source evidence](../../../rust/crates/guard-runtime/src/inventory_source_evidence_op.rs) | Rust safe-root and stable identity patterns; operation returns metadata/hashes and is not a general source-text export |
| G16 | [Workspace review context](../../../rust/crates/guard-runtime/src/resident_workspace_review_context.rs) | Existing native Cloud Review authority metadata and binding projection; not an execution consume or general evidence graph |
| G17 | [Native SLO proof](../native-runtime-slo-proof.md) | Separate direct/installed boundaries, absolute thresholds, concurrency/recovery and RSS gates, matched comparison/noise policy |
| G18 | [Privacy-safe outcome receipts](../privacy-safe-outcome-receipts.md) | Aggregate receipt fields exclude source, command, path, prompt and secret content; hashes do not create authenticity |
| G19 | [Desktop runtime staging](../../../scripts/release/stage_native_runtime_for_desktop_core.py), [frozen runtime verification](../../../scripts/release/verify_pyinstaller_native_runtime.py) | Existing artifact staging/verification seams relevant to a separately packaged bridge |

## CIGAR evidence

| ID | Local candidate source | What it establishes |
| --- | --- | --- |
| C01 | [Python package](../../../../hol-cigar-0.14.1-security/sdk/python/pyproject.toml) | `hol-cigar` 0.14.1, Python `>=3.14,<3.15`, protobuf range, local CLI and bundled worker packaging |
| C02 | [Capability implementation](../../../../hol-cigar-0.14.1-security/sdk/python/src/cigar_sdk/local_runtime.py) | Core/protocol constants, process-platform detection, complete bundled worker hashing, capability inspection without launch |
| C03 | [Python SDK guide](../../../../hol-cigar-0.14.1-security/sdk/python/README.md) | Persistent graphs, views, source admission contract, no required HOL service, synchronous serialized calls, cache/lifecycle behavior and qualification scope |
| C04 | [Local context guide](../../../../hol-cigar-0.14.1-security/sdk/LOCAL_CONTEXT_GUIDE.md) | Exact context budgets, source disclosure, trusted reviewer contract, view invalidation and delta limits |
| C05 | [Broker guide](../../../../hol-cigar-0.14.1-security/sdk/LOCAL_BROKER_GUIDE.md) | Host/client ownership, authenticated loopback, grants/leases, admission, provenance, transactions, persistence and uncertainty semantics |
| C06 | [Broker implementation](../../../../hol-cigar-0.14.1-security/sdk/python/src/cigar_sdk/broker.py), [types](../../../../hol-cigar-0.14.1-security/sdk/python/src/cigar_sdk/broker_types.py) | Public methods, capability checks, five-minute default grant, source revisions as strings, execution binding APIs and sensitive connection fields |
| C07 | [Context implementation](../../../../hol-cigar-0.14.1-security/sdk/python/src/cigar_sdk/context.py), [types](../../../../hol-cigar-0.14.1-security/sdk/python/src/cigar_sdk/context_types.py) | Graph/view API, limits, request fields, snapshots, citation and view assessment types |
| C08 | [Selection explanations](../../../../hol-cigar-0.14.1-security/sdk/SELECTION_EXPLANATIONS.md) | Development capability, recompilation cost, successful selection signals; no rejected IDs, truth scores or independent audit signature |
| C09 | [0.14.1 notes](../../../../hol-cigar-0.14.1-security/docs/release/context-sdk-0.14.1-notes.md) | Candidate status, aggregate compilation limits, Python HTTP deadlines, patched Node requirement, new artifact/platform release gates |
| C10 | [Top-level README](../../../../hol-cigar-0.14.1-security/README.md) | Separation of local context and older Honey runtime, historical performance/soak claims and stated limitations |
| C11 | [Legacy Python packaging](../../../../hol-cigar-0.14.1-security/packaging/pypi/pyproject.toml) | Older 0.9.1 profile; inappropriate source for the local 0.14.1 package definition |
| C12 | [Context crate](../../../../hol-cigar-0.14.1-security/crates/cigar-context/Cargo.toml), [native platform inventory](../../../../hol-cigar-0.14.1-security/sdk/python/src/cigar_sdk/native_platforms.py) | Local native crate and supported target inventory; not proof that Guard embeds it today |

## Public release observations

Retrieved on 2026-10-22 through the Firecrawl plugin:

| URL | Observation | Consequence |
| --- | --- | --- |
| [HOL Guard v3.55.1](https://github.com/hashgraph-online/hol-guard/releases/tag/v3.55.1) | HTTP 200; release names exact commit `35180b995cb27fdc9f92e1f68307a756c785f154` | Confirms the requested source baseline |
| [hol-cigar 0.14.1 on PyPI](https://pypi.org/project/hol-cigar/0.14.1/) | HTTP 404 | Public installation of that exact version was not available through this page |
| [CIGAR v0.14.1 release](https://github.com/hashgraph-online/hol-cigar/releases/tag/v0.14.1) | HTTP 404 | No public release was retrievable at the requested tag URL |

A 404 is a point-in-time public page observation; it does not rule out private release artifacts. Candidate development can use approved local artifacts. Public release needs the exact signed/approved bytes and fresh qualification rather than historical 0.14.0 receipts.

## Local machine observations

A direct isolated interpreter probe reported CPython 3.14.7, release level `final`, Darwin ARM64. An isolated `importlib.metadata` lookup in that interpreter reported no installed `hol-cigar` distribution. No CIGAR graph, worker, broker, daemon, model call or package installation was started for this analysis.

This establishes interpreter eligibility on the current host, not package integrity, worker readiness, complete ABI qualification, or a working Guard integration. It does not describe every Python environment on the machine.

## Scope and verification

The documentation maps source contracts and proposes an integration. It does not claim to be an exhaustive vulnerability scan, completed runtime implementation, installed-platform qualification, usability study, or performance benchmark.

Before delivery, verify the checkout base and local branch, upstream URL, referenced file hashes/links, document consistency, and whitespace. No application tests are required solely for these new analysis files. The [acceptance plan](delivery-and-validation.md) names the runtime, UI, security-boundary and performance checks required for implementation.

Historical CIGAR measurements are evidence about their stated artifacts and workloads. They do not establish better Guard latency, reduced real-model hallucination, an exponential efficiency gain, automatic action safety, or full model/effect replay in the proposed local SDK integration.
