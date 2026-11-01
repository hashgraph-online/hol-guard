# Python 3.14 availability and settings contract

This is the backend contract and implementation target. Native configuration loading/writing, restrictive workspace/managed composition, portable export projection and typed Python/TypeScript projections are implemented. The actual runtime/package/worker capability gate remains in progress; recorded enablement is requested intent and does not make assistance available. Guard's Python requirement is unchanged.

Workspace and managed fragments are sparse restrictions. They may disable flags, shorten retention, reduce resource ceilings or increase reserved tokens. They cannot select `runtime_id` or `source_set_id`, enable a locally disabled permission, or overwrite an earlier workspace denial. An invalid restriction disables assistance with a content-free diagnostic while leaving ordinary Guard settings usable. Native settings updates accept `context_assistance: null` as a reset to disabled preferences; ordinary exports omit an absent section and otherwise use a native portable view with enablement and local references cleared.

## Availability predicate

Interpret “the computer is Python 3.14” as **the selected process that will execute CIGAR is running qualified, final CPython 3.14**. Checking an unrelated `python --version`, a filename, the browser, or Guard's parent interpreter is insufficient. A separately selected 3.14 environment can qualify while Guard runs on 3.10–3.13.

Require all of the following before starting assistance or exposing executable context functionality:

| Check | Required result |
| --- | --- |
| Interpreter implementation | `sys.implementation.name == "cpython"` |
| Interpreter version | `sys.version_info[:2] == (3, 14)`; release level `final` |
| Interpreter build/ABI | Build flavor and ABI included in the integration qualification matrix; unqualified free-threaded builds remain unavailable |
| Process platform | A qualified native wheel target for this exact interpreter process architecture and libc |
| Distribution | Installed `hol-cigar` version exactly `0.14.1`, with approved artifact identity |
| Worker | Bundled worker digest, target, core `0.14.1`, and `cigar.context-worker.v1` handshake match |
| SDK feature | Required capability advertised for the requested operation |
| Doctor | A bounded synthetic compile succeeds; contains no user documents |
| User settings | Explicit global opt-in plus effective app/workspace grants |
| Managed policy | Feature and requested disclosure permitted |
| Service state | Verified current generation and resource limits permit admission |

Python 3.15 must be unavailable even though it is newer. Python 3.13 must be unavailable even if an SDK source tree can be imported. Reject prereleases, PyPy, missing or unqualified workers, package mismatches, and unsupported process targets. A runtime override, SDK worker override, MCP call, or direct HTTP request cannot bypass these checks.

The CIGAR native inventory covers macOS ARM64/x64, Linux glibc ARM64/x64, Linux musl ARM64/x64, and Windows x64. Guard also supports Windows ARM64; this does not establish a native CIGAR ARM64 Windows artifact. Qualify the actual process ABI before enabling any emulated x64 route. Do not infer wheel availability solely from the operating system name.

## Discovery and verification

Discover candidates on the control plane when settings opens, the user selects an interpreter, or a relevant installed-runtime identity changes. Do not spawn an interpreter or run doctor on each hook.

Resolve a candidate to a trusted absolute executable. Rust validates its stable identity and relevant ownership/permissions before launch. Do not execute a workspace-local `python`, mutable shell alias, or caller-supplied arbitrary executable simply to discover its version. Reuse Guard's protected native process and filesystem patterns.

Launch the selected interpreter with isolated Python mode and a fixed, installed bridge entry point. Collect structured version/build/platform facts before importing `cigar_sdk`. Use a sanitized environment, a safe working directory, closed inherited descriptors, bounded stdio, and an overall deadline. The SDK's worker inherits its parent environment, so sanitization must happen before starting the bridge; qualification must cover platform-required variables.

Then inspect installed package metadata, use `get_local_context_capabilities()` for bundled worker verification, and run a synthetic doctor check. The capability function verifies platform and bytes without starting a worker; its `runtime` string is descriptive, not an independent version gate. The subsequent handshake and compile are separate checks.

The bridge must repeat its own version assertion before SDK import. Rust publishes a capability generation bound to the verified interpreter, bridge/package/worker identity, platform/build, policy, and settings. Feature calls check that generation and effective state in memory. Interpreter replacement, service restart, policy changes, or source access changes invalidate the applicable generation/handles. Stable daemon restarts may restore an existing opt-in after successful re-verification; transient failure must not force repeated onboarding.

Guard Desktop's frozen executable is not automatically a general Python interpreter. Discover or explicitly bundle a supported 3.14 bridge runtime through Desktop's packaging/attestation flow, and qualify that artifact. Do not assume `sys.executable -m ...` works in a frozen build.

## State model

Keep user intent separate from effective availability.

| State | Meaning | Allowed work |
| --- | --- | --- |
| `unavailable` | Missing/unsupported runtime, prohibited policy, or unavailable approved artifact | Status, safe discovery and explicit setup actions |
| `install_required` | Python/platform eligible; approved SDK not installed | Explicit installation plan and action |
| `disabled` | Runtime/package ready; user has not enabled assistance | Status and settings only |
| `starting` | Existing opt-in is being verified/started | Status and cancellation; no context delivery yet |
| `ready` | Verified capability and permitted scope active | Authorized assistance operations |
| `degraded` | Existing opt-in cannot currently run | Native Guard plus status/repair; assistance requests fail explicitly |

Use bounded reason codes such as `python_missing`, `python_version_unsupported`, `python_build_unqualified`, `platform_unsupported`, `package_missing`, `package_version_mismatch`, `worker_integrity_failed`, `capability_missing`, `managed_policy_disabled`, `service_unavailable`, and `resource_limit`.

A settings/API write that tries to enable an ineligible runtime returns a typed refusal and must not claim successful activation. A previously enabled setting may remain recorded as requested after runtime loss, but `effective_enabled` becomes false immediately. Neither a saved setting nor an agent-supplied availability flag can authorize work.

Feature-off behavior means no CIGAR imports in ordinary Guard startup, bridge, worker, listener, source indexing, optional source watcher, model call, or automatic installation. Explicit settings discovery and setup checks are the only exception. Existing Guard operation continues across all of its supported Python versions.

## Packaging and installation

Keep Guard's base `requires-python = ">=3.10"` and base dependencies. Use an optional extra only for installations where Guard and CIGAR deliberately share a qualified environment. The proposed dependency is:

```toml
[project.optional-dependencies]
cigar = ["hol-cigar==0.14.1; python_version == '3.14'"]
```

The marker protects resolution but does not enforce feature readiness. On another Python version, a package manager may successfully install the extra while skipping CIGAR. Setup must report the runtime mismatch explicitly. Do not add this stanza until the exact approved version is available through the chosen release channel.

Prefer a separate, explicitly managed 3.14 environment for other Guard installations and Desktop. Installing CIGAR requires an explicit user action, the reviewed package/version/platform, existing settings protections, and approved artifact hashes. Do not auto-download Python, replace the system default, compile an sdist as fallback, search PATH for a worker, or weaken worker integrity checks.

Use `sdk/python/pyproject.toml` as the local-context package definition. `packaging/pypi/pyproject.toml` in this repository belongs to an older 0.9.1 packaging profile. The broader remote Rust workspace still uses 0.9.4 versions. Those numbers do not identify the 0.14.1 local graph candidate.

Use the Python SDK for this implementation. The dashboard does not need `@hol-org/cigar`. If a Node client is deliberately added later, the candidate requires Node `>=24.22.1 <25`; a package install does not update Node. Browser React code and a development `@types/node` version are not evidence of that runtime qualification.

## Proposed configuration

The following is a new Guard configuration design, not an existing supported TOML section. Absent settings must resolve to feature off.

```toml
[context_assistance]
schema_version = 1
enabled = false
runtime_id = ""
resource_profile = "balanced"

[context_assistance.features]
review_briefs = true
agent_context = false
shared_agents = false

[context_assistance.sources]
native_policy_facts = true
sanitized_receipt_facts = true
workspace_documents = false
source_set_id = ""

[context_assistance.storage]
mode = "memory"
retention_hours = 24

[context_assistance.limits]
context_tokens = 2048
reserve_tokens = 256
max_active_workspaces = 2
idle_shutdown_seconds = 600
```

`runtime_id` and `source_set_id` reference private, host-maintained records. They are not paths, bearer credentials, or permission grants. A nonempty selected source set is necessary for additional documents; global enablement is insufficient. In memory mode, `retention_hours` is inactive and the UI must say so.

Apply settings in this order: managed prohibitions/ceilings, explicit local consent, app/workspace grants, source disclosure intersection, runtime capability, then bounded operation admission. Workspace settings may narrow, but cannot enable or widen, user grants. Managed policy may prohibit or cap assistance but should not silently opt a user into it.

Validate enums, ranges, unknown keys, cross-field dependencies and managed restrictions in Rust. Extend native config loading/coercion, editable-key validation, update/reset/import/export behavior, and the Python/TypeScript projections together. Keep computed status out of persisted settings. Runtime identity, grants, snapshots and secret-bearing connection records must not enter ordinary settings exports.

Use the existing settings mutation authentication and proof policies. Availability inspection is read-only. Source expansion, feature enablement, installation and deletion follow the applicable existing control flow; no second CIGAR-specific approval system is necessary.

## Proposed API and agent surfaces

All endpoints below are new proposals. Reuse the daemon's authenticated local control transport, browser-origin defenses, bounded schemas and session handling.

| Interface | Semantics |
| --- | --- |
| `GET /v1/context-assistance/status` | Requested/effective state, bounded reason, host runtime version, package version and supported feature booleans; no broker secrets |
| `POST /v1/context-assistance/verify` | Explicit bounded runtime/package/worker recheck with a synthetic compile |
| Existing `POST /v1/settings` with `context_assistance` | Authorized configuration mutation; compare expected configuration generation to prevent lost updates |
| `GET /v1/context-assistance/sources` | Only the authenticated user's permitted source metadata; private excerpts use a separately authorized detail route |
| `POST /v1/context-assistance/sources` | Validate selected source identifiers, preview scope, and publish only through native source admission |
| `POST /v1/context-assistance/clear` | Explicitly scoped cache or persisted-context deletion, with existing write protections |
| Review/evidence detail projections | Separate bounded assistance fields, native action association and currentness; no change to approval payload semantics |

Use a CIGAR-specific gate for each assistance operation. Hidden buttons and conditional imports are not enforcement. Status and repair endpoints remain usable when unavailable; compile, source admission, sharing and dispatch assistance are refused before graph creation or content access.

For a follow-on MCP integration, propose `get_context_status`, `get_context`, and `explain_guard_action`. Add a proposal tool only when the host admission workflow is implemented. Tools derive authority from a verified session and host scope, never a requested `agent_id` alone.

Guard's typed MCP registry supplies list, call and FastMCP registration. Pass the same trusted availability context through all three paths. When off or ineligible, omit executable context tools from discovery and reject calls through a cached tool name with `feature_unavailable`. Notify clients of tool-list changes where supported; qualify restart/reconnect behavior where clients cache registrations.

The status response can remain available through existing Guard status reporting. It should not require installing CIGAR to explain why CIGAR is unavailable.

## Resource and deadline policy

These are proposed starting bounds, subject to installed benchmarks. They are smaller than several SDK defaults and do not constitute measured memory guarantees.

| Resource | Initial policy |
| --- | --- |
| Active workspace graphs | At most 2; close least-recently-used idle graphs after 10 minutes |
| Graph ingestion | `max_documents = 10000`, `max_document_bytes = 131072`, `max_total_bytes = 16777216` |
| Context output | 2048 `o200k_base` tokens including a 256-token reserve; at most 1792 rendered context tokens |
| Optional job notifications | At most 256 and 4 MiB combined; coalesce by action/scope; no raw content |
| Ordinary assistance response | 1 second overall deadline; fall back to the native-only view when exceeded |
| Setup/doctor | Separate, cancelable 5-second overall budget, after artifact installation |
| Default storage | Memory; persistence is an explicit later option |
| Broker client limits | Short leases, bounded tickets/proposals/bytes and fair queues; begin with SDK defaults only where they fit the host policy |

Do not treat a short HTTP/UI timeout as cancellation of a running SDK operation. Local calls are synchronous and serialized. Configure finite SDK/worker timeouts, bound admitted work before dispatch, and retire a stuck worker generation when necessary. This invalidates its contexts and may leave mutation outcomes unknown; reconcile before resubmission. Do not accumulate timed-out calls in an unbounded thread pool.

The 0.14.1 native core additionally enforces one million aggregate compilation work units and 64 MiB of charged preparation work per call. Callers cannot raise those hard limits, and accounting is not an RSS ceiling. `LimitExceeded` should produce a useful narrowed-source action, not an identical automatic retry.

Worker restart starts a fresh context epoch. Use a bounded supervisor restart policy and circuit state, re-admit current sources, and discard old reviews/grants. Never retry an uncertain source mutation or external effect merely because transport failed.

## Persistence, privacy and removal

Keep in-memory operation as the default. If enabled later, persistence stores admitted evidence and source revisions in a private domain directory. CIGAR requires Unix mode 0700 or its qualified Windows owner-only DACL/local-NTFS contract. Do not create an ordinary SQLite file in the repository or reuse Guard's authority tables.

Persistence restores evidence, not credentials, tickets, drafts, reviewer verdicts or execution permissions. It writes full checkpoints, so batch admitted changes and account for journal/disk overhead. A retention policy must actively withdraw expired evidence and remove expired files; merely recording `retention_hours` is not enforcement.

Source text, snapshots and citations have the same disclosure restrictions as their inputs. Keep these out of telemetry, cloud sync, ordinary outcome receipts, and general diagnostics. Clearing a cache or freeing a process does not guarantee memory zeroization or secure disk erasure. Turning off revokes access and stops workers; clearing persisted data is a separate explicit action.
