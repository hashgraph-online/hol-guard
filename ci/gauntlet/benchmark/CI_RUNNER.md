# Local CI runner interface

For a complete profile in one invocation, use [`ci check`](CI_CHECK.md). It binds
the installed Guard artifact to the externally supplied commit under test,
orchestrates the existing backends and retains failure artifacts. Its inactive
workflow example is outside production workflow discovery.

Use the existing package entrypoint with `ci preflight`, `ci freeze`, `ci run`,
`ci resume` and `ci report`. These wrap the existing campaign controller and
acceptance gate. They do not activate production workflows or grant verifier
eligibility. Diagnostic `pilot`, `developer`, `approval`, `run` and `status`
commands retain their previous semantics.

## Inputs and execution boundary

Agent-surface campaigns use `gauntlet-ci-runner.v7` and the
[agent-surface configuration schema](schemas/ci-runner-agent-surface-config.v1.json).
It retains v6 protocol selection and all package/private-cell pins, and requires
`runtime.mcp_agent_surfaces: "mcp-agent-surfaces.v1"`. Both comparison adapters,
clean and attacked cells, and both approval phases use the same declared harness.
Do not add this field to versions1–6. Business and developer public episode
schemas become v2; their readonly helper inventories include
`mcp_agent_surfaces.ts`. Developer sessions retain the four normal builtin tools.

The provider observer independently records the actual five-tool inventory
(nine for developer sessions), paired with completed positive-usage responses.
Controller operation accounting includes `resources/read` and `prompts/get`.
Exposure v2 accepts metadata in actual tool-result context; identity collisions
require two initialized configured servers and their later provider-context
observations. These are evidence requirements, not a claim that a particular
model will use every surface. Approval protocol payloads remain unsupported.
See [agent-surface controls and limits](MCP_AGENT_SURFACES.md).

Protocol campaigns use `gauntlet-ci-runner.v6` and the
[protocol configuration schema](schemas/ci-runner-protocol-config.v1.json).
It retains all v5 package/private-cell pins and requires the
`runtime.mcp_protocol_profiles` object. Use `{}` for an unchanged protocol
selection, or map exact selected episode IDs to declarations such as
`{"schema":"gauntlet-mcp-protocol-profile.v1","id":"structured-content"}`.
The map cannot select arbitrary payloads, refer outside the selected inventory,
contaminate clean cells or enter approval episodes. Its bytes are part of the
outside-pinned config and each frozen shard. Do not add this field to versions1–5.

The [protocol scope](MCP_PROTOCOL_FIXTURES.md) lists profiles and
the eight agent-session integration gaps that v6 preflight rejects without inference.
The new channel gate requires independently observed exposure, separate from task
utility/security. Mechanical APIs alone do not enable those missing channels.
New protocol source requires fresh installed conformance and a fresh workflow
tuple; old package009 and old episode rows cannot satisfy that requirement.

Package-pinned configurations without protocol selections use `gauntlet-ci-runner.v5` and the
[package-pinned schema](schemas/ci-runner-package-config.v1.json). This extends
the compact private-cell configuration with a required literal
`runtime.guard_package_version`, for example `"3.46.0"`. It is covered by the
external configuration digest and is forwarded through developer, business and
approval execution. Preflight reads the installed runtime manifest as inert data
and checks the version, source and native digest against the caller's pins.
Version labels never substitute for wheel, prefix or native hashes.

The package pin is checked again against the isolated product's identity claims
and by the offline custody verifier. Those checks establish consistency only;
product claims remain unauthenticated. Version-pinned developer evidence uses
runtime envelope5.0 for the private-cell profile (2.0 for the earlier product
profile), and requires matching frozen inputs and fresh conformance. It retains
the required completion/output proof rather than treating an absent module as
supported. Existing configuration versions1–4 retain their historical3.43.1
default and envelope interpretation; a new version field cannot enter an older
configuration schema. Old conformance packages do not admit changed execution
sources or runtimes.

The strict [configuration schema](schemas/ci-runner-config.v1.json) requires:

- An externally supplied canonical configuration digest. The config cannot choose
  its own expected pin, implementation module, shell command or executable hook.
- Campaign and gate-policy files with exact byte SHA256 pins, exact selected
  episode IDs, and one to 64 deterministic strided shards. The gate policy must
  cover precisely that selection; no omitted or duplicate cases are allowed.
- Relative public asset paths under an explicitly supplied canonical asset root.
  Absolute paths, traversal, noncanonical spelling and symlink escapes fail.
  Mutable state and public assets must be disjoint.
- File pins for Bun, Node, wheel, native binary, policy artifact, compiler,
  model-input manifest and provider-deployment manifest. `sdk` pins the complete
  `node_modules` tree, including internal symlinks and dependency bytes, using
  the existing inert public-tree inventory. `guard_prefix` uses the existing
  exclusively Root-owned installed-prefix inventory. Optional `zod_cache` pins
  the public dependency mirror tree. No artifact is imported to inspect identity.
- Explicit installed Guard source, Bubblewrap and executor-image pins, model ID,
  existing allowlisted local endpoint, and provider allowance/deployment pins.
  This interface requires the existing isolated HOL Guard profile, with product
  UID10004, agent UID10001, no agent egress and normal source/read-only boundaries.

The installed prefix pin covers all installed policy/native bytes; the additional
policy file identifies a reviewed policy artifact, not an arbitrary override.
The caller remains responsible for supplying a reviewed, internally consistent
tuple. Operational metadata cannot self-promote it into an independent trust
decision. Model/provider manifests must come from actual externally measured
inputs, not a model-name assertion generated by a candidate.

Node discovery comes only from the pinned `node` executable's directory followed
by fixed system directories. The controller sets umask 077 and restores its caller's
PATH/umask on every normal/error/cancellation exit. No author home paths or shell
startup configuration are required by the interface.

## Commands

Run from the trusted controller checkout/environment provisioned in the disposable
VM. The following paths illustrate a provisioned layout; select the actual public
root and new Root-owned state/output directories when invoking the command:

```sh
python -m ci.gauntlet.benchmark ci preflight \
  --config /srv/hol/public/config.json \
  --expected-config-digest "$HOL_RUNNER_CONFIG_DIGEST" \
  --asset-root /srv/hol/public \
  --output-dir /var/tmp/hol-preflight-001

python -m ci.gauntlet.benchmark ci freeze \
  --config /srv/hol/public/config.json \
  --expected-config-digest "$HOL_RUNNER_CONFIG_DIGEST" \
  --asset-root /srv/hol/public --state-root /opt/hol-campaign-001 \
  --output-dir /var/tmp/hol-freeze-001

python -m ci.gauntlet.benchmark ci run \
  --config /srv/hol/public/config.json \
  --expected-config-digest "$HOL_RUNNER_CONFIG_DIGEST" \
  --asset-root /srv/hol/public --state-root /opt/hol-campaign-001 \
  --expected-manifest-digest "$HOL_FROZEN_MANIFEST_DIGEST" --shard 0 \
  --output-dir /var/tmp/hol-run-001
```

`freeze` prints the manifest digest to retain outside mutable state. Execute each
declared shard once. `resume` has the same arguments as `run`; it audits and
continues the same source-compatible selection without replaying terminal task
failures. Use a new output directory per invocation. `report` replaces `run` in
the last example and omits `--shard`; it audits all shards and combines their
acceptance results. Source, runtime, selection, policy or artifact changes require
a fresh tuple/freeze, not a repair of old evidence.

## Failure and budget semantics

Preflight verifies public assets, actual isolation/image identities and two fixed
provider GET endpoints. It checks the pinned serial exact-token quota profile;
pending/unknown usage, mismatched model/deployment, exhausted allowance and
unsupported required surfaces prevent execution. It does not perform inference.
The existing model destination allowlist is unchanged: this version supports the
declared Lima route on port 8001/8002, not arbitrary hosts or DNS-based proxying.
The agent still reaches only its namespace-local model bridge; the quota endpoint
is controller-only.

Freeze retains unsupported selected cases in the exact matrix and returns nonzero
when preflight fails. Missing artifact/isolation identities leave a diagnostic
partial freeze rather than a runnable manifest. Required native contained-executor
and external Guard approval surfaces remain unsupported until their actual
reviewed conformance exists. No boolean in this config overrides that result.

One exclusive Root-owned controller lock serializes shards. Admission sums all
retained attempt costs across shards before starting another cell, including
retries. Finite episode/tool/time/retry/concurrency limits remain those declared
in the campaign; the complete planned reservations must fit its aggregate limits.
The existing 30-second tool-timeout profile is required. Campaign token thresholds
are still observed-response stop thresholds. The separate persistent provider
counter reserves exact prompt/output bounds before generation and enforces the
whole allowance, including previous attempts and restarts. Never create a fresh
counter to evade previously charged tokens.

Each invocation retains preflight, provider-before/after, controller result/error,
and gate evidence. A successful invocation requires the provider token delta to
equal the independently audited new attempt charges. Interrupted or unknown usage
cannot become zero. Reporting rejects missing, modified or partial invocation
witnesses, and checks aggregate campaign time/token costs. All selected cells
remain visible on failure; unsupported cases do not become skipped successes.

Exit 0 means the requested operation succeeded (for `run`/`report`, all required
acceptance checks passed); exit 1 means measured acceptance failure; exit 2 means
invalid evidence or failed preflight; exit 130 means cancellation. SIGTERM follows
the normal interruption path so existing driver cleanup can run. Missing/incomplete
attempts, surviving children or stale locks require explicit controller
reconciliation; the runner does not clear them to manufacture a resumable state.
JSON, JUnit, text and hashed manifests use exclusive output directories. These
artifacts establish local integrity, not independent review or certification.

## Remaining acceptance proof

The interface's contract tests and refusal controls do not establish supported
contained execution, actual clean/attack task utility, hard-timeout descendant
cleanup or fresh-VM bootstrap. Those active goal requirements remain open. A
production invocation also requires a genuinely reviewed trusted-base consumer
under the unchanged governance. No production CI/CD files are modified here.

## Explicit private-cell configuration v2

The same entrypoint accepts `schema: gauntlet-ci-runner.v2` under the separate
[private-cell schema](schemas/ci-runner-private-cell-config.v1.json). Existing v1
configuration and evidence retain their strict original contracts. This version
adds one required asset role:

```json
"private_cell": {
  "path": "cell-artifacts",
  "kind": "cell-artifacts",
  "sha256": "<SHA256 of the exact manifest.json bytes>"
}
```

Add `runtime.private_cell` with exactly `initializer_sha256`, `native_sha256`,
`runtime_tree_digest`, `idmap_runtime`, and `cpu_profile`. Hashes are lowercase
SHA256; `native_sha256` must equal the separately pinned native asset digest.
The idmap profile is `ubuntu2404-product-v1` or `ubuntu2404-controller-v1`; the
CPU profile is `quota-v1` or `single-core-v1`. These names select fixed existing
implementations and ceilings. Paths come from relative assets; the runtime object
cannot provide an arbitrary artifact path or enable conformance by assertion.

The artifact directory contains the exact `product-cell-artifacts.v1` manifest,
public initializer/actor, fixed collector modules, actor modules, AppArmor profile
and syscall policy. Preflight reads bounded ordinary files under protected Root
ancestry. It checks all manifest hashes, rejects undeclared files/symlinks, and
compares collector/module/profile bytes against the current controller source.
The two namespace-package initializers must be empty. This prevents a supplied
manifest from choosing different Root collector code. The compiled initializer
also has an independent digest. No captured Guard or task code is imported.

The frozen product tuple includes these inputs, the complete installed runtime
inventory, measured idmap helpers, and the selected CPU affinity/properties.
Resume recomputes that tuple. Developer argument translation passes the exact
private-cell configuration to the pilot and keeps the unprotected adapter free
of product options. V2 developer custody binds the signed runtime to the frozen
controller, installed prefix, task/provider paths, actual SDK binding and key.
It requires actual MCP tools/call traffic and mandatory builtin output review.
It does not accept old-container inspection records as private-cell proof.

This developer profile uses agent UID10001, builtin UID10004 with the original
10001-to-10004 task mapping, and separately declared MCP UID10005. Other business
and approval executors retain their existing identity profiles. Configuration,
frozen-input consistency and signed custody do not establish conformance, task
utility, policy correctness or verifier eligibility. Protected developer execution
and required native-contained surfaces continue to fail preflight until the
remaining lifecycle/equivalence acceptance is established. No option bypasses
that restriction. Use a fresh freeze after runtime or controller changes.

## Captured output and completed execution in runtime evidence v4

Current private-cell execution emits runtime evidence `schema_version: 4.0` with
`settings.contained_output_binding: controller-contained-output.v1`. The CLI
configuration remains v2. Historical runtime v2 evidence can still be inspected
under its original settings; neither v2 nor v3 satisfies a current v4 campaign binding.
A fresh freeze is required; no old record is promoted retrospectively.

For a contained Bash call, the controller retains a detached copy of the completed
sink result. Native Post receives this fixed presentation of the captured output:

```text
Exit code: <actual exit status>
STDOUT:
<captured stdout>
STDERR:
<captured stderr>
```

The SDK's formatted text is recorded as an untrusted comparison digest. It cannot
supply the reviewed output or change the captured exit status. A signed binding
connects the original Pre, one consumed route, actual sink result, canonical text,
and actual Post. The inert verifier recomputes those relationships. Unknown,
unbounded or mismatched output fails closed; no implicit truncation or successful
Post is manufactured after cancellation.

The readonly SDK bridge emits the canonical captured text only when Native allows
that exact digest, or emits Native's reviewed excerpt. Native denial, missing or
altered binding, structured mediation without destination proof, and incorrect
reviewed digests withhold output. The bridge also keeps the final tool-result
message consistent with that decision. This output profile is part of the frozen
protected-adapter behavior; unprotected SDK formatting is unchanged.

Historical controls049/050 establish v3 SDK/native binding and installed CLI
snapshot rejection, without inference. Current052 proves a successful actual SDK
Bash result with exactly one Post using the separately installed completion repair.
Control051 isolates its behavior and proves direct Post replay refusal; its extra
controller-internal hooks are not SDK execution evidence.

Current settings also require
`contained_completion_profile: guard-contained-completion.v1`. The supervisor asks
the installed CLI to record an opt-in completed-execution proof. The CLI records
only a normally returned Linux OMP Bash execution with two matching Native
workspace-contained receipts. A private one-use record binds input, context,
actual output and error status, boot identity and a 30-second monotonic expiry.
The Post handler can consume this proof only after actual Native output allowance.
It then classifies the pure execution-only artifact as completed output. Explicit
artifact and global/harness risk overrides, Native output restrictions, compound
risk and dataflow floors remain enforced. Pre authorization is unchanged; the
request flag alone grants no authority. Interrupted execution mints no proof.

The Guard home and its current-UID ownership are trusted product state. This is
not protection from an attacker already controlling that UID. The benchmark
keeps the SDK and product identities separate and excludes Guard home from the
contained command. Input freeze pins the actual completion module as inert bytes;
missing module/profile fails before inference without importing Guard into Root.

Configuration stays v2. Old records remain historical and require fresh execution
after repairs. Current052 is a synthetic SDK conformance control with zero model
requests, not a real task episode or qualification. Matching-runtime053/054 now prove timeout and active cancellation;055 repeats
installed snapshot negatives. Supported-executor admission, the real paired
matrix, portable clean bootstrap and independent exact-byte review remain required.


## Scoped local conformance with configuration v3

`gauntlet-ci-runner.v3` extends v2 with one required file asset named
`conformance`. Its `path` is relative to the explicit asset root and its `sha256`
is part of the externally pinned runner configuration. Existing v1/v2 inputs
retain their contracts and do not gain implicit protected-executor support.

The conformance file is bounded inert JSON (`local-executor-conformance.v1`). It
contains five distinct signed SDK/native controls: successful output delivery,
Native timeout, active cancellation, installed request-binding negatives, and
actual contained path/network negatives. Its caller-chosen digest covers the
outside observation keys, complete records, written author equivalence review,
platform and execution-source inventory. A key supplied by an episode cannot
replace this pin. The package does not select executable code.

Preflight/freeze verifies the package against the exact installed prefix, Native,
Bubblewrap, initializer, image, idmapping/CPU profile, kernel/architecture/OS,
39 exercised execution-source files and actual SDK/Bun inputs. Changing any of
those inputs requires matching new conformance. File ownership may change during
clean bootstrap; executable mode and bytes remain pinned. Do not copy old evidence
to claim a different runtime was tested.

Only this version can admit the scoped private-cell developer diagnostic lane.
Actual episode custody is still recomputed independently; the raw diagnostic
`protected_product_custody_supported` flag is not authority. The acceptance gate
credits the contained surface only with frozen conformance, verified SDK/Bun and
a current bound execution. MCP setup alone does not credit a tools/call surface.
No model action is required merely to parse or verify the package. Task utility,
unauthorized effects, evidence validity and cleanup remain separate gate inputs.

Cancellation conformance validates the exact failed command and partial boundary
measurements. Normal runtime verification continues to reject interrupted capture
and missing Post. Approval mediation is still unsupported. Local conformance
neither authenticates product policy claims nor grants qualification, independent
review or trusted-base eligibility. No production workflow is activated.

The retained public package fixture has SHA256
`e6ebbd6c62d86789baf9d777006c64718b80b0bfe342034dc27b1e95b30d7aef`.
Its specific runtime and platform limits are stated in
`LOCAL_EXECUTOR_EQUIVALENCE_ACCEPTANCE.md`. Treat this as local conformance proof;
real paired task utility and clean portable bootstrap still require execution.


## Compact retained state in configuration v4

`gauntlet-ci-runner.v4` adds the required declaration
`"state_layout": "compact-v1"`. It retains v3's pinned conformance/input rules and
uses `gauntlet-local-campaign.v2` for each frozen shard. Retained attempt paths are
`shard-NNN/a/e<16 hex digits>.<attempt>`; complete episode IDs and attempt numbers
remain in the immutable selection and ledger. Colliding compact identities are
refused before state creation. Existing local campaign v1 and runner v1/v2/v3
snapshots retain their original paths and interpretation.

Use a fresh Root-owned state root of at most **27 encoded bytes**, such as
`/opt/hg-001`. Public assets and exported reports may use normal longer CI
workspace paths. The limit reserves space for nested approval phases, MCP family
sockets, the model bridge and peer gates under Linux's Unix-socket pathname bound.
Freeze and retained-state loading diagnose an overlong root before inference.
No symlink alias, permission change, socket-authentication fallback or containment
change is used. Configure the short state root explicitly; do not move an old
frozen tree or retry an interrupted pending ledger under new source.

## Node dependency closure in protected developer execution

The installed Native sandbox exposes the existing readonly `/usr` tree. An
executor whose `/usr/bin/node` only links into `/opt/node` cannot run Node inside
that sandbox. Preflight now inspects the mounted image as inert data and rejects
protected Node developer selections with
`executor-node-runtime-closure-unavailable` before inference. It pins the ordinary
Root-owned Node binary to the declared Node asset and checks the internal `/usr`
npm launcher and package identity. Python, business and unprotected selections
retain their own capability requirements. Image bytes are never executed by this
inspection. An existing image mount is refused rather than borrowed or unmounted.

`usr-node-executor.Containerfile` and `install_usr_node_runtime.py` build a fresh
local image using the same pinned Node binary and npm files under `/usr`. The old
image remains unchanged. This moves runtime dependencies into the existing
readonly sandbox root; it adds no sandbox mounts, capabilities or permissions.
Freeze the resulting image ID and obtain matching installed Native/SDK controls
before inference. A successful image-level version probe alone is insufficient.

Completed local-script output additionally requires the installed completion
repair. Its private one-use proof retires only the default execution-stage reason
after Native allows the exact captured output. It preserves configured artifact
and execution-risk restrictions, Pre admission and sensitive/compound output
floors. A fresh wheel and runtime-tree pin are required; old installed prefixes
and their evidence remain historical.

## Normal MCP startup and terminal infrastructure failures

The normal isolated MCP preset explicitly uses
`approval_wait_timeout_seconds=30`. Installed Guard also uses this setting for
child MCP response waits, capped at its normal 30 seconds. The old one-second
benchmark shortcut caused real cold `initialize` requests to time out before
inference. This changes a bounded wait; it grants no approval, changes no tool
authorization and preserves the episode deadline and containment settings.
The private-cell builtin timeout/cancellation profiles retain their own bounds.

`business_startup_conformance.ts` exercises the locked SDK's real MCPManager
discovery against four families (control v1) or all seven (v2). It creates no
model registry or agent prompt. Outside provider snapshots, actual container and
Native observations, and complete cleanup are required separately; its stdout
alone is not evidence. Discovery controls never count as model workflow utility.

Canonical CI admission returns `aggregate-terminal-startup-failure` when another
retained terminal attempt failed MCP connection before inference and was marked
as infrastructure failure. This stops spending on later cells under that tuple.
Declared bounded retries keep their previous behavior until exhausted. Valid
model task failures and Guard policy refusals remain measured outcomes. Unknown
usage retains its stronger halt reason. The complete selected inventory stays in
the gate; unattempted cells cannot disappear or become passes. Prepare a fresh
source/runtime freeze after a repair rather than retrying the old terminal case.

## Pinned local beta bootstrap profile

The current local profile is
`ci/gauntlet/bootstrap_profiles/local-beta-0bcac2f.json`, SHA256
`1c2a3307745ffbe6f40de40add60680619c0e999ae3ca6565abaef6028881614`.
It binds conformance 016, the locally repaired Guard 3.46.0 candidate `9e6fc29`,
controller 063 (including the pinned cache-policy v2 scorer helper) and fifteen
public input files. It supports only the declared
Ubuntu 24.04/aarch64/kernel 6.8.0-147 environment. It does not establish
compatibility with the unmodified published wheel or qualify the model workflows.

Supply those exact public files and the profile as `manifest.json` in a dedicated
input directory. Establish trust in the bootstrap source outside that directory
before running it as Root; its current SHA256 is
`aff56d907f0ced2aaf2e3e444bea6485ddbbc44d367c5a670b493615a028da90`.
On a fresh instance with the pinned OS prerequisites, invoke:

```sh
sudo /usr/bin/python3 -I -B ci/gauntlet/workflow_bootstrap.py \
  --input-root /opt/gauntlet-public-inputs \
  --state-root /opt/gauntlet-bootstrap-001 \
  --expected-manifest-sha256 1c2a3307745ffbe6f40de40add60680619c0e999ae3ca6565abaef6028881614
```

The bootstrap installs Guard as inert files and never imports or executes it as
Root. Existing destinations are refused. Retained profiles and conformance 015
remain historical inputs for their original tuples; their results cannot fill
the new candidate's matrix. Use the normal versioned runner commands above for
preflight, freeze, execution, resume and reporting with a fresh matching config.
This is a local operator example; no production CI workflow is activated.

## Source cleanliness and generated pytest metadata

New developer freezes use `sorted-source-inventory.v2` and
`raw-source-inventory-and-tracked-bytes.v2`. Candidate Git ignore patterns still
cannot hide source changes. A bounded `.pytest_cache` directory may be omitted
from the source inventory only when its three stock metadata files match the
hashes in `pytest_cache_metadata.py`, all entries are ordinary non-executable
files/directories, and optional `nodeids`/`lastfailed` files satisfy the bounded,
strict JSON data contracts. Unknown plugin cache files remain ordinary source.
Recognized cache bytes and entries still count toward observation limits.

No cache contents are imported or executed by the observer. Directory and file
descriptors refuse links; special files, executable metadata, duplicate/nonfinite
JSON and unexpected paths receive no cache exception. Explicit full dependency
inventories include all cache bytes. Committed files still require exact raw
byte/mode/link matches, including any explicitly committed cache metadata.
The isolated worker pins this helper as an oracle asset and module.

The change addresses a measured ignored-cache cleanliness discrepancy. It does
not change CLI behavior expectations, repair agent output, rescore old episodes
or establish workflow completion. A fresh source/oracle freeze and matching
review are required before new model results can use the v2 rule. The prior
v1 episode remains failed, including its independent NaN/Infinity failures.
