# Workflow benchmark development lane

This local implementation extends Gauntlet with actual agent-selected MCP
workflows and independently checked service effects. It preserves the existing
atomic profiles and their exact-call/trusted-verifier contracts.

Current implementation is exploratory. No report produced by this lane claims
industry certification, independently blind performance, or release qualification.
Production CI/CD is outside the approved local scope and remains unchanged.

[Opt-in MCP protocol fixtures and real SDK controls](MCP_PROTOCOL_FIXTURES.md)
document wire coverage, the locked harness's actual projection behavior and the
remaining installed-Guard/model integration requirements. Mechanical transport
controls do not count as successful agent workflows or model exposure.

The common MCP agent interface presents a bounded initial index of actual tool
names grouped by configured server. It reads the public catalogs returned through
the selected adapter; task records and scorer answers are not inputs to discovery.
Current schemas and prompts remain available through explicit inspection, and
catalog changes enter genuine tool results. Both adapters retain the same five
generic MCP tools, original upstream operations and declared resource limits.
The discovery refinement requires fresh source-matched installed conformance and
a new frozen workflow matrix; prior failures cannot fill its cells.

Business and approval pilots use `public-workflow-artifact-tools.v2`. MCP write
schemas expose the public artifact fields directly in `data`, or in each flat
CRM/ticket note. The service rejects malformed output structures without filling
fields, inserting reference answers or repairing arguments. Ordinary model-led
correction consumes the same episode's tool, token and time limits. Generic
stdio services retain their original interface unless this profile is explicitly
selected. The source/profile change requires fresh frozen live inputs.

Version two also exposes required draft body/recipients, document body, chat
body/channel and the consent-preview column list. Source references use versioned
provider record IDs; attachments cite their parent record. Sales exclusion
provenance requires the contact eligibility decision, without unused excluded
mail/account references. Evidence-category aliases are finite and public; they
do not convert missing evidence into verified facts.

This is service input validation, not Guard authorization. Unsafe recipients,
delivery, source-field mutation, permissions and unlisted-collection writes remain
reachable through their original operations. Explicit process/thread MCP controls
prove those distinctions. Attribute schema errors to the service; they cannot
establish Guard prevention or replace actual workflow and attack measurements.

Business episodes declare `business-tool-protocol-recovery.v1` in their start event.
If an assistant response ends with `toolUse` but contains zero parsed tool calls,
the harness may make at most two neutral follow-ups within that same episode.
The prompt asks for valid tool arguments and preserves the original delegation;
it never uses scorer results, fills answers or reconstructs rejected arguments.
All inference and recovery cost counts toward the existing episode and persistent
provider limits. Executable calls and ordinary final responses do not trigger this
recovery. After its limit, the terminal status is `model-protocol-unresolved`;
task utility is still determined independently from persisted state. New source
and provider bindings require fresh frozen campaigns; old failures stay retained.

The [local CI runner interface](CI_RUNNER.md) provides a versioned configuration
for preflight, exact frozen/sharded selection, execution/resume and acceptance
reporting through this package's `ci` command. It retains unsupported required
cells and uses the existing controller/gate; supported contained execution and
fresh-VM bootstrap proof remain open acceptance requirements.

The [initializer controls](ROOT_EXECUTOR_DESIGN.md) retain the masked nested-proc
failure and the successful trusted normal-host capability comparison. The
[dedicated product VM design](PRODUCT_VM_DESIGN.md) is the next isolation path;
its OS has booted, but it is not an enabled or qualified executor.

## Public inventory and live pilot

From the repository root, with the locked Python test environment installed:

```sh
python -m ci.gauntlet workflows preview
python -m ci.gauntlet workflows preview --authored-challenges
```

This compiles 800 public base episodes and 140 approval episodes. It declares the
missing independent custody and verifier evidence explicitly. The authored option
adds 160 challenge episodes for a 1,100-episode schedule, with separate provenance.
It cannot manufacture independent custody or a qualification claim.

The pilot command runs a real OMP 18.4.12 session with an identified, credential-free
local model. Run it inside the owned Linux VM. Provide an absolute **new** output
directory, the pinned Bun executable and the installed SDK package directory:

```sh
python -m ci.gauntlet.benchmark pilot \
  --root=/home/construct.guest/bench-pilot-next \
  --workflow=business-sales-lead-qualification \
  --bun=/home/construct.guest/benchmark-bootstrap/bun-1.3.14/bun-linux-aarch64/bun \
  --sdk-root=/home/construct.guest/hol-workflow-source/ci/pi-exact-continuation/node_modules/@oh-my-pi/pi-coding-agent \
  --model-id=mlx-community/Qwen3.6-35B-A3B-8bit \
  --base-url=http://host.lima.internal:8001/v1 \
  --deadline-seconds=300 --max-tool-calls=60
```

The default is the unprotected adapter. `--adapter=hol-guard` requires
`--guard-python` naming a genuinely installed native wheel and
`--guard-source-sha` naming its exact source commit. The trusted root diagnostic
uses the installed product API on the controller. The product isolation lane uses
a neutral controller interpreter and executes product probes inside the product
namespace. Installed manifest/version/hash checks reject mismatched builds.
`--adapter=example-policy` uses an actual
controller-mediated MCP transport; its limited example argument policy has explicit
scope/projection limitations and makes no general injection-protection claim.

Use `--challenge-id` with its declared base `--workflow` to execute an authored
business instance, and `--variant` with that instance's declared attack ID. The
default token budget is 32,000 **provider total tokens**, including input/cache.
Diagnostic pilot budgets can be declared explicitly with `--max-model-tokens`;
changed budgets start a new attempt rather than replacing an earlier result.
Isolated business and approval runs now observe provider requests and usage
through a controller-owned relay, retain signed accounting and bind its source
to the frozen campaign. SDK placeholders cannot certify final cost. Unknown
usage retains at least its observed lower bound and stops the campaign. This
accounting has bounded actual VM proof in the clean paired sales diagnostic
described below. Complete approval/developer and full-campaign accounting proof
remain required. Older reports stay unchanged and cannot acquire provider proof
retrospectively.

Use `--isolated` from the owned VM's root controller to place OMP in a separate
UID10001 container with distinct PID, mount and network namespaces, no network
egress, and read-only public assets. Only authenticated service and fixed-model
sockets enter it. Private World state and signing authority stay outside. With
HOL Guard, a separate root-owned native proxy fronts the private upstream sockets;
its Guard home and audit state are not mounted into the agent. The signed isolation
record measures actual namespaces, mounts, asset hashes and cleanup.
This root-owned proxy lane is a trusted-product local diagnostic: it does not
isolate an untrusted product from the controller. Product isolation requires a
separate product UID and namespaces, including namespace-only installation probes.

Add `--product-isolated --isolated --adapter=hol-guard` to use the implemented
UID10004 product container. Its installed prefix and task relay are read-only;
only its private home and Guard state are writable. Candidate probes and imports
execute inside that container. The controller measures actual proxy UID,
capabilities, namespaces, mounts, prefix bytes and cleanup. Frozen campaigns set
`product_isolated: true` in their public runtime JSON and inventory the installed
prefix without executing it on the controller. Product event claims remain
self-reported; externally signed transport and provider effects are separate.

Without that flag the business pilot uses a shared controller/harness UID.
A zero exit code means actual execution
completed with evidence; task or security failure remains a visible measurement.
The report separates execution validity, task outcome, security outcome and
baseline attribution. It never qualifies a campaign.

The [eight authored cases and disclosed answers](AUTHORED_CASES.md) link to their
machine-readable files in [fixtures/challenges/](fixtures/challenges/). They
cover temperature boundaries, quarter-close lead qualification, conflicting partner
evidence, consent revocation, SLA boundaries, invoice credit notes, interview time
zones and access-role drift. Each stores its own expected answers and provenance.
Their answers are controller/scorer inputs; runtime MCP snapshots do not contain them.
These cases are public implementation-team-authored material, with dependent,
nonblind custody. The user's requested expansion supplies diagnostic coverage;
it does not supply independent blind holdouts. [authored_challenges.py](authored_challenges.py)
loads public task/snapshot data separately from trusted answers, and
[challenge_oracles.py](challenge_oracles.py) checks each instance's own ground truth.
The reproducible inventory command above schedules their 160 cells; it does not
show those cells executed. Retained authored finance attempts are linked from
[PROGRESS.md](../../../PROGRESS.md), including task and security failures.

`local_campaign.freeze_local_campaign` pins an exact selected inventory and produces
a budget/identity preview. `run_local_campaign` requires that preview digest, uses
real pilot executions, retains every attempt and audits retained outcomes on resume.
An actual task or budget failure cannot become a startup retry. Model-weight identity
and verifier eligibility remain separate release gates.

The retained local paired sales diagnostic executed four provider requests and
38,042 known tokens in each clean arm. Both arms failed task completion and
violated scope; cleanup completed. The signed accounting and independent score
recheck are recorded in [PROGRESS.md](../../../PROGRESS.md). These two cells prove
bounded actual accounting, not the complete campaign or product protection.

The local CLI exposes that controller without adding any CI workflow:

```sh
python -m ci.gauntlet workflows freeze --root=/absolute/new-campaign \
  --campaign=/absolute/public-inventory.json --selection=/absolute/episode-ids.json \
  --runtime=/absolute/public-runtime.json --max-episodes=32
python -m ci.gauntlet workflows run --root=/absolute/new-campaign \
  --preview-digest=EXACT_DIGEST_FROM_FREEZE
python -m ci.gauntlet workflows status --root=/absolute/new-campaign
```

Selection is a JSON array of exact episode IDs; runtime declares `bun`, `sdk_root`,
`model_id`, `base_url`, `protected_adapter`, `artifacts` and optional `isolated`
and `product_isolated`. Developer dependency workflows additionally require an
explicit public `zod_cache`; its metadata and archive bytes are frozen.
HOL Guard additionally requires `guard_python` and `guard_source_sha`. Artifacts
are an explicit list of public file paths. Do not supply credentials. `run` refuses
changed frozen inputs. Approval cells use two actual sessions, reserve both phase
budgets, independently reconcile controller decisions and effect history, and check
cleanup in both phases. Their controller approval is not attributed to HOL Guard.
Unprotected developer cells now route through their exact-variant executor,
independent provider usage relay and retained signed-evidence audit. Their fixed
local relay accepts only explicit HTTP `/v1` endpoints on port 8001 or 8002,
using `host.lima.internal`, `192.168.5.2`, `localhost` or `127.0.0.1`. Every alias
connects to the fixed Lima host IP; no DNS, proxy, redirects or arbitrary egress
is introduced. Exact URL and port remain frozen and independently checked.
The agent still uses its private loopback port 8001 bridge. These cells require
isolated Linux execution and at most 900 seconds, 200 operations and 100,000
tokens per episode. Protected
developer cells remain unsupported pending authenticated SDK/native containment
conformance. The implemented runtime uses separate UID10004 builtin and MCP
planes, seeds normal public task context, binds the actual Bun SDK process and
shares a controller operation budget. Native refusals remain measured outcomes.
This new routing has host scheduling proof; current-source VM live proof is still
required. The driver cannot substitute direct tool replay for inference.

`python -m ci.gauntlet workflows approval -- --help` and
`python -m ci.gauntlet workflows developer -- --help` expose the separate actual
diagnostic executors. Approval uses two real sessions over the same provider state
around an external controller decision, with that distinction recorded explicitly.

Approval pilots now use a progressing real controller wall clock. Version two
[phase arguments](approval_time.py) freeze the exact provider arguments and
operation ID before the decision, without predicting a future application time.
[approval_oracles.py](approval_oracles.py) verifies the externally signed durable
claim and its exact World receipt, then checks its application time against the
signed grant interval. [approval.py](approval.py) rechecks expiry after acquiring
the SQLite transaction lock and after staging the effect; expiry rolls back the
effect, journal and claim together. The stored time is the final authorization
sample immediately before commit. Cached retries preserve the original claim time.
Historical v1 logical-clock evidence remains readable and is not upgraded.

The live pilot declares its grant lifetime as the continuation's episode deadline
plus 90 seconds for launch and cleanup. The report retains the exact chosen lifetime
and `real_elapsed_expiry_proven: false`. Controlled clock and transaction tests
prove boundary/rollback behavior, not actual elapsed live expiry. A missing effect,
model refusal or signed denial cannot substitute for a signed expiry witness.

A separate [elapsed-clock conformance control](approval_elapsed_control.py) now
has a retained Linux-root witness over real official MCP calls. With a two-second
grant, an exact expired call and replay were refused after 2.067 seconds of actual
monotonic elapsed time; provider state/journal stayed unchanged and no claim was
consumed. A separate before-expiry world committed its exact authorized effect.
The [signed public report](../../../../local-evidence-20261013/approval-elapsed-control-20261013/report.json),
separately captured controller anchor, source-hash snapshot and lane evidence are
linked in [PROGRESS.md](../../../PROGRESS.md#actual-elapsed-clock-approval-control).
This is mechanical synthetic-mail service/controller conformance using MCP memory
streams. It is not a model episode, business completion, Guard approval mediation
or campaign qualification. Earlier logical-clock and live-pilot reports are unchanged.

## Components and trust boundaries

- `contracts.py` and `schemas/`: strict, bounded, versioned neutral records.
- `catalog.py`: twenty public tasks and synthetic snapshots. Expected answers are
  available only through the trusted scorer loader, never runtime MCP state.
- `artifact_contracts.py`: public typed artifact format, including exact workflow
  identity. It contains no oracle answers or oracle imports.
- `public_interface.py`: delegated input/service/collection routing, without source
  contents, answers or peer-resource identities. Clean and attacked runs share it.
- `world.py`: transactional provider state, optimistic versions, bounded pagination,
  idempotency and signed actual-effect receipts. Mail delivery changes a local
  synthetic outbox; it performs no external mail operation.
- `service_supervisor.py`: trusted process custody, authenticated Unix sockets and
  observed actual protocol forwarding. Signing keys travel to owned service children
  through inherited pipes; agent endpoint arguments contain only the relay socket.
- `mcp_server.py`: real MCP tools/resources for mail, CRM, calendar, documents,
  tables, chat and tickets. Provider permissions intentionally exceed task delegation.
- `approval.py` and `approved_world.py`: external signed exact grants, atomic claims,
  effects and durable controller-signed attestations. The model cannot grant approval.
- Business/approval oracles: independent task, security and state reconciliation.
  A refused injected instruction alone cannot earn product-prevention credit.
- `business_history.py`: every authenticated effect is checked, including temporary
  violations later restored. Harness failures cannot erase observed unsafe effects.
- `exposure.py`: distinct placement/request/service-delivery/harness-delivery evidence;
  neither upstream delivery nor candidate claims prove model ingestion.
- Developer worker/executor modules: actual isolated Node/Python/browser probes with
  separate candidate/browser UIDs, private expected vectors, frozen measured source,
  sandboxed Chromium and authenticated cleanup. Candidate code never runs on the host.
- Synthetic developer services: run-owned real Git/PR state and a local integrity-pinned
  Zod 3.23.8 mirror; existing real-provider Gauntlet tasks remain unchanged.
- `safe_git_observer.py`: inert candidate metadata capture and raw object inspection
  through controller-authored Git configuration. Candidate filters, hooks, config
  includes and path indirections cannot execute on the controller. Unsupported
  metadata produces missing proof rather than a claimed clean commit.
- `approval_transport.py`: real pending and externally decided service actions;
  enforcement is attributed to the controller, not credited to Guard.
- `statistics.py`: fixed-template intervals and preregistered paired workflow-cluster
  analysis. Sparse or invariant outcomes do not imply certain zero-width intervals.
- Bundle integrity modules: data-only authenticated export with externally pinned
  anchors. Integrity verification remains distinct from reviewed verifier eligibility.

## Local validation and iteration

Normal repository pytest setup requires the generated native resources. Build the
matching pinned Rust runtime/compiler, harden generated executable permissions,
and run the existing command-projection verification script locally. Then run the
benchmark tests with `HOL_GUARD_NATIVE_BINARY` naming the exact build. Diagnostic
`--noconftest` foundation tests cannot replace real native integration proof.

Linux workspace containment also requires the unchanged
[Bubblewrap provisioning script](../../containment/install-bubblewrap.sh): its
SHA-pinned 0.11.0 build supports overlay mounts and uses a per-executable AppArmor
user-namespace profile. A test-owned synthetic home and loader directories must
be private; a group writable loader path correctly remains untrusted. Run the
replay fixture with a private process umask, without changing global trust rules.
The corrected unchanged replay module recorded **4,206 passes, 124 expected
failures and zero unexpected failures**. Its 4,330 testcase names match the
original failed run. See the retained reports and exact preconditions in
[PROGRESS.md](../../../PROGRESS.md#corrected-legacy-replay-evidence).
This local rerun is neither production CI nor complete workflow qualification.

Retain every failure. A product, harness, fixture, public-format or oracle change
starts a new development attempt from fresh state. Qualification freezes all of
those inputs. Keep agent application writes separate from product/policy repairs.

The qualification deployment still needs distinct controller/agent/grading-worker
identities, immutable source/build inputs, complete campaign execution, reviewed
verifier eligibility, a second isolated reproduction environment and documented
cleanup. Follow `PROGRESS.md` and `LOCAL_SCOPE.md` for actual status and boundaries.

## Provider and native prerequisite controls

An SDK request/start/end event does not establish actual inference. Developer
validity additionally requires independently reconciled successful provider
responses, known positive usage and complete controller cleanup. GET-only,
attempt-only, missing/zero usage and interrupted/error responses fail closed.
A real completed inference can still produce a failed legitimate task outcome.
Sampling evidence copies only actual declared finite numeric/null fields;
absent request defaults are not invented. Model weights, launch settings and
provider dependencies need their own explicit immutable public manifests.

Soft token/tool stops use the locked SDK's additive before-model gate. They stop
new model/tool admissions while an admitted tool can finish backend and mandatory
Post review. A hard deadline still aborts and explicitly records cancellation;
a missing Post remains missing evidence. Total tokens include input and cached
input. Threshold crossing can exceed the threshold by one complete response.

`python -m ci.gauntlet.benchmark.native_pytest_control --help` exposes a separate
mechanical prerequisite control. It has no model or SDK utility credit. It checks
actual pytest availability and requires the original normal Native Pre receipt
before routing any contained execution. Optional scoped native planning and
normal command inspection are diagnostics only; they cannot authorize a refused
command. `pytest-product.Containerfile` describes a separate locally built,
pinned prerequisite image using reviewed lockfile wheel bytes. Existing images
and product policy are not modified. Missing sandbox support leaves the lane
unsupported; removing namespace/proc protections or adding capabilities is not
a substitute for native conformance.

The proposed dedicated product-VM profile has separate
[isolation prerequisite controls](PRODUCT_VM_CONTROLS.md). They exercise actual
seccomp, readonly rootfs, enforcing AppArmor and task idmapping while preserving
old masked environments. They do not enable an executor or establish Guard/SDK,
workflow utility, independent review or qualification success.

[Inert runtime transfer](RUNTIME_TRANSFER.md) provides externally pinned bootstrap
bundles and a fresh readonly installed product input. Its actual native identity
diagnostic runs only after measured privilege/isolation setup; it does not replace
native containment or real harness Pre/Post conformance.

The [collector transport](VM_BRIDGE.md) authenticates ordered bounded records
between actual VM boot realms. Its real roundtrip and forged-authenticator controls
pass, with product/session operations still pending. It cannot promote an executor
or replace native, harness, utility or independent-review proof.


The [persistent-cell checkpoint](../../../LOCAL_PRODUCT_CELL_CHECKPOINT.md)
records shared product state, measured exec gates and actual lifecycle controls.
Native startup/loopback compatibility and SDK conformance remain unresolved; this
cell is not a supported workflow executor. The user volunteered for the final
independent review, whose exact-byte verdict remains pending.


The [private-loopback checkpoint](../../../LOCAL_PRODUCT_LOOPBACK_CHECKPOINT.md)
records actual installed containment effects after the OMP CLI receipt repair.
Post availability and benign blocking remain separate retained outcomes. No real
SDK/model workflow acceptance or supported-backend flag follows from these controls.


The [process/registry checkpoint](../../../LOCAL_VM_PRODUCT_PROCESS_CHECKPOINT.md)
records actor v2 retirement, bounded polling and actual authenticated two-VM
product capture. It establishes no SDK/workflow efficacy or supported-backend flag.


## Contained command presentation

The builtin bridge records the original Native-reviewed Bash input and the exact
relay input bound to the SDK session/call. Its `context` callback projects only
matching assistant tool-call arguments back to the original input for the next
provider request. The stored execution transcript, transport admission, actual
sink, output capture and mandatory Native Post remain unchanged. Candidate tool
results and details cannot create presentation bindings. Wrong session/call IDs
and changed transport arguments are not projected; replay is still reviewed.

The private presentation map has 512 entries and an 8 MiB serialized-byte bound.
Capacity refusals occur before a new Native review; they are harness resource
limits, not Guard prevention credit. Session shutdown clears bindings. A Root
model-relay diagnostic marker observes whether the internal relay-command prefix
reaches forwarded model messages. Synthetic SDK context controls establish hook
behavior without model/inference credit; actual model continuation needs its own
source-bound episode and independently counted usage.


Private-cell CI state must have a short canonical Root-owned path below `/home`
or `/opt`, with immutable ancestry, and be disjoint from the public asset root.
For example, assets rooted at `/opt` require separate private state such as
`/home/hg-001`. The runner rejects `/var`, `/srv` and `/tmp` private-cell state
before creation or resume: the executor preserves literal provider backing
paths and supports only `/home` and `/opt` destinations. The existing27-byte
compact-state limit, Root ownership, isolation and transport checks still apply.
