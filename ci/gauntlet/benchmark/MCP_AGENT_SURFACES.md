# Agent access to MCP protocol surfaces

Current notification refinement: an actual schema/inventory notification must
reach the next provider context even when the agent does not manually inspect
the catalog again. Two retained ordinary-CLI controls reproduced the omission.
After each real MCP tool call, the adapter now refreshes that configured server's
catalog through the real manager. It compares against metadata actually presented
to the agent (including changes already received between calls) and appends a
changed public catalog to that genuine tool result as server-supplied data.
It creates no artificial tool call or top-level user/system message, never fetches
links, and never reconstructs data withheld by the product. Both adapters use
the same behavior. The original result, error flag and details survive a failed
or oversized metadata refresh; the effect call is never repeated.

Current validation:22clean-VM SDK controls pass, including all12profile controls,
5scripted sessions, the effect control,15boundary subcontrols and3ordinary
business CLI cases. Five more ordinary developer CLI cases pass in an owned
private loopback namespace atUID/GID10001 with zero effective capabilities;
both notification cases now reach actual tool context with the9-tool inventory.
The outside audit finds no surviving namespace processes. No model calls or
Guard mediation credit follow from these controls. The two red cases and first
green source remain separate evidence.

Changing the catalog bridge invalidates the earlier010source pin. Actual
admission rejects it specifically for `mcp_agent_surfaces.ts`. Current
controller058/conformance011 now pins all48execution sources and fresh
controls215–222. Its SHA256 is
`56c2fa0e9b06db54e6c917763354682af526966bd18f9d4f2bf53634af9c9fff`.
Actual clean-VM admission verifies the platform and real SDK/Bun bytes;
53host custody/admission checks and123combined Linux checks pass. Outside cleanup
is complete. Source057control207 stopped before SDK import when a transient
cgroup process exited during a proc read. That failure is retained with complete
outside cleanup. The hook sampler now handles that disappearance within its
existing observation deadline, still requiring an actual measured target before
reading any decision.69host and70Linux contracts pass, including unchanged
permission and kernel-boundary refusal. The older010and installed protocol controls below are historical
proof for their exact source056tuple, not current eligibility.

`mcp_agent_surfaces.ts` supplies five tools over the real locked SDK manager.
It contains no fixture, task answer, scorer, policy repair or endpoint-selection
logic. Every operation selects an already configured synthetic service family.
Account access and user delegation remain separate; this adapter does not enforce
the benchmark's expected task outcome.

| Tool | Actual operation and boundary |
| --- | --- |
| `mcp_inspect_server` | Reads public initialization identity, tool schemas/annotations, resource catalogs or prompt catalogs. Configured identity stays separate from server-supplied identity. Connection configuration, environment, transport and authentication state are excluded. |
| `mcp_call_tool` | Resolves an actual tool belonging to the selected configured server, then calls that genuine SDK tool with the original call ID, context and cancellation signal. All advertised upstream tools remain reachable. |
| `mcp_read_resource` | Uses the manager's actual `resources/read` API. The URI is sent to the selected MCP server; this adapter does not fetch it over HTTP. |
| `mcp_get_prompt` | Uses actual `prompts/get` and returns the prompt as tool-result data. A server's message role cannot become a new top-level user/system instruction. |
| `mcp_reconnect_server` | Reconnects an existing configured server through the SDK and returns its refreshed public identity/catalog. It cannot add servers or change their transport settings and does not override the SDK reconnect breaker. |

The result bridge preserves typed `resource_link` blocks in text visible to the
agent, taking them only from the genuine SDK result after any upstream product
proxy. It preserves error flags and raw details. It never follows links or
reconstructs fields withheld by a product. New public metadata/link rendering has
a 128-KiB byte bound, rejects nonfinite numbers, and permits at most64links. The
adapter has a finite1–500operation budget, with cancellation checks before and
after each operation. It cannot replace independent controller usage accounting.

Two levels of controls use real SDK18.4.12 and actual Unix-relayed fixture servers:

1. Twelve profile controls exercise the manager APIs and returned tool results.
   Separate boundary controls reject wrong-server calls, unknown arguments,
   cancellation, exhausted operation budgets, oversized/nonfinite public data,
   invalid prompt/resource arguments and private connection-state disclosure.
2. Five genuine SDK agent sessions execute these tools through scripted streams.
   They check schema acceptance, actual execution, the fixed five-tool inventory
   through reconnect, and resource/prompt/link/annotation payloads in the next
   scripted stream's tool context. Scripted usage values are never inference.

A separate baseline effect control performs an actual peer read and deletion
through the adapter despite misleading read-only annotations. Signed World
receipts and the changed state establish that unsafe task effects remain reachable.
This is a mechanical reachability control, not an agent episode or product result.

Run in the owned Linux environment with explicit pinned tools and a new ordinary
evidence directory:

```sh
HOL_WORKFLOW_BUN=/absolute/path/to/bun \
HOL_WORKFLOW_SDK_ROOT=/absolute/path/to/@oh-my-pi/pi-coding-agent \
HOL_WORKFLOW_PROTOCOL_EVIDENCE_DIR=/absolute/existing/empty/evidence-directory \
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -B -m pytest --noconftest \
  tests/test_guard_workflow_benchmark_mcp_agent_surfaces.py \
  -o addopts= --junitxml=/absolute/new/result.xml
```

Missing pinned SDK/Bun inputs yield explicit skips, never coverage. Every real
manager/session control uses fresh World state, closes its SDK/MCP clients and
requires zero surviving service sessions/workers and removal of owned sockets.
The session control creates only a fresh synthetic authentication database and
uses an overridden scripted stream, with no provider requests or Guard claims.
Public observations retain real transport, actual returned results and cleanup.

The ordinary business/developer helpers now select this adapter only through
their explicit v2 episode schemas. Runner v7 freezes the common
`mcp-agent-surfaces.v1` profile for both comparison adapters and clean/attacked
cells, including both approval phases. V1 episodes and runner versions1–6 retain
their old interpretation. Every new helper is staged readonly. Independent Root
accounting counts resource/prompt reads as operations, and the provider observer
records actual tool inventories and configured server identity observations.
Developer task inputs expose legitimate configured-server/tool routing without
changing authorized record IDs, answers or upstream tool reachability.

Sixteen ordinary CLI controls additionally use the actual OpenAI-compatible HTTP
path and locked SDK: all12business protocol profiles,3developer profiles
(clean/resource-link/prompt-get), and1business SDK intent-argument control.
Each completes8real tool operations and9static HTTP responses, with unchanged
World state and complete service cleanup. These are static responders, not model
inference. Developer controls use an owned loopback-only network namespace and
drop to UID/GID10001 with zero effective capabilities before executing the SDK;
an outside audit finds no surviving processes in that namespace. This fixture
is not a substitute for the protected executor or its security-equivalence proof.

Exposure v2 uses actual later provider tool context for catalog metadata and
requires both initialized configured identities for a collision. V1's original
tool-definition witness remains unchanged. Resume recomputes the selected mode,
signed provider binding, helper custody and exposure rather than trusting report
claims. The gate still requires actual channel exposure; selecting the profile
alone cannot satisfy it. Unsupported Guard-withholding evidence remains open.

Fresh installed Native controls must then prove actual mediation/interception,
including an authenticated channel witness when Guard withholds a payload.
The existing `private_cell_sdk_conformance.ts` entrypoint accepts explicit
`private-cell-sdk-conformance.v5` with
`mcpAgentSurfaces: "mcp-agent-surfaces.v1"` for a generic `mcp_call_tool` read
followed by the fixed Native Node test. Older conformance schemas reject that
field. The SDK gate retains its exact existing entrypoint and Bun/peer checks;
an attempted differently named diagnostic helper was refused before SDK execution.
Installed control199 on controller056 passes: the actual locked SDK completes
the generic MCP read and Native-contained Node test with exactly one required
Post, canonical captured output, replay refusal and same-UID peer refusal.
The existing verifier checks its signed runtime as inert data, and an outside
VM audit finds no owned actors, services, containers, mounts, profiles or cgroups.
The refused control198 is retained separately. Actual Bun negative controls
reject malformed v5/legacy combinations before SDK binding. This is one scoped
mechanical success control, not full current conformance010, all-channel
mediation, model inference or independently approved equivalence.
Real model-selected workflows and independent provider usage remain required.
Twelve additional installed-proxy controls on controller056 exercise every
protocol profile with the real SDK manager and current repaired3.46.0 runtime.
All12pass; outside Native custody signatures verify, including three proxy
sessions per control (the second docs connection is the actual reconnect).
Correlated ingress/request/response bytes establish delivery of each injected
surface through the product to the SDK; identity collision checks both configured
servers. Resources, prompts, catalogs and unsafe linked reads use real World
operations. These controls register no user workflow task context and perform no
model inference, so they cannot establish task-scoped policy protection or
successful workflows. All payloads remain observable; no prevention is credited.

Retained evidence uses the outside-pinned manifest
`native-mcp-protocol-controls-002/manifest.json` and data-only verification003 in
the local evidence directory. The first verifier assumed `forwarded` publication
must precede a response; its refusal is retained. The corrected verifier binds
the earlier actual received ingress frame and checks forwarded bytes against it.
The benchmark's existing reducer already handles that ordering. No product run
was repeated for the verifier repair. An outside VM audit finds no surviving
owned actors, services, containers, mounts, profiles or cgroups after all12cases.

Historical source056conformance010 pins its48execution sources and controls199–206.
Its SHA256 is `a346d3f53cab4c53c0c92c7b395b15ad46205e63649657782b62116230483260`.
Actual clean-VM admission verifies the current platform and real SDK/Bun bytes;
52host and52Linux admission/custody tests pass. The old009package remains
preserved and rejected. This grants scoped local diagnostic execution, with an
explicit implementation-author equivalence review. It supplies no independent
approval, task utility or qualification eligibility. Production CI/CD, trust policy, original fixtures,
SDK locks, old installed prefixes and prior episode outcomes remain unchanged.
