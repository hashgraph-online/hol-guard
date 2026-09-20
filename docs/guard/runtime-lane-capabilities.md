# Runtime lane descriptions

`hol-guard policy capabilities --json` describes what this source can represent.
It does not establish that a running consumer negotiated, installed, or enforced a
policy. The additive `runtime_lanes` object identifies that distinction explicitly.

Use `hol-guard policy validate policy.yaml --runtime-lane generic-local-sqlite --json`
to check every active rule against the actual local row compiler. A successful
check means static representation succeeded; its activation evidence remains
`not_evaluated`. The full document is also compiled so that total selector fanout
cannot bypass the document-wide limit.

| Lane | Current interpretation |
| --- | --- |
| `generic-local-sqlite` | Every supplied selector must survive actual row compilation. The producer still has to supply the corresponding authenticated request context. |
| `native-intrinsic` | Default intrinsic protection does not establish support for scoped policy rules. |
| `native-scoped-v4` | Staged representation exists for bounded request shapes, but the static validator refuses activation until an authenticated ready consumer is proven. |

`exactCommand` is an additional AND predicate. It requires a concrete artifact
selector and can retain harness and workspace restrictions. It never substitutes
for those restrictions or turns a global or family selector into an exact
approval. Unsupported combinations receive rule-specific diagnostics. Disabled
and inert ignore rules do not become active enforcement rows.

The staged native descriptor distinguishes bounded benign shell commands,
destination-only SSH, one existing nonsensitive workspace file, and an MCP call
with empty arguments. Those source shapes are not blanket shell, file, or MCP
support. Content-dependent authority, native approval context, and managed
authority remain separately unsupported in this descriptor. A retained network-policy extension also requires
a separate authenticated consumer and cannot validate through these lanes. The
trusted CLI schema currently rejects that extension before evaluation. Intrinsic protection
must remain intact.

Command expressions can be exercised by `policy evaluate-command`. That CLI
evaluator does not establish an authenticated policy application route.
The CLI refuses additional selectors, expiry, local context, and managed authority
instead of evaluating a broader projection. The trusted document schema supports
allow, review, and block effects for this evaluator; internal helpers do not add
schema effects. Expression-bearing policy therefore fails the generic runtime-lane check even
when standalone evaluation succeeds.

The source observation has `selectedLane: null` and `readiness: unavailable`.
Installed version, source files, an oracle setting, and a successful static check
must never turn it into a ready observation. An actual producer and negotiated
consumer observation is separate work; this descriptor does not advertise new
runtime capabilities.
