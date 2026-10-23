# Local provider quota

`provider_quota.py` reserves the exact tokenized prompt plus the requested output
limit **before generation**. Settlement charges the full prompt, including cached
input, plus every producer-emitted response token. Its cap covers all requests
using that counter, including failed requests and subsequent process starts.
This complements the campaign's observed-response stop threshold; that threshold
alone is not a hard provider budget.

For a smaller milestone within an existing lifetime allowance, the trusted
provider may pin `maximum_accounted_tokens` in its deployment binding and pass
it to `install_mlx_quota`. `reserve` checks the smaller ceiling under the same
journal lock, including all historical charges and the complete next prompt and
output reservation. This neither resets accounting nor changes the lifetime
authorization. The setting is provider-controlled, not a model request option.
Status still reports the lifetime allowance; retain the externally pinned
deployment binding to establish the stricter milestone ceiling.

The trusted provider creates one private counter, then retains its externally
pinned configuration digest across starts. Files are private, exclusively owned,
single-link regular files under protected ancestry. Admission and settlement use
a process-shared lock and fsynced hash-chained journal. A missing file, broken
chain, overlapping request, unresolved reservation or uncertain usage prevents
further inference. Unknown usage retains the full reservation. There is no reset,
automatic repair or implicit refund operation. A fresh counter is a new allowance
and must never be used to evade an existing goal-wide cap.

The journal is operational accounting within trusted provider authority. It does
not resist a malicious provider owner restoring an older complete directory, and
its hash chain is not an external signature or verifier trust grant. Independent
before/after observations and immutable evidence remain necessary.

`mlx_quota_adapter.py` supplies a version-specific seam for the hash-pinned MLX-LM
single-request producer. It does not import MLX itself. It uses the original
tokenizer and generator, with prompt/decode concurrency one, no batching, draft
model or distributed generation. Tokenization happens once; the exact reserved
token IDs must reach the producer. It observes producer output rather than HTTP
client consumption, and delays the completion sentinel until durable settlement.
Producer errors, altered inputs and output overflow retain the reservation and
halt admission. A failed durable halt also stops admission in that process.

Only the trusted controller may access quota status. It must not expose a new
agent proxy destination. The caller must separately pin the actual model files,
runtime, original server source, adapter, launch configuration and allowance.
Installing this seam on an unverified endpoint does not establish those facts.
This module is not yet integrated into the portable campaign interface, and the
MLX development server is not a production service recommendation.

## Explicit lifetime ceiling increases

After new external authorization, the trusted controller can call
`extend_allowance(total_tokens=..., authorization_digest=...,
expected_journal_hash=...)`. `total_tokens` is the new **lifetime total**, including
all previous charges. Retain the exact authorization document separately and
pin its canonical JSON digest. This API does not itself establish user consent.

The operation requires the exact observed journal tip, settled known usage and a
strictly increasing ceiling. It appends one fsynced hash-chained event without
changing the original config, request limit, model identity or historical rows.
Replayed authorizations, stale observations, pending usage and halted counters
are rejected. A ceiling increase cannot refund prior charges or clear a halt.

The returned quota instance pins `expected_allowance_digest`; future launches
must supply it alongside the original config digest. Old or incorrect pins fail
closed, including after truncation of the extension event. Deployment bindings,
public status and new frozen campaigns must declare this changed allowance.
Keep previous frozen inputs and evidence intact. There is still no reset API.

All four CI runner config versions accept the optional `quota_allowance_digest`
provider pin. When present, preflight requires the exact digest in both adapter
metadata and quota status. Missing or changed values fail admission. Original
configs without the field retain their exact original status shape and reject
extended counters. A new deployment binding is required in either case.

## Malformed tool-output compatibility

`mlx_tool_formatter_compat.py` is an optional, separately pinned deployment
adapter for the same original server bytes. Its formatter rejects a parser
`SyntaxError` through the server's existing per-call `ValueError` path, after a
trusted observer durably retains the exact bounded invalid text and its digest.
It never repairs arguments or supplies an executable replacement. Other parser
failures keep their original behavior; retention faults escape that rejection
path and must remain failures. Valid calls, mixed-call ordering and streaming
indexes stay under the original formatter.

This adapter does not change tokenization, generation, model/template identity,
quota configuration, producer accounting or installed MLX files. It requires a
new deployment binding, source pin, declared formatting profile and fresh frozen
workflow inputs. Preserve earlier parser failures and their costs. Never pool
results across formatting profiles without identifying that change. Installing
the adapter is neither model inference nor successful workflow evidence.

The installed original Qwen parser/formatter reproduced the SyntaxError offline.
An installed-class control then checked exact invalid-text retention, rejection,
unchanged valid objects, mixed streaming indexes and escaping retention failures.
The owned provider quota was identical before and after; zero inference occurred.
These controls supplement the wrapper's unit contracts. A fresh owned process
and real HTTP/usage proof remain required before a changed deployment is used.

## Nullable schema parser profile, 2026-10-15

The optional v2 formatter profile pins the installed Qwen XML parser as well as
the server. The locked SDK converts optional nullable types into JSON Schema
type arrays such as `["string", "null"]`. The original parser treats this array
as an unknown type and applies `ast.literal_eval` to a valid unquoted XML string.
An offline capture of the actual SDK wire schema and the installed parser
reproduce rejection of valid fixture arguments without model inference.

`nullable_parser_sha256` enables `qwen-xml-nullable-type-view.v2`. It gives the
parser a detached schema view resolving only one recognized non-null type plus
null. The original parser already handles literal null before type conversion.
Original tool schemas, constraints, model input, argument text and MCP validation
remain unchanged. Ambiguous unions and nested data are not reinterpreted. This
is a parser/schema interoperability repair, not argument reconstruction.

The view is internal parser configuration, never a validation schema. Nullable
booleans use the original parser's JSON/literal decoding branch, avoiding its
permissive string-to-false converter. `true`, `false` and `null` decode as written;
malformed words are rejected. A quoted `"false"` remains a string and fails the
original boolean schema. Earlier v1 view deployments and evidence remain retained.

This profile retains exact bounded text for both `SyntaxError` and `ValueError`
rejections. Original `ValueError` objects still take the existing rejection path;
observer failures escape as failures. Unrelated engine errors remain unchanged.
The default v1 profile keeps its earlier behavior. New metadata, helper source,
parser pin, deployment binding and frozen campaigns are mandatory before live use.
Offline controls supply no task, safety, qualification or independent review credit.

## Matching local controls, 2026-10-14

The owned Qwen 3.6 provider used a persistent 3,000,000-token allowance. One actual
completion returned `READY.` with 15 prompt and 3 completion tokens. Its durable
counter reported exactly 18 known/charged tokens and no pending reservation. A
request with a 3,000,000-token output limit was rejected before admission; the
entire quota status remained unchanged. The owned provider was then stopped and
its port closed. The operator's separate server remained untouched.

Public anchors, signed startup/control records and cleanup are retained outside
the repository under `../local-evidence-20261014/quota-live-control-001` and
`../local-model-provider-20261014/startup-001`. These are mechanical budget
controls, not successful workflow episodes, Guard execution proof, qualification
or independent review. The remaining allowance is **2,999,982 tokens**; subsequent
work must reuse the same persistent counter, not start at three million again.
