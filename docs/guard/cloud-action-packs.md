# Cloud Action Packs

A cloud action pack describes one provider's hosted actions as data. It says which hosts requests may reach, how
the provider signs in, and for each action: the exact request, the arguments a caller may set and their bounds, the
facts Guard derives from those arguments, the response fields that come back, and the limits a host must enforce.

Packs live in `contributions/cloud-actions/`. The schema is
[`contracts/extensions/cloud-action-pack.v1.schema.json`](../../contracts/extensions/cloud-action-pack.v1.schema.json)
(`guard.cloud-action-pack.v1`). The Rust tooling in `guard-command` validates, tests, compiles, renders and diffs
them. Nothing in it sends a request.

## What a pack cannot say

The language is small on purpose, so a pack from a third party can be reviewed as data:

- No expressions, scripts or loops. A body is built from constants, whole arguments, and one bounded copy of an
  array argument (`each`).
- No URL outside the declared `hosts`. The scheme is always `https`, the host is fixed per action, and an argument
  can fill only whole path segments.
- No credential headers. Header names are lowercase constants. Names containing `auth`, `cookie`, `token`,
  `secret`, `key`, `session`, `password` or `credential`, and framing headers such as `host`, `content-length`,
  `forwarded`, `proxy-*` and `x-forwarded-*`, are refused. `content-type` is refused too, because rendering
  always sets it for the JSON body. The host adds the credential and the `user-agent`.
- No unbounded input. Every string has a `maxLength`, every integer a range, every array an item limit. Patterns
  must start with `^` and end with `$`, compile on the linear-time `regex` engine within 1 MiB, and are matched
  against the whole value, so an alternation such as `^a|b$` cannot match a value that only starts with `a`.
- No effect weaker than the facts. An action whose fact class is `send` cannot declare `effect: read`.

## Facts

Each action names a fact class and may add extractors for object, reversibility, scope, counts, audience,
recipient domains, environment and sensitivity. An extractor is a constant, a boolean flag, the length of an array
argument, a bounded integer argument, or the domains of address arguments. Extraction is total: a value that is
missing, malformed or out of range becomes `unknown`, never a guess. The facts feed the version 2 evaluator in
[Cloud Action Evaluator](cloud-action-evaluator.md).

## Rendering and projection

Rendering checks every argument against its rule, then builds the request. Path segments and query values are
percent-encoded. A path segment that is empty, `.` or `..` (including full-width and ideographic full stops) or
that contains a control character is refused, as is a query value with a control character. Bodies are JSON.

Projection reads a response the host already received. It refuses a body over `response.maxBytes`, refuses
duplicate keys, keeps only the declared fields, refuses a list longer than its `maxItems`, and labels fields that
carry provider text (`untrusted: true`) so the caller can treat them as data, not instructions.

## Fixtures

Every action in a source pack carries at least one `safe` and one `risky` fixture. A fixture states the arguments
and what must happen: the error code, the facts, the exact rendered request, or the projection of a recorded
response. Compilation runs the fixtures and stops on any failure.

## Artifacts and digests

`compile` validates the pack, runs its fixtures, strips them, and returns a
`guard.cloud-action-pack-artifact.v1` artifact with three SHA-256 digests over canonical JSON:

- `packDigest`: the whole compiled pack.
- `factsProgramDigest`: each action's id, fact extractors and effect, so a change to what Guard decides on is
  visible apart from request or wording changes.
- `artifactDigest`: everything else in the artifact: schema, compiler version, provider, the two digests above
  and the compiled pack.

Loading an artifact recomputes all three and refuses any mismatch, so an edited artifact does not load. Key order
does not change a digest.

## Widening

`diff` compares two packs or artifacts for the same provider and lists each change with a code. A change is
widening when it lets a pack do more than before: a new host, scope or action, a looser argument, a weaker effect,
a dropped capability, a new response field, a removed untrusted label, looser limits, a changed executor or
link, or any changed fact extractor. Any edit to a pattern or forbidden rule counts as widening, because whether a new pattern accepts less
cannot be decided in general. A widening pack version needs fresh review.

## Running the tools

```
guard-cloud-action pack
hol-guard-runtime cloud-action pack
```

Both read one JSON request per line on standard input and write one JSON result per line:

| `op` | Input | Result |
|---|---|---|
| `validate` | `pack` | `actions` count |
| `test` | `pack` | fixture `report` |
| `compile` | `pack` | `artifact` |
| `diff` | `old`, `new` (pack or artifact) | `diff` |
| `render` | `pack` or `artifact`, `actionId`, `arguments` | `request` |
| `extract` | `pack` or `artifact`, `actionId`, `arguments` | `facts` |
| `project` | `pack` or `artifact`, `actionId`, `response` | `projection` |

A result is `{"ok": true, ...}` or `{"ok": false, "error": {"code": ..., "pointer" | "argument": ...}}`.

## Shipped packs

`github.json`, `notion.json` and `slack.json` cover the seven hosted actions that exist today. Each action links to
its hosted tool name. Known limits of the format, compared with hand-written adapters:

- An argument cannot be normalized before use (for example, removing dashes from an id). The pattern accepts only
  the canonical form.
- Paging values that a provider returns in a response header (such as a `Link` header) cannot be projected.
- A list longer than its `maxItems` is refused rather than truncated.
