# Extension `x-hol.tests`

Status: registered (alpha). Owner: HOL Guard maintainers.

`x-hol.tests` stores example events with a policy document, together with the decision each event must produce. Editors and CI run them before a policy is applied. The extension follows the registration rules in [`compatibility.md`](../compatibility.md#extension-registration).

## 1. Key and location

- Key: `x-hol.tests`.
- Allowed location: the `spec` object only. A reader that finds the key anywhere else treats it as an ordinary unregistered extension.
- Value schema: [`x-hol.tests.schema.json`](x-hol.tests.schema.json). Up to 256 tests.

```yaml
spec:
  defaults:
    mode: enforce
  rules:
    - id: block-unknown-mcp
      enabled: true
      effect: block
      match:
        tools: [mcp]
      lifetime:
        mode: permanent
      provenance:
        source: builder
        createdAt: 2026-10-14T00:00:00Z
  x-hol.tests:
    - id: mcp-is-blocked
      name: MCP servers are blocked for every agent
      event:
        harness: codex
        tool: mcp
      expect:
        effect: block
        ruleId: block-unknown-mcp
```

## 2. Semantics

Each test describes one request and the expected outcome:

- `event.harness` is required. `event.artifact`, `event.tool`, `event.publisher` and `event.workspace` are optional and correspond to the `artifacts`, `tools`, `publishers` and `workspaces` matchers. `event.tool` uses the same family names the compiler accepts for `match.tools`; `shell` is an alias of `tool-action`. An event names either an artifact or a tool, not both: a tool event is looked up as the artifact `family:<family>`, the same key the compiler writes for `match.tools`.
- `event.at` sets the evaluation clock so that `lifetime.mode: until` rules can be tested. Without it, a runner uses the current time.
- `expect.effect` is `allow`, `block`, or `default`. `default` means that no rule in the document applies, so the outcome falls through to `spec.defaults` and the client's own local rows.
- `expect.ruleId`, when present, must equal the id of the rule that decided the request.

A runner evaluates the document alone. It compiles the rules with the normative compiler and resolves each event the way the local enforcement lookup does. It does not consult local approvals, one-shot grants, or rows from other documents. A test therefore checks what this document says, not what one particular device will decide.

The outcome is defined by the compiled rows, not by the rule text. A runner finds the matching rows and then picks one:

1. **Matching.** Every row checks the agent, and a row for `*` matches any agent. Beyond that, an `artifact`-scope row checks only the artifact, a `publisher`-scope row checks only the publisher, and a `workspace`, `harness` or `global` row also accepts its artifact or tool family when one is set. A row whose `expires_at` is at or before the evaluation time does not match.
2. **Exact-only families.** A `harness`- or `global`-scope row for the `file-read`, `mcp-tool`, `package-request`, `prompt` or `tool-action` family applies only to one exact approved action, which a policy document cannot express. Such a row never matches a test event. In practice, a `tools` rule for one of these families takes effect only when it also names a workspace.
3. **Selection.** A matching `block` row beats every matching `allow` row, whatever its scope. Among rows with the same effect, the more specific row wins. Specificity compares the scope first (`artifact`, `workspace`, `publisher`, `harness`, `global`), then prefers a row for the event's own agent over a `*` row, and then prefers a row that sets, in this order, an artifact hash, an artifact, a workspace and a publisher.
4. **Ties.** All rows from one document share an update time. If matching rows from different rules have the same effect and the same specificity, the effect is known but the deciding rule is not. A runner then checks only `expect.effect`, and it reports `x_hol_tests_ambiguous` for a test that also sets `expect.ruleId`.

The selection step records what the enforcement lookup does today. It is stricter than the most-specific-first order in [`semantics.md`](../semantics.md#current-runtime-precedence-frozen): an allow in a document never overrides a block from the same document. Tests follow the enforcement behaviour so that a passing test matches a real decision.

## 3. Failure behaviour

- An enforcing reader must ignore `x-hol.tests` for matching, effect, lifetime, authority and precedence. Two documents that differ only in `x-hol.tests` compile to identical rows.
- Like every extension, the value takes part in the canonical document digest and the bundle signature, and it must not be dropped before hashing or forwarding.
- A runner that finds a value that does not match the extension schema reports `x_hol_tests_invalid` with the JSON path, and it runs no tests from that document.
- A failing test does not make the document invalid. Publishing tools may refuse to publish while tests fail, but the enforcement path never consults them.

## 4. Security and privacy

Test events are written by the policy author and stored in the document. They must not contain secrets, credentials or raw command text. The schema accepts only bounded identifiers and selector strings, and has no free-form command or payload field. Any tool that builds a test from a recorded decision must copy only the selector fields listed above.

## 5. Fixtures and consumers

- Fixtures: [`fixtures/valid/with-tests.yaml`](../fixtures/valid/with-tests.yaml) and [`fixtures/valid/enforceable-scopes.yaml`](../fixtures/valid/enforceable-scopes.yaml). The second covers tool families inside a workspace, agent-specific over all-agent rules, publisher rules, a block winning over a more specific allow, expiry and disabled rules.
- Compiled rows: [`fixtures/compiled/rows.json`](../fixtures/compiled/rows.json) records the rows, or the compiler error, for every valid fixture, so another implementation of the compiler can check itself byte for byte.
- Conformance: `tests/test_policy_document_extension_tests.py` checks that each extension value matches the schema, that removing the extension changes the digest but leaves the compiled rows unchanged, that the compiled rows match `rows.json`, and that every test in the fixtures produces its expected effect and rule when the compiled rows are imported into a local store and resolved by the runtime lookup.
- First consumer: the Guard Cloud policy editor, which runs these tests before publishing. A local `hol-guard policy test` command is planned.

## 6. Collisions and retirement

The `x-hol.` prefix is reserved for HOL Guard maintainers. If a later core API version adds a native tests field, that version will define how `x-hol.tests` is migrated. v1alpha1 readers keep accepting the extension for the whole deprecation window that [`compatibility.md`](../compatibility.md#version-boundary) requires.
