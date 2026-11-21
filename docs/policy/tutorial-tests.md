# Tutorial: test your policy

A policy is code that decides what agents may do, so give it tests. Tests live in the file under
`spec["x-hol.tests"]`; they travel with the policy and run the same everywhere.

## A test case

```yaml
spec:
  x-hol.tests:
    - id: test-block-event-stream
      name: "Installing event-stream"
      event:
        harness: codex
        artifact: pkg:npm/event-stream
      expect:
        effect: block
        ruleId: rule-package-firewall-compromised-packages
```

`event` is what happened. `expect.effect` is the decision you require. `expect.ruleId` is optional; add it
when you care which rule decides. Use `effect: default` to assert that nothing matches.

## Run them

```bash
hol-guard policy test guard-policy.yaml
```

```text
guard-policy.yaml: policy.package-firewall
  PASS      test-package-firewall-compromised-packages  Installing event-stream
  PASS      test-package-firewall-fallthrough-package  An unlisted package falls through to the defaults
2 passed, 0 failed, 2 total
```

A failing case prints the expected and actual decision and the command exits 1, so it can gate a CI job:

```bash
hol-guard policy test guard-policy.yaml --format json
```

## Keep them running while you edit

```bash
hol-guard policy test guard-policy.yaml --watch
```

## Ambiguous results

If your test names a rule but another rule ties with it on effect and specificity, the case is reported
`ambiguous`. Tighten a match so one rule clearly wins. See [precedence](precedence.md).

Next: [move from evaluate to enforce](tutorial-evaluate-to-enforce.md).
