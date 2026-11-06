# Tutorial: from evaluate to enforce

Roll a policy out in steps so a mistake costs you a warning instead of a blocked agent.

## 1. Start in observe mode

Set the defaults mode to `observe` in `guard-policy.yaml`:

```yaml
spec:
  defaults:
    mode: observe
```

The policy modes are `observe`, `prompt` and `enforce`. In `observe` mode Guard records decisions without stopping the agent. Import it:

```bash
hol-guard policy test guard-policy.yaml
hol-guard policy import guard-policy.yaml --replace --apply
```

## 2. Watch what it would have done

```bash
hol-guard policy status
hol-guard history explain <receiptId>
hol-guard policy explain <decisionId>
```

`history explain` shows the receipt and the rule that decides it, in `matched_rule`. `policy explain
<decisionId>` replays the receipt against the Live policy and lists every candidate rule. If a rule would
have blocked something you wanted, fix the match, add a test for that event, and import again.

## 3. Switch to enforce

Change the mode:

```yaml
spec:
  defaults:
    mode: enforce
```

```bash
hol-guard policy diff guard-policy.yaml
hol-guard policy import guard-policy.yaml --replace --apply
hol-guard policy status
```

`diff` shows the one-line change. After import, `status` shows the Live version and mode. If a device
refused the policy, the rejection reason is shown there.

## Going back

`hol-guard policy export --output previous.yaml` before a change keeps a copy you can `import` to return to it.
