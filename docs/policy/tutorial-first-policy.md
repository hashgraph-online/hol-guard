# Tutorial: your first policy

You will write a policy file, check it, and see it decide an event. It takes about five minutes.

## 1. Start from a starter

```bash
hol-guard policy init --starter package-firewall
```

This writes `guard-policy.yaml` with one rule that blocks known compromised npm packages, plus two example
tests. If you use an editor with YAML language-server support, the first line of the file points it at the
schema, so it completes fields and underlines mistakes as you type.

## 2. Validate it

```bash
hol-guard policy validate guard-policy.yaml
```

A clean file prints `valid`. Introduce a typo, such as `effct: block`, and run it again. You get a
diagnostic with the line and column of the problem. Run `hol-guard policy validate guard-policy.yaml
--format json` for the machine-readable form.

## 3. Ask what it would decide

```bash
hol-guard policy check guard-policy.yaml --event '{"harness":"codex","artifact":"pkg:npm/event-stream"}'
```

The Decision is `block`, from `rule-package-firewall-compromised-packages`. Try an unlisted package such as
`pkg:npm/left-pad`. No rule matches, so the effect is `default` and your `defaults` section decides.

For shell commands, use a command rule and `--command "docker ps"`.

## 4. Put it on the device

```bash
hol-guard policy diff guard-policy.yaml
hol-guard policy import guard-policy.yaml --replace --apply
```

`diff` shows what would change on this device. `import --replace` without `--apply` prints the same diff as a dry run. Add `--apply` to confirm and install it. Use `--merge` to add rules and keep the ones already on the device.

Next: [add tests](tutorial-tests.md).
