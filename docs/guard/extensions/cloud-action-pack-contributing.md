# Contribute a cloud action pack

A cloud action pack tells Guard what a provider's hosted actions do: the exact request each one sends, the arguments
a caller may set, the facts Guard decides on, and the response fields that come back. The format is described in
[Cloud Action Packs](../cloud-action-packs.md). This guide covers writing one and getting it reviewed.

You need the released CLI (`pipx install hol-guard`). Every step below runs offline through the native runtime that
ships in the wheel; none needs a Rust toolchain, an account or the provider's credentials.

## Trust ladder

An action moves up three levels. Each needs a separate review, and none is reached by a contribution alone.

| Level | What it means | How it is reached |
| --- | --- | --- |
| `portable-policy` | Hosted policy recognizes the action and can decide on it. Nothing runs it. | A binding beside an existing command source or MCP server contribution; see [Bind a hosted action](../extension-builder/HOSTED-ACTIONS.md). |
| `cloud-executable` | A host may run the action from a compiled pack artifact, on the pack's pinned hosts, with bounded output. | A merged pack in `contributions/cloud-actions/` whose fixtures pass, then a maintainer turning it on for hosted use. |
| `verified-publisher` | The pack's publisher is confirmed, and hosts trust its artifact through a signed catalog entry. | Maintainers only. A contributed pack sets `"verified": false`. |

A listing or catalog entry never grants execution: a workspace still opts in to each provider, and every risky call
still meets the workspace's policy.

## 1. Check what already exists

Start from the shipped packs in `contributions/cloud-actions/`. If the provider is there, extend its pack rather
than adding a second one. See what Guard decides today for a call you care about:

```sh
hol-guard command explain --cloud slack.chat.post_message \
  --arguments '{"channel": "C0123456789", "text": "Build is green."}'
```

## 2. Draft the pack

Draft from the provider's own OpenAPI 3 document or MCP `tools/list` result. Use the provider's published
description, pinned to a version, not a third-party copy.

```sh
hol-guard extensions generate --cloud --from openapi --input api.json --output pack.json --slug shop \
  --json > draft-notes.json
hol-guard extensions generate --cloud --from mcp --input tools.json --output pack.json --slug files \
  --host mcp.files.example --auth-mode oauth2 --json > draft-notes.json
```

`--json` writes the proposals and notes to standard output while the pack goes to `--output`. Keep
`draft-notes.json` out of the pull request. The command never overwrites `--output`; to draft again, choose a
new path.

The draft errs toward strict and is incomplete on purpose. Work through its output:

- `proposals`: each action's class and the evidence for it. Lower a class only when the provider's documentation
  shows the action is weaker, and say why in the pull request.
- `notes`: arguments and operations left out, and guesses such as response fields or a placeholder `api` scope.
  Replace every guess with the provider's documented value.
- `reversibility`: the draft proposes `permanent` for every action that is not a read. Change it only when the
  provider documents a restore path, such as a trash that keeps items for a stated period.
- Remote MCP tools keep their own argument names, including camelCase and hyphenated ones. An object argument, or
  an array of non-strings, becomes a `json` argument bounded by `maxBytes` (and `maxItems` for an array). When a
  provider does not document a tool's arguments, declare the ones you can bound and set `openArguments.maxBytes`
  to allow the rest within a total size; facts must then come from constants or declared arguments only. Neither
  `json` nor `openArguments` is accepted for an HTTP executor.
- Drop actions you do not intend to support. A smaller pack is easier to review and widen later.

## 3. Write fixtures

Every action needs at least one `safe` and one `risky` fixture. A safe fixture states the facts, the exact request
and the decision each preset gives. A risky fixture shows the call the action must refuse (`expect.error`) or the
fact that makes a preset stop it. Cover the risk families that apply to the provider: bulk and query-selected
changes, permanent deletes, sharing outside the organization, sending to many recipients, and money movement. Use
synthetic IDs and example hosts only: no real accounts, workspaces, people or tokens.

## 4. Validate and explain

```sh
hol-guard extensions validate --cloud pack.json
hol-guard command explain --cloud shop.remove_pet --pack pack.json --arguments '{"pet_id": 7}'
```

`validate` checks the pack and runs every fixture. `explain` prints the facts and preset decisions for one call;
run it for one risky action and its safe counterpart and paste both results into the pull request.

## 5. Open the pull request

Use the **Cloud action pack** template (`?template=cloud-action-pack.md`). Reviewers check that:

- every host, scope and argument bound matches the provider's documentation for the pinned version;
- no class, effect or reversibility understates what the action does;
- text from the provider is marked `untrusted` in responses;
- fixtures cover the risky families above and use synthetic data;
- for a change to an existing pack, the `diff` op's widening codes are listed and justified.

A merged pack changes nothing for any user until maintainers turn it on for hosted use.
