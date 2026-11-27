# Contribute a browser driver profile

A browser driver profile tells Guard which MCP server, package or harness tool drives a browser, and
maps each of that driver's tools to one of Guard's closed browser verbs (`Navigate`, `Click`, `Type`,
`Evaluate` and so on). Guard uses the profile to show a readable browser review card and to scope
approvals to an origin instead of a raw argument hash. File rules, trust bindings and packaging are
in [`contributions/browser-drivers/README.md`](../../../contributions/browser-drivers/README.md). This
guide covers writing a profile and getting it reviewed.

You need the released CLI (`pipx install hol-guard`). Every step below runs offline through the
native runtime that ships in the wheel; none needs a Rust toolchain, a browser or the driver itself.

## What a profile can and cannot do

A profile is evidence about a driver. It never allows a call, lowers a review or adds a verb.

- The verb decides the intent. A profile cannot name an intent, so mapping a tool to `Read` instead
  of `Evaluate` is the claim reviewers check most closely.
- A tool mapped to `Other`, and any tool the profile does not list, is reviewed as privileged.
- A contributed profile cannot claim generic names such as `browser`, `chrome`, `playwright`, shells
  or interpreters, and its `publisher.verified` stays `false`. Maintainers mark publishers verified.
- A shipped first-party profile wins over a contributed one for the same server, package or tool
  namespace.
- A merged profile is bound as `external`, so it stays off until a user turns it on.

## 1. Check what already exists

Start from the profiles in `contributions/browser-drivers/`. If the driver is there, extend its
profile rather than adding a second one. See how Guard classifies a call today:

```sh
hol-guard browser explain --driver browser.playwright-mcp --tool browser_navigate \
  --args '{"url": "https://shop.example/cart"}'
```

## 2. Draft the profile

Export the driver's MCP `tools/list` result from a pinned release, then draft from it:

```sh
hol-guard extensions generate --browser --from mcp --input tools.json \
  --slug example-pilot --server example-pilot --name 'Example Pilot' \
  --publisher-name 'Example Maintainer' --output browser.example-pilot.json --json > draft-notes.json
```

`--json` writes the proposals and notes to standard output while the profile goes to `--output` and
draft benign gate rows go to `browser.example-pilot.gate-rows.json` (or `--gate-output`).
Keep `draft-notes.json` out of the pull request. The command never overwrites `--output`; to draft
again, choose a new path. See
[Draft a browser driver profile](../extension-builder/README.md#draft-a-browser-driver-profile) for
the input formats.

The draft errs toward strict and is incomplete on purpose. Work through its output:

- `proposals`: each tool's verb and the name token that chose it. Read the driver's documentation
  for every tool. Raise a verb whenever the tool can do more than its name says, for example a
  `click` tool that also accepts a script. Lower one only when the documentation shows the tool is
  weaker, and say why in the pull request.
- `notes`: tools mapped to `Other` (`verb_unknown`), tools skipped because their names are not
  lowercase slugs, and the `unknown` profile mode. Map each `Other` tool when its behavior is
  documented; leave it `Other` when it is not.
- Pointers: the draft reads `url`, `element`, `text`, `script` and `file` arguments from common
  input schema property names. Add any the driver names differently, and use a `discriminator` with
  `cases` for a tool whose action argument picks the operation.
- `profileMode`: set `default` to `isolated`, `dedicated` or `shared`, and list the launch flags that
  reveal the mode, only when the driver documents how it starts its browser. Leave `unknown`
  otherwise.
- `match`: add the npm package in `packages` and set `referenceUrls` and `referenceVersion` to the
  release you reviewed.

## 3. Add regression cases

Every changed tool needs a row in the benign false-positive gate, and every quiet case a matching
gate row. Start from the drafted gate rows: each tool has a protect row (`neg-` id) and its benign
`allow` pair. Replace the placeholder arguments with a realistic call on a synthetic page, then add
the rows to `tests/fixtures/benign_false_positive_gate.json`, mid-list. See "Browser protection" in [`ci/gauntlet/README.md`](../../../ci/gauntlet/README.md).
Use synthetic origins and data only: no real sites, accounts, people or tokens.

## 4. Validate

```sh
hol-guard extensions validate --browser browser.example-pilot.json \
  --gate-rows tests/fixtures/benign_false_positive_gate.json
python scripts/refresh_extension_artifacts.py --trust-only
```

`validate --browser` compiles the profile with the rules Guard applies to a contributed profile at
runtime and lists the verb counts, the `Other` tools and any shipped profile that already matches
the same identity. It fails when a tool has no gate row, a row names an unmapped tool, or a protect
row has no benign pair. The refresh script writes the profile's `external` trust binding; include it in
the pull request.

## 5. Test with an installed Guard

Connect the released Guard to the agent you are using, for example `hol-guard install claude-code`,
so the calls you make while authoring are reviewed the way a user's would be. Never approve your
own Guard requests; show the approval link to the person you are working for. Run
`hol-guard browser explain` for one privileged tool and one routine tool of the closest shipped
driver, and record the version and both results in the pull request.

After the profile ships in a release and a user turns it on, drive one routine page and one
privileged call through the agent against a disposable local page. Never point the privileged case
at a real account or shared site.

## 6. Open the pull request

Use the **Browser driver profile** template (`?template=browser-driver.md`). Reviewers check that:

- every tool's verb matches the driver's documentation for the pinned version, and no verb
  understates what the tool can do;
- the match lists name only this driver and claim no generic names;
- `publisher.verified` is `false` and the trust binding is `external`;
- gate rows and Gauntlet cases cover every changed tool and use synthetic data;
- for a change to an existing profile, any verb that moved to a weaker intent is justified.

A merged profile changes nothing for any user until they turn it on.
