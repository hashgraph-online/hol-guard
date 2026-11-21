# Repository guidance for agents

## Public GitHub surface security

This repository is public. Treat every pull-request title, description, comment, review reply,
workflow note, and linked artifact as an externally visible security boundary.

- Before creating or editing any public PR text or comment, inspect the complete outgoing content,
  including Markdown links, URLs, code blocks, quoted logs, generated summaries, and bot prompts.
- Never publish private or identifying details. This includes private hostnames, IP addresses,
  machine names, SSH or VPN routes, Tailscale identities, usernames, home-directory paths, local
  checkout paths, browser-session or approval-center state, credentials, keys, tokens, request IDs,
  internal environment names, deployment topology, or details that reveal how to reach private
  systems. Use generic terms such as “live-agent validation was unavailable” when a limitation must
  be recorded.
- Describe only the target-repository change and reproducible public validation. Do not paste agent
  transcripts, shell history, private issue context, internal handoff notes, or cross-repository
  details into GitHub.
- Before every public mutation, run a focused scan over the exact outgoing text for local paths,
  home directories, IP or hostname patterns, SSH/Tailscale/VPN terms, secret or credential names,
  and internal infrastructure keywords. Rewrite matches before publishing.
- If a disclosure is found, remove the affected comment or review reply and sanitize the current PR
  body. Inspect the PR's edit history and use GitHub's revision-deletion control for every affected
  revision. Editing the current body alone does not remove an older public revision.
- After cleanup, re-read the public PR body, comments, review threads, and retained edit history.
  Report any inaccessible revision or uneditable comment instead of claiming complete removal.
- Never use a public cleanup reply to repeat the sensitive detail. Keep the cleanup itself generic.

### Synthetic names in fixtures, tests and public text

Test fixtures, Gauntlet cases, unit tests, commit messages and pull-request text must invent their
own names. Never copy a directory layout, route path, repository name, product name or host name
out of a private checkout, an approval record or a local session, even when it only illustrates a
point. Use plainly synthetic names such as `app/items/[slug]`, `app/(group)/overview` or
`example-org/storefront-portal`, which say nothing about a real project.

## Command extension contributions

Coding agents author most command extension pull requests. Fixture tests prove matcher behavior, but
they do not show how an extension behaves in the agent session it is meant to protect. Test against
an installed HOL Guard as well as the source checkout:

1. Check for the released CLI with `hol-guard --version`. If it is missing, tell the user that the
   extension workflow uses it and ask before installing it with `pipx install hol-guard`. The
   released CLI includes the Extension Builder, so generating and validating a review kit needs no
   Rust toolchain.
2. With the user's agreement, connect Guard to the agent you are running in, for example
   `hol-guard install claude-code`, `hol-guard install codex`, or `hol-guard install cursor`. The
   shell, file, and MCP actions you take while authoring are then reviewed the way an end user's
   would be. Never approve your own Guard requests; show the approval link to the user.
3. Run `hol-guard command explain '<command>'` for at least one destructive case and one safe
   counterpart from your fixture. The result shows what the shipped catalog already covers, so you
   neither duplicate an existing extension nor miss an overlap.
4. Generate and validate the kit with `hol-guard extensions generate` and
   `hol-guard extensions validate`, then follow the
   [extension contribution guide](docs/guard/extensions/contributing.md).
5. Complete the **Installed Guard check** section of the Command extension pull-request template
   with the Guard version, the agent, and the `command explain` results. Remove local paths,
   secrets, and private command history first.

After the extension ships in a release, follow
[Test with an installed Guard](docs/guard/extensions/contributing.md#test-with-an-installed-guard)
to turn it on and run its destructive and safe cases through the agent. Use only disposable
targets for the destructive case and never point it at real data or shared infrastructure.

## Cloud action pack contributions

Packs in `contributions/cloud-actions/` follow
[Contribute a cloud action pack](docs/guard/extensions/cloud-action-pack-contributing.md). Draft with
`hol-guard extensions generate --cloud`, check with `hol-guard extensions validate --cloud` and
`hol-guard command explain --cloud`, and fill in the **Cloud action pack** pull-request template. Leave
`provider.publisher.verified` as `false`, and use synthetic identifiers in every fixture.

## Repository review guidance

### File-size review policy

The repository's 500-line maintainability guideline applies to source-code files, not declarative data files.

Do not raise line-count, file-length, "file too large", or split-the-file findings for `*.json` files. This includes command-extension sources under `contributions/command-sources/`, portable fixtures under `tests/fixtures/`, generated JSON, schemas, manifests, contracts, and other declarative JSON.

Large JSON files are expected when they enumerate command matchers, fixtures, schemas, or generated data. Review them for correctness, security, schema validity, duplication, malformed data, trust-boundary mistakes, and unnecessary generated churn, but never require splitting or shrinking them solely because of line count or file size.

Continue applying the 500-line guideline to source code where appropriate.

### Approval invariant

Every executable review must offer Allow once and Always allow, and every part of Guard must honor an approval until the user removes it or the command's hash changes. Read `docs/guard/approval-invariant.md` before changing approval tokens, retry bindings, scope contracts, saved decisions or the review card. A change that makes a supported review once-only, or drops Always allow for a supported execution route, breaks this invariant. Content-bound scripts without a working execution binding are explicitly unsupported: show the unavailable capability and verified recovery actions instead of approval buttons that cannot run the reviewed version. Inventory or a command-text hash cannot substitute for that binding. Findings about tighter binding without removing a supported choice are in scope.

### Python runtime review policy

HOL Guard is moving its runtime from Python to Rust (`rust/crates/`). Report new Python runtime logic under `src/`.

When a pull request adds or grows `*.py` code under `src/`, report one finding for the pull request that asks whether the new logic belongs in Rust instead. Runtime logic means command parsing, matching, classification, decisions, scanning, hashing, secure file I/O, hook handling, or other deterministic hot-path work. Name the likely crate when it is clear, and use `docs/guard/native-hook-data-plane-ownership.md` for what Rust already owns.

Do not report tests and tooling (`tests/`, `ci/`, `scripts/`, `conftest.py`), deleted or shrinking Python, thin shims or glue that only call the native runtime, parse arguments, or render its result, or fixes to existing Python that has no Rust equivalent yet.

Raise the finding as a question, not a blocker.
