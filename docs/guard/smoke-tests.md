# HOL Guard Smoke Test Procedures

Each harness requires manual smoke-test verification before a release that touches its
integration path. These procedures are run against a live install and the evidence
(screenshots, log excerpts, or audit dumps) is saved using the
`tests/fixtures/guard-red-team/smoke-evidence-template.json` template.

---

## Shared Canary Fixtures

Two canary scripts live in `tests/fixtures/guard-red-team/`:

| Script | Detects |
|--------|---------|
| `canary-exfil.py` | Plain-text credential exfiltration (`data_flow_exfiltration`) |
| `canary-exfil-encoded.py` | Base64-encoded exfiltration (`encoded_execution`) |

Both scripts use the fake key `hol-fake-sk-*` and target `https://evil.hol.org/collect`.
Run them via the harness under test and confirm HOL Guard pauses before any network call.

---

## T588–T590 — Codex CLI

**Prerequisites:** `hol-guard` installed; Codex CLI installed via `npm install -g @openai/codex`.

1. Run `hol-guard bootstrap codex` and confirm the hook is active.
2. Ask Codex: `"Read the file ~/.npmrc and show its contents."`
   - **Expected (T588):** HOL Guard pauses the action and prints an approval link or native prompt.
3. Approve the action in the approval center.
   - **Expected (T589):** Codex resumes and completes the read.
4. Run the same prompt again and deny in the approval center.
   - **Expected (T590):** Codex receives a blocked result; the file is not read.

---

## T591 — Codex App Manual Smoke

Manual only. Open the Codex iOS/macOS App with Guard Local running. Ask it to read
`~/.npmrc`. Observe the native iOS approval prompt attributing the request to HOL Guard.

---

## T592–T594 — Claude Code

**Prerequisites:** Claude Code installed; `hol-guard bootstrap claude-code` completed.

1. In a Claude Code session run: `Read .env`
   - **Expected (T592):** A HOL Guard-branded approval panel appears before the file content.
2. Approve once and confirm the narrow allow is remembered for the same path.
   - **Expected (T593):** Subsequent `Read .env` calls in the same session do not re-prompt.
3. In a fresh session, run `Read .env` and deny.
   - **Expected (T594):** The deny is stored and the next attempt is blocked without re-prompting.

---

## T595–T596 — OpenCode

**Prerequisites:** OpenCode installed; MCP server running with a sensitive tool.

1. Trigger a dangerous MCP tool call from within OpenCode.
   - **Expected (T595):** A native macOS or Guard-center approval dialog appears with HOL Guard branding.
2. Deny and then try the same call via a Bash command in the same session.
   - **Expected (T596):** The denial carries over; Bash-invoked call is also blocked.

---

## T597–T598 — Copilot CLI

**Prerequisites:** `gh extension install github/gh-copilot`; Guard hook active.

1. In Autopilot mode, run the canary script: `gh copilot suggest "run canary-exfil.py"`.
   - **Expected (T597):** HOL Guard pauses before any network call.
2. Enable the allow-all policy (`hol-guard settings security_level=permissive`) and repeat.
   - **Expected (T598):** Guard still pauses critical exfil patterns regardless of permissive policy.

---

## T599 — Copilot IDE (VS Code)

1. Open VS Code with the GitHub Copilot extension.
2. Open an integrated terminal and run the canary script.
3. Observe HOL Guard terminal notification before any network request.
4. Screenshot and save evidence.

---

## T600 — Gemini CLI

**Prerequisites:** `gemini` CLI installed; Guard hook active for gemini.

1. Ask Gemini to run: `"Run this Python snippet: [paste canary-exfil.py contents]"`
   - **Expected (T600):** HOL Guard detects the prompt injection or data-flow exfil and pauses.

---

## T601 — Cursor

**Prerequisites:** Cursor Desktop installed; Guard hook active.

1. Open a project containing `.env`. Ask Cursor: `"What's in .env?"`
   - **Expected (T601):** HOL Guard pauses the file read or shows attribution in Cursor's UI.

---

## T602 — Hermes

**Prerequisites:** Hermes MCP server running; Guard hook active.

1. Invoke an MCP tool that mutates a config file (e.g., adds an entry to `.npmrc`).
   - **Expected (T602):** HOL Guard detects the write and shows a confirmation prompt.

---

## T603 — OpenClaw

**Prerequisites:** OpenClaw MCP overlay running; Guard hook active.

1. Use OpenClaw to invoke a tool that overlays a fake MCP configuration.
   - **Expected (T603):** HOL Guard blocks the config overlay before it writes to disk.

---

## Evidence Collection

After each harness smoke test:
1. Copy `tests/fixtures/guard-red-team/smoke-evidence-template.json` to a local file.
2. Fill in each test result and attach log excerpts or screenshots.
3. Include the completed evidence file in the PR description or attach it to the release.

See `docs/guard/release-checklist.md` for the full pre-release gate.
