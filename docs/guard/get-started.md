# Guard Get Started

Install `hol-guard` when you want local harness protection.
Install `plugin-scanner` separately when you want maintainer or CI checks for plugin packages.

Use it when you want to protect a harness before local MCP servers, skills, hooks, or plugin surfaces run.

## The everyday flow

1. Start the guided first-run setup:

   ```bash
   hol-guard init
   ```

   Guard prints a plan first, then asks before one side effect at a time. You approve the dashboard open, Guard completes it, then you move to harness installs, Guard Cloud connect, and desktop notification setup. Nothing opens or changes until you approve that checkpoint, and each checkpoint reports completion before the next prompt appears.

   For automation only, run:

   ```bash
   hol-guard init --yes
   ```

2. Alternatively, use the manual discovery path only when you want to inspect each step yourself:

   ```bash
   hol-guard bootstrap
   ```

   For a Hermes-first setup:

   ```bash
   hol-guard hermes bootstrap
   ```

3. Or, if you prefer the manual path, install Guard in front of the harness you use most:

   ```bash
   hol-guard install codex
   ```

   For Codex, install now enables Guard-owned `PreToolUse` Bash hooks in `.codex/hooks.json` and turns on the Codex hooks feature. That native hook path still runs when Codex itself is in YOLO mode, so Guard can pause sensitive Bash commands before execution instead of forcing a slower Codex approval mode.

   After upgrading later, run `hol-guard update` to update the installed `hol-guard` package in that environment.

4. Once setup is complete, run one dry pass so Guard records the current state:

   ```bash
   hol-guard run codex --dry-run
   ```

5. Launch through Guard after that. Guard will stop and ask if a tool is new or changed:

   ```bash
   hol-guard run codex
   ```

6. If the shell is interactive, approve inline. If the shell cannot prompt, Guard queues the change in the local approval center instead of ending the session with a dead stop:

   ```bash
   hol-guard approvals
   ```

7. Review or resolve changes from the terminal when you want a text-only path:

   ```bash
   hol-guard approvals approve <request-id>
   hol-guard approvals deny <request-id>
   hol-guard diff codex
   ```

8. Check receipts and current status:

   ```bash
   hol-guard receipts
   hol-guard status
   ```

9. Connect cloud sync later only if you want shared history:

   ```bash
   hol-guard connect
   hol-guard connect status
   hol-guard connect repair
   hol-guard sync
   ```

10. Share the generated install/connect command guide when someone needs the exact local-first flow:

   ```bash
   hol-guard explain install-connect
   ```

11. Inspect or rotate the local installation identity that cloud sync uses:

   ```bash
   hol-guard device show
   hol-guard device label set "VPS - Hermes runtime"
   hol-guard device rotate
   ```

12. Check supply-chain bundle coverage after sync when you want to see which ecosystems are fully protected, beta, or monitor-only:

   ```bash
   hol-guard cloud sync-intel
   hol-guard supply-chain sync
   hol-guard supply-chain scan
   hol-guard supply-chain explain minimist@1.2.5 --ecosystem npm
   ```

   Guard prints the latest bundle summary plus ecosystem support labels. Today `npm` and `PyPI` show **Protected** coverage, Cargo/Go/Maven/Gradle/Composer/RubyGems show **Beta**, and system packages or unsupported package managers stay **Monitor-only** so Guard never pretends advisory blocking where it does not exist.

## Which command should I use?

| Situation | Command | What it answers |
| :--- | :--- | :--- |
| I need the current protection posture | `hol-guard status` | What is Guard watching, is sync connected, and what is the next action? |
| I need first-run setup | `hol-guard init` | Open the local dashboard, install supported harnesses, start optional Cloud connect, and check desktop notifications. |
| I need install/connect docs | `hol-guard explain install-connect` | Which local-first setup and optional cloud commands should I share? |
| I need to preview one install before I run it | `hol-guard protect npm install <package> --dry-run` | Would Guard allow, warn, review, or block this exact install request right now? |
| I need setup or runtime troubleshooting | `hol-guard doctor <harness>` | Why is this harness or Guard runtime not behaving correctly? |
| A launch was blocked or changed | `hol-guard diff <harness>` | What changed since the last recorded snapshot? |
| I need to resolve a queued block | `hol-guard approvals` | Which requests are waiting, and how do I approve or deny them? |
| I need decision history | `hol-guard receipts` | What decisions did Guard record locally? |
| I need the tracked catalog | `hol-guard inventory` | Which artifacts are currently tracked and present? |
| I need an exportable evidence artifact | `hol-guard abom` | What local AI-BOM can I attach to an audit or handoff? |
| I need the chronological log | `hol-guard events` | What happened over time on this machine? |
| I need supply-chain coverage labels | `hol-guard cloud sync-intel` | Which ecosystems are protected, beta, or monitor-only right now? |
| I need a workspace install scan or one-package verdict | `hol-guard supply-chain scan` or `hol-guard supply-chain explain <package> --ecosystem <ecosystem>` | Which current dependencies or package versions would Guard warn, review, or block right now? |

## One continuity model

Guard uses the same product loop across the local daemon, the CLI, and Guard Cloud:

1. **Home** answers whether this machine is protected right now. `hol-guard status` and the local Home view show the same next action, latest proof, and cloud sync state.
2. **Protect** owns install, repair, remove, status, and first protected action proof. The daemon handles these actions directly when available; the CLI commands stay visible as a fallback when the daemon is offline, unsupported, or missing a local session token.
3. **Inbox** owns decisions that need judgment. Local approvals use the same categories and policy memory scopes that cloud review uses, so a scoped decision can be synced without changing meaning.
4. **Evidence** owns durable proof. Receipts from daemon actions, CLI actions, and cloud sync use the same local store before any optional upload.
5. **Settings** owns policy. Local config remains the source of truth for offline protection, while cloud sync can distribute shared policy memory when you connect a workspace.

The important handoff is that local protection does not depend on Guard Cloud being online. Cloud adds shared history and team policy, but the daemon and CLI still block risky actions, write receipts, and preserve approval continuity on this machine.

## Troubleshooting

| Symptom | Start here | Then try |
| :--- | :--- | :--- |
| Guard did not find my harness | `hol-guard detect --json` | `hol-guard doctor <harness> --json` for adapter-specific warnings |
| `hol-guard run` paused a launch | `hol-guard diff <harness>` | `hol-guard approvals`, then retry `hol-guard run <harness>` |
| I approved a prompt and want proof | `hol-guard receipts` | `hol-guard explain <artifact-id>` for the latest receipt and diff context |
| I need audit or handoff evidence | `hol-guard inventory` | `hol-guard abom --format json` for machine-readable export |
| I need to understand recent activity | `hol-guard events` | Use `--name <event>` to filter a noisy local timeline |
| Cloud sync or pairing looks wrong | `hol-guard connect status` | `hol-guard connect repair`, `hol-guard connect`, or `hol-guard sync --json` depending on the status output |

## Additional playbooks

- [AI skill guidance](./SKILL.md) for package-install interception workflows (`protect`, `scan`, `audit`).
- [False-positive remediation](./remediation.md) for scoped and expiring exception handling.
- [Blocked malware incident response](./incident-response.md) for containment and recovery.

## Evidence-first decisions

Guard now scores local decisions from structured evidence, not only string heuristics. Each changed artifact carries:

- typed risk signals with confidence and remediation
- capability deltas like `new_network_host`, `secret_scope_expanded`, and `subprocess_added`
- provenance state and local history context
- review priority and suppressibility guidance

Runtime prompt intent is also evaluated as first-class risk input. Guard detects more than direct `.env` reads, including:

- secret-bearing files (`~/.ssh`, `~/.aws/credentials`, `~/.kube/config`, `.npmrc`, `.pypirc`, Docker auth config)
- exfil-like intent (`upload`, `post`, `webhook`, `gist`, transfer verbs)
- subprocess and shell-wrapper expansion
- destructive mutation intent
- Guard bypass intent

## Fine-tune local policy

Guard works with local defaults first, then optional overrides for a harness, publisher, or artifact.

Home config:

```toml
mode = "prompt"
default_action = "warn"
changed_hash_action = "require-reapproval"
desktop_notifications = true

[harnesses.codex]
default_action = "allow"

[publishers.hashgraph-online]
default_action = "allow"

[artifacts."codex:project:workspace_tools"]
default_action = "sandbox-required"
```

Optional project override:

```toml
# .hol-guard.toml
[artifacts."codex:project:workspace_tools"]
default_action = "block"
```

Guard still reads the legacy `.ai-plugin-scanner-guard.toml` file if you already have one, but new local overrides should use `.hol-guard.toml`.

Guard resolves decisions in this order:

1. saved decisions from `hol-guard allow` or `hol-guard deny`
2. project override file
3. home config
4. Guard's built-in recommendation

Use these actions in config or saved decisions:

- `allow`
- `warn`
- `block`
- `sandbox-required`
- `require-reapproval`

## Require proof before remembered trust

The approval gate protects the places where Guard would otherwise remember trust: scoped allow decisions, broad/global allow, policy clears, settings changes, approval-history clears, native approval persistence, and cloud/headless policy sync. Enforcement lives in the daemon and store layer, so the dashboard and CLI cannot bypass it.

Enable password proof:

```bash
hol-guard settings approval-password enable \
  --new-password '<password>' \
  --confirm-password '<password>' \
  --cooldown-seconds 900
hol-guard settings approval-password status
```

The default mode requires proof for allow decisions and broad trust changes. If your team also wants proof before block decisions, enable **Require password for block decisions too** in Settings or pass `--strict-all-decisions` when enabling the gate.

Cooldown is intentionally narrow. A valid cooldown can satisfy ordinary non-global allow decisions, but it cannot satisfy global allow, policy clear, settings import/reset, disabling the password gate, disabling TOTP, recovery, or policy-memory clear. When TOTP is enabled, cooldown is disabled so every protected action requires both the password and a current authenticator code. Lock or unlock the current password-only terminal approval window explicitly:

```bash
hol-guard approvals unlock --duration 15m
hol-guard approvals lock
```

Add Google Authenticator-compatible TOTP when password-only proof is not enough:

```bash
hol-guard settings approval-totp enroll --current-password '<password>' --device-label '<device>'
hol-guard settings approval-totp verify --current-password '<password>' --code 123456
hol-guard settings approval-totp status
```

Guard emits a standard `otpauth://totp/HOL%20Guard:<device>` URI with a Base32 secret, SHA-1, 6 digits, and a 30-second period. The seed is encrypted locally and never appears in public settings, diagnostics export, receipts, URLs, or screenshots. Guard rejects invalid codes, replayed time steps, and stale enrollment state. When TOTP is enabled, protected actions require both the current password and a current authenticator code.

## What `install` does

`guard install <harness>` creates a local launcher shim under Guard’s home directory:

- macOS/Linux: `~/.hol-guard/bin/guard-<harness>`
- Windows: `~/.hol-guard/bin/guard-<harness>.cmd`

Claude Code also gets Guard hook entries in `.claude/settings.local.json` when you install from a workspace.

Copilot CLI gets a Guard-owned repo hook file at `.github/hooks/hol-guard-copilot.json` when you install from a workspace. Guard only reads `~/.copilot/config.json` and `~/.copilot/mcp-config.json`; it does not auto-write user-level Copilot config.

OpenCode gets the normal Guard shim plus a Guard-owned runtime overlay at `<guard-home>/opencode/runtime-config.json`. Guard
injects that overlay through `OPENCODE_CONFIG_CONTENT` when you launch through Guard so native skill loads stay on ask
without mutating your checked-in `opencode.json`.

Hermes gets the normal Guard shim plus a Guard-owned bundle at `<guard-home>/hermes/` with:

- `mcp-overlay.json`
- `pretool-hook.json`
- `manifest.json`

Guard injects the managed overlay paths through `HERMES_GUARD_MCP_OVERLAY_PATH` and `HERMES_GUARD_PRETOOL_PATH` when
you launch Hermes through Guard.

OpenClaw gets the normal Guard shim plus a Guard-owned bundle at `<guard-home>/openclaw/` with:

- `overlay.json`
- `pretool-hook.json`
- `manifest.json`

Guard injects the managed overlay paths through `OPENCLAW_GUARD_OVERLAY_PATH` and `OPENCLAW_GUARD_PRETOOL_PATH` when
you launch OpenClaw through Guard. It does not mutate `~/.openclaw/openclaw.json`.

## Harness approval model

Guard uses three approval tiers:

1. native harness approval where the harness already has a strong tool permission model
2. the local Guard approval center on `127.0.0.1` when Guard needs to pause a launch cleanly
3. terminal resolution through `hol-guard approvals` when you do not want a browser surface

Current strategy:

- `claude-code`
  prefers Claude hooks and can hand blocked work to the approval center cleanly
- `copilot`
  wraps the `copilot` CLI, watches documented repo hooks and MCP config, and treats workspace `.vscode/mcp.json` as MCP artifact detection only
- `codex`
  uses inline MCP elicitation in the same Codex chat when the interactive CLI or Codex App can answer it, and falls back to the local Guard approval center for `codex exec` or any other nonresponsive session
- `cursor`
  keeps Cursor’s native tool approval and lets Guard own artifact trust before tool use
- `antigravity`
  scans Antigravity settings, installed extensions, and Antigravity-owned MCP or skill roots before launch
- `opencode`
  detects OpenCode MCP servers, commands, plugins, and skills before launch, and `guard install opencode` adds a
  Guard-owned runtime overlay that keeps native skill loads on ask
- `hermes`
  prefers the managed Hermes same-channel path when Guard owns the overlay bundle, falls back to the approval center,
  and keeps browser auto-open off for blocked requests
- `openclaw`
  scans OpenClaw gateway config, channel posture, MCP servers, workspace skills, user skills, and OpenClaw-owned skills,
  then prefers native-or-center delivery once the managed overlay bundle exists
- `gemini`
  scans `.gemini/settings.json`, extension manifests, hooks, MCP registrations, and Gemini skill directories before
  launch, then routes blocked changes to the approval center

Guard does not claim VS Code Copilot extension-host interception in this pass. A VS Code inline tool prompt by itself is
not proof that Guard blocked the action, because that prompt can come from VS Code's own permission surface. For Copilot,
count Guard proof only from CLI hook responses, Guard runtime receipts, or an MCP client that explicitly answers Guard
elicitation. Guard also does not add Cisco AIBOM runtime policy logic in this pass. AIBOM can come back later only as
evidence or export.

## First-party canaries

Use these local repos to prove Guard against real first-party surfaces:

- `hashnet-mcp-js` for a real MCP server harness target
- `registry-broker-skills` for a real skills registry fixture during scan and trust checks

Suggested local validation:

```bash
hol-guard detect codex --json
hol-guard install codex
hol-guard status
hol-guard run codex --dry-run
hol-guard receipts
```

For a real Codex canary, point `~/.codex/config.toml` or `<workspace>/.codex/config.toml` at a local `hashnet-mcp` command, then repeat the Guard loop above.

## Codex-specific approval behavior

Guard now has three real runtime paths for Codex:

1. native Codex Bash tool calls
   Guard installs a Codex `PreToolUse` hook in `.codex/hooks.json`, so sensitive Bash commands are denied before they run and routed into HOL Guard approval
2. interactive Codex CLI and Codex App MCP tool calls
   Guard sends an MCP `elicitation/create` approval request, so the user can approve or deny in the same Codex chat
3. noninteractive Codex runs such as `codex exec`
   if Codex does not answer the elicitation request, Guard queues a localhost approval request and returns the request id plus approval URL in the same tool-call error

That means the user should never get a silent pass-through on a risky Codex action that Guard manages:

- native Bash deny plus HOL Guard approval-center recovery for sensitive shell actions
- same-chat approve or deny when Codex can render the inline MCP prompt
- explicit approval-center recovery when the session cannot

## Seamless approvals

When Guard blocks a launch, it opens a persistent approval link in the terminal rather than pausing the session. You can resolve requests without leaving your harness:

1. Guard returns the approval URL in the block output and queues the request locally.
2. On macOS and Windows, Guard also sends a native desktop notification for the new request. Set `desktop_notifications = false` in `~/.hol-guard/config.toml` or `HOL_GUARD_DESKTOP_NOTIFICATIONS=0` to disable it.
3. Open the approval center at the URL, from the notification, or in your browser.
4. Approve or deny the request from the approval center UI or the CLI:

   ```bash
   hol-guard approvals approve <request-id>
   hol-guard approvals deny <request-id>
   ```

5. After you resolve the request, Guard reports one of two honest outcomes:
   - Codex resumed, Guard sent the exact blocked command context back into the same session, so watch the same chat for the next HOL Guard message.
   - Guard could not find the Codex session to resume, return to Codex manually and follow the saved approval or block guidance.

   For harnesses without resume support, Guard still saves the decision and shows the manual next step. No page reload is required.

To inspect a pending request's details or get the approval URL, pass the request-id to the `approve` command with `--dry-run`, or visit the approval center URL shown in the block message directly.

## Troubleshooting

### Approval link says API error

If the approval center URL in a block message returns an API error, the local approval center locator may be stale.
Use the **Repair approval center** action in the Guard dashboard Settings tab, or call the repair endpoint directly when the daemon is running. The port shown in Guard's status output or the dashboard URL is your daemon port:

```bash
GUARD_PORT=$(hol-guard status --json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print((d.get('runtime_state') or {}).get('daemon_port', d.get('daemon_port', 4781)))" 2>/dev/null || echo 4781)
curl -s -X POST "http://127.0.0.1:${GUARD_PORT}/v1/daemon/repair" \
  -H "X-Guard-Token: $(cat ~/.hol-guard/daemon-auth-token)"
```

After repair, restart Guard, then retry the block message URL or relaunch your harness through Guard. Pending approval requests are preserved across repairs.
