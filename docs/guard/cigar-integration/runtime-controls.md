# Development runtime controls

The optional native service has configuration, local candidate enrollment, runtime controls and explicit workspace/source grants. The Protection panel and public CLI project those APIs. The full integration remains under implementation. See the [execution log](EXECUTION_LOG.md) for exact qualification scope and outstanding checks.

## End-user controls

Open the **CIGAR** tab in the main navigation (`/cigar`). **Overview** shows the current runtime and a three-step setup checklist. **How it works** explains source access, review briefs, app connections, execution context, storage, and runtime registration.

CIGAR stands for **Context Intelligence Graph Agentic Runtime**, displayed in the page header and learning screens. Open **Tutorials** or **Take a walkthrough** for guided lessons on a first cited brief, scoped AI app context, and supported native execution preparation. Instructions stay with the selected step across runtime and source sections, with expected outcomes, example questions, copy controls, and links to the actual settings. A lesson can be resumed within the browser session; its saved progress contains only a lesson identifier and step number. Reading or advancing a lesson never saves feature preferences, starts CIGAR, grants sources, or authorizes an app.

**How it works** includes an interactive conceptual flow: admitted sources, a scoped graph, compilation within a context budget, and delivery to Guard or authorized apps. It explains citations, source freshness, effective questions, storage choices, and the difference between context and command authorization. The execution lesson retains this candidate's external-app delivery qualification limits.

In **Runtime & preferences**, choose an enrolled runtime, select preferences and save through Guard's existing settings/proof flow. A saved on preference displays **Not started** until you click **Start CIGAR**, prominently available at the top of every CIGAR section. Starting performs native process verification in the background; the UI reports **Ready** only after it succeeds. The primary action then becomes **Use CIGAR**, which opens **Sources & AI apps** for explicit workspace access. An idle runtime displays **Paused** and can be started again. Unsaved changes, a pending operation, missing selection, or policy restrictions prevent activation. The workspace's **Turn off CIGAR** action cancels work, closes the active capability and persists opt-out without clearing Guard approvals or other preferences.

**Sources & AI apps** contains workspace grants, selected documents, app pairing, and separately authorized sharing. **Data & privacy** provides context cleanup and diagnostics. The former Protection settings entry links to the CIGAR workspace; review and Evidence links open its relevant section directly.

Opening CIGAR reads native status and registered runtime metadata only. It never scans PATH, probes Python, installs packages, or starts a runtime. An empty runtime list means this Guard profile has no registered CIGAR bundle; it does not mean Python 3.14 is absent or incompatible. Final CPython 3.14.7 qualifies, including in a separate selected environment while Guard uses another supported Python.

Home also shows native context readiness, a link to its Protection settings and **Turn off context assistance** when an enabled preference or pending job is known. Opening Home reads status only; it does not start or probe a runtime. Context status failures are separate from Guard protection and approval controls.

These CLI commands reach the same resident-owned service:

| Command | Behavior |
| --- | --- |
| `hol-guard context status --json` | Read native state; no CIGAR probe, import or installation |
| `hol-guard context runtimes --json` | Explicit metadata-only listing of enrolled local candidates |
| `hol-guard context check --json` | Schedule selected-runtime verification; an off preference stays off |
| `hol-guard context start --json` | Verify and activate only an already saved, enabled selection |
| `hol-guard context off --json` | Cancel/stop optional work and persist opt-out |

Each accepts `--guard-home` for an explicit installation. The commands also work below the scanner's `guard` command. Human output reports native requested/effective state and any pending job. JSON preserves opaque revisions as strings. Neither entry point accepts interpreter facts, executable paths or approval fingerprints as activation authority. There is no CLI shortcut that creates user consent.

A successful start response can mean a background verification job was accepted. Read status for its result. A transport timeout is an unknown result: inspect status before another start request. The service does not automatically retry a mutation after an uncertain outcome.

Keep Guard's desktop app or daemon running for `check`, `start` and context tools. These commands control the existing service; they do not launch a persistent Guard host. If a standalone CLI invocation accepts a job but subsequent status reports `runtime_not_verified`, open Guard and explicitly start assistance again. Off-state status and runtime listing remain available.

## Runtime requirement

The actual selected executable must be a verified final CPython 3.14 process with the supported build/ABI, approved CIGAR 0.14.1 package and matching bundled worker. Python 3.13, 3.15, prereleases, PyPy, debug and free-threaded builds do not qualify. Guard retains its broader base Python support; a separate verified Python 3.14 environment is valid. The dashboard reports the Guard host's state, including when viewed from another device.

Current installed development evidence covers darwin-arm64 only. Windows activation explicitly refuses until persistent Job Object transport is implemented and qualified. The existence of an eligibility predicate for another platform is not platform qualification.

## Local candidate enrollment

Public package installation and its product setup experience remain pending. Development tests use the explicitly staged, independently approved local candidate described in the [runtime receipt](evidence/receipts.json). No system Python or live Guard installation is changed by those tests.

The native operator command is `context-assistance-enroll-local --stdin` on the matching `hol-guard-runtime` binary. Its JSON request has these fields:

| Field | Meaning |
| --- | --- |
| `schema` | `guard-cigar-enroll-local.v1` |
| `guard_home` | Private installation state directory |
| `runtime_id` | Bounded opaque local selection ID |
| `local_candidate_approved` | Explicit operator acceptance of this candidate |
| `source_revision` | Exact 40-character candidate source revision |
| `selection` | Private selected executable, site-packages and work-directory paths |
| `approval` | Independently reviewed bundle/platform/file fingerprints |

This is an operator enrollment interface, not an HTTP/MCP request body. A browser or agent cannot approve its own arbitrary expected bytes. Enrollment verifies actual executable/package identity, Python facts, worker handshake and synthetic compilation, then retains the record privately. The result explicitly has `activation_granted: false`. The real settings writer requires an enrolled selection with matching current bytes for a first opt-in; activation repeats actual process verification.

## State and privacy

`requested_enabled` preserves validated local intent. `effective_preferences`, `restriction` and `verification_permitted` separately report native policy restrictions. `effective_enabled` also requires a live verified capability for the current preference generation. `last_check` is historical metadata with `active: false`; it grants no current capability. A ready runtime alone grants no workspace documents or app access.

Status and explicit runtime listing omit private executable/package paths. They report content-free diagnostics and metadata. Source permissions are native, and local/workspace/managed restrictions can narrow consent. Invalid machine authority disables assistance. A managed lock cannot prevent immediate opt-out.

The smaller and balanced context presets select token/workspace/idle preferences. They are not RAM measurements or savings estimates. Memory is the default storage choice. Optional [saved evidence](private-persistence.md) requires a separate successful native write/restart/read check. Independent agent sharing requires its own explicit preference and broker compile check. Selecting saved evidence alone does not enable AI app access or sharing. Platform and runtime gates apply to every mode.

The advanced [native execution context](native-execution-context.md) preference is independently off. Its local adapter uses the native captured-Bash path for Pi and Oh My Pi on macOS, with explicit app/workspace grants and fixed native facts. It prewarms one additional private memory broker/client; it does not require MCP access, sharing or saved evidence. Settings distinguish the SDK check, native preparation readiness and recent private observations. SDK/context failure preserves the command's native authorization. Native owner tests, installed sink tests and the password-backed browser approval flow have separate evidence; actual external app delivery remains unqualified.

## Qualification

`npm run test:context-assistance` covers the new UI contracts and authenticated transport. Native library and resident protocol tests exercise the real installed candidate separately. `tests/test_context_assistance_cli_installed.py` is an opt-in process test requiring the exact native binary plus the recorded selection/approval. It has passed explicitly, as has the installed dashboard/source flow; historical failed attempts remain in the execution log. A default skipped run is not qualification. Those receipts qualify their recorded commits and artifacts, not later changes automatically.

The [initial installed browser receipt](evidence/receipts.json) covers opt-in, source admission, citations, stale refusal, refresh/comparison, withdrawal/revocation and opt-out. The [execution log](EXECUTION_LOG.md) records subsequent Home, review/history, scoped MCP, sharing, persistence and native executor/browser checks against their exact packages. Desktop, actual external harness delivery, remaining executor boundaries and performance qualification remain required by the [full goal](EXECUTION_GOAL.md).

## Native receipt facts

With **Sanitized receipt facts** enabled, each explicitly granted workspace may use a memory-only window of at most 16 recent native decisions. Only `PreToolUse`, `PostToolUse` and `UserPromptSubmit` decisions in that exact canonical workspace match. An app grant narrows the harness as well; the dashboard grant can inspect that workspace's native facts. App target names remain permission targets, not agent authentication.

The current feed covers receipts created by the resident native evaluator and committed through its native evidence writer. It does not import arbitrary historical database rows or claim complete hook-route/activity coverage. A native origin alone is insufficient: successful persistence must also be observed. Failed writes leave optional context unchanged. Duplicate durable receipts still acknowledge successfully. The separate notification mailbox never consumes Guard's direct-evidence queue or acknowledgement tokens.

The SDK receives only the canonical harness/event, recorded decision and policy actions, observe-mode flag, native policy generation and receipt digest, with an explicit statement that the fact is neither execution confirmation nor an approval grant. Recorded and observed policy actions stay separate so an observation cannot be presented as an enforced decision. It receives no raw command/prompt, source path, origin authenticator, execution-intent digest or review capability. Context and native evidence remain distinct from execution authority.

Pending origins and committed notifications are bounded at 128 and 64 respectively. Producers use nonblocking native memory operations; they do not call the SDK, read source files or wait for graph work. The context actor coalesces admitted notifications on its next read. A missed update clears retained receipt context and exposes a loss indicator. The durable evidence writer, its ordering/failure signal and acknowledgement behavior stay independent. Withdrawal/revocation does not drain optional updates first. Turning off closes the mailbox and discards ephemeral grants and context.
