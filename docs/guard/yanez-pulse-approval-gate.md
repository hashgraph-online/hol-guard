# Yanez Pulse approval gate

Yanez Pulse is the third approval-gate factor, beside the approval password and
the authenticator app (TOTP). When it is on, the user approves each gated action
in the YID app with a face scan. Guard verifies the Pulse receipt in Rust and
only then issues the same short-lived grant a correct password or code would.

This document records what was changed, why, how it was tested, and what is
still open.

## How it works

```text
CLI / dashboard ──► Python glue ──► resident (Rust) ──► Pulse (HTTPS)
                                    │
                                    ├─ pulse_request   build terms, create authorization
                                    ├─ pulse_poll      one check every 10 s, no gate lock held
                                    └─ verify          verify receipt → ledger → consume → grant
```

1. A gated call (`require_approval_decision`, `require_high_risk`,
   `require_extension_control`, `require_local_cli_trust`) reaches the resident.
   With Pulse on, the resident answers `approval_gate_pulse_required` unless an
   open, matching Pulse cooldown covers the action.
2. The caller asks the resident to create a Pulse request for **the same**
   purpose, action, scope, subject and session nonce. The resident builds the
   terms, keeps them, and returns a request id and a six-character match code.
3. The caller checks the request every 10 seconds until the 15-minute window
   closes. Each check is its own resident operation (at most 8 seconds, inside
   Guard's 9-second limit per resident call), so no approval-gate lock is held
   while the user decides. A check that cannot reach Pulse is tried again on
   the next interval; only an approval in the YID app ends the wait early. The approved receipt
   stays inside the resident and is never returned to Python or the browser.
4. The caller repeats the original gated call with `pulse_request_id`. The
   resident verifies the receipt against the action in that call, records it in
   the local single-use ledger, consumes it at Pulse, and registers a grant with
   `factor_set = ["pulse"]`.

The CLI waits in step 3 (`pulse_mode = "wait"`). The dashboard gets
`202 approval_gate_pulse_pending` with the request id and match code, polls
`/v1/approval-gate/pulse/poll`, then resubmits (`pulse_mode = "defer"`). Both
surfaces reach the same resident call with the same parameters.

## Rust-side verification approach

All receipt checks live in the new `guard-yanez-pulse` crate
(`receipt::verify_receipt`). They follow Pulse's enforcement checklist, in this
order, and any failure leaves the action blocked:

| # | Check | Failure code |
| --- | --- | --- |
| 1 | Compact JWS, ≤16 KB, `alg` pinned to `EdDSA`, no `crit`, key chosen by `kid` | `approval_gate_pulse_receipt_invalid` |
| 2 | Ed25519 signature against the Yanez JWK set (current and retired keys). An unknown `kid` refreshes the set once, at most every 30 s | `…_receipt_invalid` |
| 3 | Required claims and types: `yanez_decision = approved`, `iat = yanez_decided_at`, not more than 60 s in the future, `yanez_match_overlap ≥ 0`, `yanez_consent_not_after` present and no later than the deadline Guard asked for | `…_receipt_invalid` |
| 4 | `iss` equals `https://yid.yanez.ai` (`YANEZ_ISSUER`), `sub` equals the pinned YID, `yanez_agent_key_id` equals the pinned key id, `jti` equals the request id | `…_wrong_issuer`, `…_wrong_yid`, `…_wrong_agent_key`, `…_wrong_request` |
| 5 | Approver's BLS12-381 signature (min-pk, basic scheme, `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`) over the exact `yanez_signed_message` bytes, with public-key subgroup validation | `…_user_signature_invalid` |
| 6 | Signed envelope, parsed with duplicate keys rejected: version 1, `action = agent_authorizations.decision`, `decision = approve`, and issuer, YID, request id, tier, consent bound and terms all equal to the receipt. `signed_at` is within 300 s of `yanez_decided_at` and inside Guard's age and future limits, each widened by 300 s for the phone's clock | `…_user_signature_invalid` |
| 7 | Receipt terms structurally equal Guard's own copy (Pulse rules: bool ≠ number, `-0 = 0`, ordered arrays, integers ≤ 2^53−1) | `…_terms_mismatch` |
| 8 | Approver's key is in the YID's **live** key registry, read at verification time, at a tier that covers the one it signed. The registry answer must be for the pinned YID | `…_user_key_unregistered`, `…_wrong_yid` |
| 8a | Approver's key is one Guard pinned at enrollment (`pulse_user_keys`). A key Yanez registers later does not count; the user sets up Pulse again to use a new device | `…_user_key_unconfirmed` |
| 9 | Tier is at or above the floor the user chose at setup: `medium` (the default, "Standard face scan") or `high` ("Strict face scan"). `low` is never accepted | `…_assurance_too_low` |
| 10 | Freshness: `now − decided_at ≤ 900 s` (Pulse's recommended maximum age), and `now ≤ consent_not_after` | `…_stale`, `…_consent_expired` |

Then, in the resident (`approval_gate_pulse.rs`):

- **Binding.** The resident recomputes an HMAC-SHA256 over purpose, action,
  scope, subject, session nonce, the caller's OS-session hash, the request
  nonce and the factor generation, using a 32-byte key kept in Guard's
  encrypted secret store. It must equal the HMAC in the terms the user
  approved. A different action, scope, subject, session or factor generation
  is a different request.
- **Single use.** The `jti` is written durably to the local ledger *before* the
  remote consume. Guard then calls `POST /api/authz/introspect` with
  `consume: true` and acts only on `valid && consumed_now`. The
  `consumer_token` is derived from the key and the `jti`, so retries reuse it.
  The pending entry is taken out of the table before verification, so one
  request can be verified once.
- **Minimum face scan.** Setup takes `min_tier`, `medium` (the default when
  it is absent) or `high`; anything else, `low` included, is refused with
  `approval_gate_pulse_invalid_tier` before anything reaches the phone. With
  `high`, setup needs a device on the YID that can sign at high
  (`approval_gate_pulse_no_signing_key`) and a high enrollment scan. The choice
  is saved as `pulse_min_tier`, and every later approval is verified against
  it. A saved value Guard cannot read counts as `high`, so a damaged or edited
  setting can only make the check stricter. Changing it means turning Pulse
  off and setting it up again.
- **Each settings change is its own approval.** A Pulse-protected settings
  change names itself as `params.settings_change`, one of `save` (with the
  settings), `update_channel` (with the channel), `reset` or `pulse_disable`.
  The resident derives the `action` and `subject` from it
  (`approval_gate_settings_binding.rs`); a save is bound to a digest of the
  change, keyed with the daemon's auth token, that leaves out how the change
  is approved. The binding goes into the Pulse request and is checked again
  when the change is applied (`require_settings_write`, `disable_pulse`), so
  an approval for one settings change cannot complete another. A request that
  names a settings change may not also name its own `action` or `subject`.
- **No fallback.** In Pulse mode a password or TOTP code is refused
  (`approval_gate_pulse_required`), `unlock_cooldown` is refused, and TOTP
  enrollment is refused.
- **The authenticator is paused, not deleted.** If TOTP was set up, Pulse
  setup keeps its secret and replay counter in the secret store, sets
  `totp_enabled` to false and records `totp_paused_by_pulse`. No code is
  accepted while Pulse is on. Turning Pulse off (with a Pulse approval, with
  recovery, or by turning the gate off) brings the same authenticator back,
  if its secret is still stored. An unfinished TOTP setup is dropped.

## Time limits

| Limit | Value | Source |
| --- | --- | --- |
| Time to approve in the YID app (`decision_window_seconds`) | 15 minutes | Pulse's default |
| Request deadline (`intent_expires_at`, signed into the receipt as `yanez_consent_not_after`) | Decision window + 60 s | Leaves Guard time to collect a last-second approval; Pulse enforces it too |
| Oldest receipt Guard accepts | 15 minutes after approval | Pulse's recommended `max_age_seconds`; in practice Guard verifies within seconds |
| Approval dated in the future | Refused beyond 60 s | Pulse's verification checklist |
| CLI and dashboard wait | 16 minutes | Decision window + deadline margin |
| Pulse cooldown | Off by default; 15 minutes or 1 hour if chosen | Guard's existing cooldown options, scoped to purpose, scope and session; strict purposes never use it |

## What the YID app shows

For a single queued approval, the runtime reads Guard's own stored request
(`approval_requests` in `guard.db`, read only), keyed by the
`approval-request:<id>` subject the approval is already bound to. It never
takes these values from the caller, so a caller cannot make the phone describe
a different action from the one the grant is issued for.

| Row | Value | How it is made safe |
| --- | --- | --- |
| Request | The purpose label, for example "Approve an agent action Guard paused" | Fixed text per purpose |
| Program | The names of the programs being run, for example `rm` or `curl \| sh` | Guard's shell parser; file names only, no flags, arguments, paths, redirects or environment values; at most 4 parts |
| Command | The command the agent wants to run, for example `rm -rf ~/client-acme/build --token=[redacted]`. Off by default; shown only after the user opts in (see below) | Shell line continuations are joined first. Guard's Guard Cloud secret filter (`cloud_scrub_text`) then runs on the whole command before anything is cut. Credentials it does not know by name become `[redacted]`: URL user info (`https://user:pass@host`), `-u`/`--user` values with a password, `--pass`/`--pwd`/`--auth` values, the `-p`/`-a` passwords of `mysql`, `sshpass`, `docker login` and `redis-cli`, variables ending in `PWD`, `PASS` or `AUTH`, and every request header value except `Content-Type`, `Accept`, `User-Agent` and similar. The user's home folder, and any other folder under `/Users`, `/home` or `C:\Users`, becomes `~` wherever a path can start (after a space, quote, `=`, redirect, `@`, `,`, `\|`, `;`, `&`, a slash as in `file:///`, or a short flag as in `-I/home/...`). Control and invisible characters are dropped; at most 300 characters |
| Agent | The harness, for example "Codex" | Known harnesses mapped to names; other ids only if they are plain identifiers |
| Request type | For example "Tool call" or "Package install" | Mapped from a closed list of Guard request kinds; others left out |
| Risk level | high, medium or low | Same rule Guard uses for Guard Cloud (`review_contracts._risk_category`) |
| Reason | Guard's risk headline, for example "Deletes files." | Through Guard's Guard Cloud secret filter (`cloud_scrub_text`) |
| Match code | Six characters from the binding HMAC | Random, shown on both screens |

Every other value is one line of at most 120 characters. If the command would
take the terms over Pulse's 4 KB limit, the Command row is left out and the
request is still sent. The notification headline stays the short program
summary. Settings changes, policy clears and other Guard-internal purposes show
only their purpose label. A bulk approval shows its count, programs, agents,
request types and highest risk level, never the commands.

### Opting in to the command

The Command row is off by default, including on Guards set up before this
setting existed: the phone shows the program names, risk summary and match
code, as agreed for #7236 to #7490. The filtering above is pattern based and
best-effort, so it cannot promise to catch every secret.

A user who wants the command on the phone opts in on the Yanez Pulse card in
Settings ("Show the command in the YID app") or with
`hol-guard settings approval-pulse show-command on`. Both first explain what is
sent to Yanez Pulse and that the filtering is best-effort; the dashboard asks
the user to confirm, and the CLI needs an interactive terminal and a typed
`yes`. Both then send a settings save that names only `pulse_show_command`, so
the YID app approves exactly that change. The resident enforces this itself:
when a settings update names `pulse_show_command`, it accepts only a grant
bound to a save of exactly those `approval_gate` fields
(`gate_save_binding`), so a grant approved for another change cannot turn
sharing on or off, and no other field can ride along. Turning it off works the
same way without the explanation.

The setting lives in the approval gate state (`pulse_show_command`; only an
explicit `true` shows the row) and is reported in the public gate config.
While Pulse is off the config reports `false`, and saving `true` is refused
with `approval_gate_pulse_not_enabled`. Turning Pulse off clears it with the
other Pulse settings, so a new setup starts with the command off.

## Changes and why

### New Rust crate: `rust/crates/guard-yanez-pulse`

| File | What | Why |
| --- | --- | --- |
| `src/lib.rs` | `AssuranceTier`, `PulseError` with stable codes, statuses and user-safe messages | One error type, so every failure maps to a fail-closed gate error and never leaks receipt or key material |
| `src/jws.rs` | Ed25519 compact-JWS verification (via `ring`) and JWK-set parsing | Verify Yanez's signature offline; pin `EdDSA`; select by `kid`; refuse ambiguous `kid`s |
| `src/user_sig.rs` | BLS12-381 verification (via `blst`) over the exact signed bytes | Pulse requires verifying the approver's own device signature, not just Yanez's |
| `src/strict_json.rs` | Duplicate-key-rejecting parser; Pulse structural equality; safe-integer rules | Pulse requires these exact parse and compare rules; works with the workspace's `arbitrary_precision` serde_json |
| `src/terms.rs` | Builds terms from an action binding and an `ActionSummary` (one-line, length-capped rows, and a Command row of up to 300 characters that is dropped first if the terms would pass 4 KB); HMAC binding; match code; consumer token | Bind each receipt to the exact action; show a short summary, and the filtered command when the user allows it, without sending secrets to Pulse |
| `src/terms_command_tests.rs` (new) | 5 tests: row order, length, one line, never for a batch, dropped before the size limit | See Tests |
| `src/receipt.rs` | `verify_receipt`: the ordered checks above | One auditable place for every receipt check |
| `src/client.rs` | `PulseTransport` trait and the HTTPS client (`ureq`, rustls, HTTPS only, no proxy, no redirects, capped bodies, short timeouts); only the production Yanez host, `yid.yanez.ai` | Nothing an agent writes can point Guard at another server; outages map to `approval_gate_pulse_unavailable` (503) |
| `src/testkit.rs` (feature `testkit`) | Fake Yanez deployment that signs with real Ed25519 and BLS keys | Acceptance tests exercise real cryptography, not mocks |
| `src/receipt_tests.rs` | 15 receipt acceptance vectors | See Tests |

### Resident (`rust/crates/guard-runtime`)

| File | What | Why |
| --- | --- | --- |
| `approval_gate_pulse.rs` (new) | `pulse_request`, `pulse_poll`, `verify_pulse_stage`, config loading, error mapping | The Pulse factor, split so no network wait happens inside the gate's critical section |
| `approval_gate_pulse_store.rs` (new) | Transport seam, Yanez key cache (10 min), pending-request table (in memory, ≤16 per home), MAC'd Pulse cooldown record, local `jti` ledger | Resident-side state; no lock held across HTTP |
| `approval_gate_pulse_enrollment.rs` (new) | `begin`, `confirm`, `disable`, `recover`; the minimum face scan (`min_tier`) | Enrollment needs the current factor and a verified enrollment receipt at the chosen floor. Disabling needs a fresh Pulse grant bound to turning Pulse off. Recovery needs the password and the one-time code |
| `approval_gate_settings_binding.rs` (new) | Derives the `action` and `subject` of a settings write from `params.settings_change` | What an approval for a settings change covers is decided in the resident, not by the caller |
| `approval_gate_pulse_summary.rs` (new) | Reads the stored approval request and reduces it to the YID app summary | What the phone shows comes from Guard's own record, never from the caller |
| `approval_gate_pulse_summary_tests.rs` (new) | 12 tests: program names, risk level, secret filter, closed lists, store lookup | See Tests |
| `approval_gate_pulse_command.rs` (new) | The command the YID app shows: line continuations joined, secret filter on the whole command, extra credential rules, user folders as `~`, one line, cut at 300 characters; also the `pulse_show_command` switch | The user sees what they approve; secrets and the account name stay on the machine |
| `approval_gate_pulse_command_tests.rs`, `approval_gate_pulse_command_flow_tests.rs` (new) | The filter and folder rules, and end to end: what reaches Pulse, the default, the switch needing a YID approval, and the switch without Pulse | See Tests |
| `approval_gate_settings.rs`, `approval_gate_state.rs`, `approval_gate_pulse.rs` | `pulse_show_command` in the settings save and the public config; the Pulse request adds the command only while it is on | One opt-in, changed only through a settings save the resident checks is bound to exactly that change |
| `approval_gate_pulse_tests.rs` (new), `approval_gate_pulse_review_tests.rs`, `approval_gate_pulse_binding_tests.rs`, `approval_gate_settings_binding_tests.rs` | Acceptance tests through the real wire op, plus the cases found in review | See Tests |
| `approval_gate_verify.rs` | Pulse branch at the top of `verify_or_raise_locked`; Pulse fields on the gate input | Pulse replaces both factors, the way TOTP replaces the password |
| `approval_gate_grants.rs` | A strict check accepts `["pulse"]` as well as `["password"]` | Strict purposes (settings, policy clear and similar) must work in Pulse mode. A Pulse grant can only exist in the factor generation Pulse was enrolled in |
| `approval_gate_settings.rs` | Pulse fields in the public config; explicit `pulse_cooldown_seconds`; turning the gate off ends Pulse; revoking the cooldown also closes a Pulse cooldown; `unlock_cooldown` is refused in Pulse mode | A password must never open a window the Pulse factor guards |
| `approval_gate_pulse_enrollment.rs` | Setup step 1 (`authorize_only`) checks the password and authenticator code on their own and lets the same session start setup with only the agent key for 15 minutes; tied to the session and the factor generation, held in memory only, ended by enrollment | The dashboard asks for the password first, like the authenticator setup, without a six-digit code expiring while the user pastes the agent key |
| `approval_gate_enrollment.rs` | TOTP enrollment is refused while Pulse is on | Otherwise a password alone could add a second, weaker approval path, or replace the paused authenticator |
| `approval_gate_state.rs` | Public config gains `pulse_enabled`, `pulse_cooldown_seconds` | Dashboard and CLI show the same state |
| `approval_gate_op.rs` | Dispatch for the six new methods | Wire entry points |
| `daemon_route_paths.rs` | `/v1/approval-gate/pulse/{enroll,confirm,poll,disable,recover}` require the header token and are dashboard-session paths | The same protection as the TOTP routes |
| `Cargo.toml`, `lib.rs` | Depend on `guard-yanez-pulse`; register modules | |

### Wire contract (`rust/crates/guard-contracts/src/approval_gate.rs`)

The input gains `pulse_request_id`, `pulse_agent_key` and `pulse_recovery_code`.
The new methods are `pulse_request`, `pulse_poll`, `begin_pulse_enrollment`,
`confirm_pulse_enrollment`, `disable_pulse` and `recover_pulse`. The grant
shape is unchanged: Pulse grants carry `factor_set: ["pulse"]`, so the existing
Python and dashboard grant decoders keep working.

### Python (thin glue only)

| File | What | Why |
| --- | --- | --- |
| `approval_gate_pulse.py` (new) | `request_pulse_approval`, `poll_pulse_approval`, `await_pulse_approval`, `_with_pulse`, enrollment wrappers | One retry path for every grant call, so the CLI and dashboard approve the same action the same way |
| `approval_gate.py` | Grant-issuing calls go through `_with_pulse`; re-exports | Pulse support without changing the 18 CLI call sites |
| `approval_gate_types.py` | `ApprovalGateInput` gains `pulse_request_id`, `pulse_agent_key` and `pulse_recovery_code` (hidden from `repr`), plus `pulse_mode` and `pulse_on_status`; `ApprovalGateError` can carry `details`; the config decoder reads the Pulse fields | `details` carries the request id and match code back to the dashboard |
| `approval_gate_state.py` | Public config Pulse fields | Parity with Rust |
| `native_approval_gate.py` | Sends the Pulse input fields; new config-returning methods | Bridge |
| `cli/approval_gate_prompt.py` | In Pulse mode, returns a "wait" input and prints the match code | `hol-guard approvals approve` and every other prompt get Pulse automatically |
| `cli/approval_pulse_commands.py` (new), `commands_parser_policy.py`, `commands_dispatch_records.py` | `hol-guard settings approval-pulse status / enroll [--min-tier medium\|high] / disable / recover / show-command on\|off`. Setup sends new users to `https://pulse.yanez.ai/?referrer_id=holguard` for the YID app, the same link as the dashboard; every Pulse command's `--help` also links Yanez's Pulse docs | Secrets read only with `getpass`; never from arguments or environment variables. The `referrer_id` only names HOL Guard as the source of the visit; it carries nothing about the user or the machine |
| `cli/approval_gate_prompt.py`, `cli/extension_controls_commands.py` | `submit_with_pulse`: a daemon-bound CLI command asks for a Pulse request for the exact mutation, waits for the YID app and sends the same payload again | Extension changes from the CLI work in Pulse mode |
| `daemon/server_control_pulse.py` (new), `server.py`, `server_control_routes_post.py` | Daemon routes for setup (passing `min_tier`), poll, disable and recover; dispatch matches only the five exact paths the token check covers | Dashboard setup flow; no other path reaches a Pulse handler |
| `daemon/server_control_repair.py`, `config.py` | Settings save, update channel and reset name their `settings_change` | Each settings change is its own approval |
| `daemon/extension_control_errors.py`, `extension_control_api.py` | A Pulse refusal keeps its code and the request to approve | The CLI and dashboard can wait for the YID app and send again |

### Dashboard

| File | What | Why |
| --- | --- | --- |
| `pulse-approval.ts` (new) | Inside `fetchWithGuardAuth`: on `approval_gate_pulse_required`, retry once in defer mode, wait for the YID app, resubmit with the request id; rejection, expiry and outage become errors | Every gated request gets Pulse with no per-call-site change, and a 202 is never mistaken for success |
| `pulse-approval-overlay.tsx` (new), `app.tsx` | Toast with the match code and status | The user can check that the YID app shows the same request |
| `pulse-settings-panel.tsx`, `pulse-setup-modal.tsx` (new), `settings-workspace.tsx` | "Yanez Pulse" card below the authenticator card, and a three-step setup window styled like the authenticator one: 1) approval password, plus the authenticator code when it is on; 2) the YID steps, the hidden agent key field, the face scan ("Standard face scan (recommended)" sends `min_tier: medium`, "Strict face scan" sends `high`) and the cooldown, with the YID app link `https://pulse.yanez.ai/?referrer_id=holguard` (the `referrer_id` names only HOL Guard as the source of the visit); 3) the match code while Guard waits for the scan, then the one-time recovery code. Turn off and recovery stay on the card, with the "Show the command in the YID app" switch (off by default; turning it on first explains what is sent and asks to confirm; changing it asks the YID app, with Cancel while it waits) | Pulse is the named third option in Settings, set up the same way as the authenticator |
| `approval-proof-inline.tsx` | In Pulse mode, no password or code field; a "you will approve in the YID app" notice; no credentials sent | No local secret is needed or sent |
| `guard-api.ts`, `guard-types.ts` | Pulse API calls and config fields | |
| `pulse-approval.test.ts` (new), `package.json` | Dashboard tests, added to `npm test` | |
| `settings-save-proof-modal.tsx`, `home-dashboard.tsx` | In Pulse mode, "Save settings" and "Clear remembered decisions?" show a YID app notice and send no credentials | Pulse pauses the authenticator, so these windows must not ask for a password or code |

### Fixtures and docs

- `tests/fixtures/approval_gate/parity_vectors.json`: the four Pulse keys were
  added to every expected public-config payload (additive; 208 lines). The Rust
  vector tests and the Python parity test replay this file.
- `rust/crates/guard-runtime/tests/fixtures/daemon_route_vectors.json`: route
  vectors for the five new paths.
- `docs/guard/get-started.md`: user-facing Pulse section.

## How the requirements map

| Requirement | Where |
| --- | --- |
| Named third option, same experience in dashboard and CLI | Settings card and `approval-pulse` CLI; both approval surfaces go through `_with_pulse` to the same resident call (tested for identical Pulse requests) |
| Receipt bound to action, scope, session and nonce; freshness window | HMAC binding; 15-minute decision window (Pulse's default) plus 60 s deadline margin; 15-minute maximum age |
| Verify Pulse and user signatures, pinned YID and issuer, tier, single use | Checks 1–10, the ledger, and introspect-consume |
| Minimum assurance chosen by the user | `min_tier` at setup (medium by default, or high), saved and checked on every approval; an unreadable value counts as high |
| One approval covers one settings change | `settings_change` bindings derived in the resident and checked when the request is verified and when the change is applied |
| No sensitive data to Pulse | The command only after the secret filter and with user folders as `~`, and only after the user opts in (off by default; the opt-in explains that filtering is best-effort and needs a YID approval the resident binds to exactly that change); otherwise program names, the agent, the request type, the risk level, the filtered headline, a match code, an HMAC and a nonce (tested end to end) |
| Fresh approval per action by default; cooldown explicit and tightly scoped; high-impact always fresh | Cooldown defaults to 0. A cooldown covers only the same purpose, scope, session and factor generation, its record is MAC'd, and strict purposes never use it |
| Rejection, expiry and outage fail closed | Tested in Rust, Python and the dashboard |
| Recovery without an agent-accessible bypass | Password (PBKDF2 verifier) plus a one-time recovery code stored only as a SHA-256 hash; secrets only through `getpass` or the dashboard form |
| Polling holds no authorization lock | One bounded resident op per poll; table locks are never held across HTTP |
| Hard block never creates a Pulse request | `pulse_request` refuses any `verdict` other than `review` or `require-reapproval` (tested) |
| Tests: parity, replay, wrong YID, low assurance, timeouts, revocation, key rotation | See below |

## Tests

| Suite | Count | Result |
| --- | --- | --- |
| `cargo test -p guard-yanez-pulse` (receipt vectors, parsers, terms and summary rows, the command row, client parsing) | 55 | pass |
| `cargo test -p hol-guard-runtime --lib approval_gate` (Pulse acceptance, review cases, minimum face scan, settings-change bindings, summary, the command shown, its opt-in and binding, the credential and path filters, and all existing gate parity vectors) | 151 | pass |
| `pytest tests/test_guard_approval_gate_pulse.py` (CLI/dashboard parity, defer, wait, cooldown, fixed scopes, secret handling, settings saves, minimum face scan, settings-change bindings, extension changes, CLI links, the show-command opt-in) | 46 | pass |
| The Python approval-gate, Pulse, native parity, daemon-route, bridge, cooldown prompt, nudge and settings API suites together | 251 | pass |
| `tsx src/pulse-approval.test.ts` (resubmission, reject, expire, outage, pass-through, deadline, a stalled check, proof fields, face scan choice, setup refusals, short request deadlines, overlapping approvals, closing setup, closing setup while it starts, the setup link, bulk count, Pulse-mode wording, the show-command switch) | 20 cases | pass |
| Existing dashboard tests: approval-gate, guard-api, queue-bulk-approve, settings-workspace, settings-save-proof-modal, approval-retry-ux | | pass |

Acceptance cases covered in Rust: accept; reject; expiry; pending is not
approval; wrong YID (both a receipt and the registry); wrong issuer; wrong agent
key; wrong request; a low scan refused while medium and high pass; setup refused without a medium-capable device; replay (pending taken,
local ledger, remote consume); action, scope and session binding; terms
tampering; forged Yanez and user signatures; `alg: none`; future-dated
decision; stale and consent-expired receipts; outage at request and at
verification; hard block; scoped cooldown and the fresh default; a forged
cooldown record; agent-key revocation; device removal and downgrade; a device
Guard did not pin; Yanez key rotation through a refresh; user key rotation; enrollment needing the current
factor and the same session; enrollment ending older grants; disable needing a
Pulse grant bound to turning Pulse off; recovery needing both secrets; a high
floor refusing a medium scan, needing a high-capable device and a high
enrollment scan, and an unreadable saved floor counting as high; an approval
for one settings change (update channel, reset, turning Pulse off, a save)
refused for another, in both directions and for a different channel.

The resident-backed Python suites need the native runtime forced, as in CI
(`HOL_GUARD_NATIVE=force`, with `HOL_GUARD_NATIVE_BINARY` and
`HOL_GUARD_NATIVE_SOURCE_COMPILER` pointing at a release build); without it
they fail with "The native approval authority did not answer". Local Rust
checks used 1.88, the version CI pins.

## Known gaps and follow-ups

1. **QR enrollment.** Pulse has no pairing feature today, so enrollment by QR
   code is not possible and setup pastes an agent key (hidden, never logged).
   This could be worked on with Yanez.
2. **Device keys: Yanez can remove, only Guard can add.** The `user_keys`
   registry has no revoked flag; Yanez removes a device by dropping its key
   from the list. Guard reads `user_keys` on every verification, so a removed
   device stops working at once. The registry and the receipts share an
   operator, so Guard does not trust the registry to add devices: it pins the
   approver keys at enrollment and refuses any other key. Using a new device
   means setting up Pulse again. A confirm-this-device step in the dashboard
   and CLI would avoid that, if Yanez exposes a fingerprint the YID app can
   show for comparison.
3. **Desktop app.** The Desktop child flow (`HOL_GUARD_DESKTOP` with an
   environment password) is not Pulse-aware. In Pulse mode the CLI falls back
   to its wait prompt, so the Desktop UI needs a "waiting for YID app" state.
4. **Dashboard end-to-end tests.** Unit tests cover the request layer. Add a
    Playwright spec in `dashboard/e2e/` for setup and for approving a queued
    item with a fake Pulse.
5. **Strictness hint.** For `require_approval_decision` the Python side sends
    `strict = (scope == "global")` with the Pulse request. If the resident
    treats more actions as strict, the only effect is that a cooldown is not
    used, which is the safe direction.
6. **Approval invariant.** Pulse changes only the proof that unlocks the gate.
    Allow once, Always allow and saved approvals are unchanged.
