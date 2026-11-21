# The Windows release gate runs on code no CI can test

Date: 2026-10-20
Status: finding, for a decision after 3.50.0 ships
Scope: `/windows-gauntlet` driver, not Guard runtime behaviour

## The finding

`/windows-gauntlet` is a release gate. The code that executes it is not in this
repository. It lives in `~/.agents/skills/windows-vm-ssh/scripts/`:

- `guard-gauntlet-windows.sh`
- `vm-lock.sh`
- `vm/`

Nothing in repository CI builds, lints, tests or regression-checks any of it. A
change there is unreviewed and unverified by construction. The same blind spot
produced the `validation_base` defect, where a Windows Gauntlet build exited 2
silently.

This matters more than an ordinary untested script, because a gate that cannot
execute does not fail loudly. It returns zero coverage, and zero coverage is easy
to read as "nothing went wrong".

## What happened on 2026-10-20

The Windows run against `f37b83ccea` produced `harness-error` on all 12 cases
with `tool_calls 0` and no final summary, driver exit 1. No Guard behaviour was
exercised in either direction.

The driver attributed this to a stale ChatGPT login. That attribution is wrong,
and so was this document's first reading of why.

### What the evidence actually shows

Two findings below come from the peer session that holds the VM lease. They are
recorded here as that session's evidence, not as something this session
reproduced; the per-case JSON is the primary record.

**The adapter is healthy.** `NativeLunaRoute` driven standalone on the VM — same
PATH, same SDK root, same Windows job object, same code path the runner uses —
reports `READY port=59430`, bound on 127.0.0.1, process alive and answering HTTP
at t=0/5/10/15/20/25s, adapter stderr empty. A real inference through it
(`POST /v1/chat/completions`, `stream=true`, `reasoning_effort=medium`) returned
a live SSE stream: keepalive, a content chunk, a `finish_reason=stop` chunk with
`usage.prompt_tokens=13`, `[DONE]`. Status 200, 521 bytes delivered, process
alive afterwards, stderr still empty.

So the adapter binds, survives idle, and serves real Luna inference on that VM
with this Mac's ChatGPT login. Adapter, login, loopback and Bun are all good.

**The adapter dies inside the run.** The per-case JSON for the single-case probe
(`f37b83ccea-a2`) records 32 live rounds:

- round 0: `ConnectionResetError` at `provider-connect`
- rounds 1-31: `URLError` at `provider-connect`
- all rounds: 0 bytes, 0.0s

That sequence is not "never started". A reset on the first request means the
adapter was listening and the connection reached it; the refusals that follow
mean the port was gone from then on. The adapter died at or during the first
request, in the run — and not when driven by hand.

Earlier drafts of this document read the `URLError` rounds alone and concluded
the adapter never bound. Round 0 refutes that, and the standalone run refutes it
twice over.

## Driver defects this exposed

1. **Wrong diagnosis.** "Stale login" fires on `URLError`, which cannot be an
   auth failure — a live provider rejecting a credential returns HTTP 401, which
   surfaces as `HTTPError`. It sent the operator to refresh a sign-in that was
   fine. Two negative controls: a force-resync changed nothing, and the login
   demonstrably works when the adapter is driven directly.
2. **A mid-run crash surfaces no error text.** `luna_route` calls `_stderr_tail`
   in `__enter__`, so adapter stderr is printed only when startup fails. An
   adapter that dies after a successful start throws its stderr away. This is why
   roughly 90 minutes of failures produced no error text at all, and why the
   first investigation chased authentication. A crash path that surfaces nothing
   is its own bug, independent of what the crash turns out to be.
3. **No fail-fast.** 329s elapsed against 0.0s per-round connects: the driver
   retried a dead port for the entire case budget.
4. **Doubled cost.** The self-resync then burned a second full attempt on the
   same dead port before giving up. One dead adapter cost roughly 90 minutes of
   release window.

Defect 4 is the expensive one. Defects 1-3 turn a 30-second error into a
90-minute one.

Two defects listed in the first draft of this document are withdrawn: "the
adapter is not waited for on bind" and "a previous adapter is not reaped". The
standalone run shows the bind is sound, and the single-case probe ran on a fresh
lease with nothing to be orphaned from.

## Leading cause, narrowed but not confirmed

The route is entered once in the runner parent via `ExitStack` and held for the
whole suite; cases run in separate worker processes that dial 127.0.0.1 on the
adapter's port. The leading candidate is Windows job-object ownership —
`KillOnCloseJob` in `luna_route` plus whatever job the worker or daemon lifecycle
creates — where closing a handle or terminating a job takes the adapter down on
first use. The driver's own assessment string, "host process or owned daemon
lifecycle did not complete", points the same way.

### The instrumented run (a3)

An instrumented single case ran on the VM at
`C:\Users\tester\hgw-gauntlet\runs\f37b83ccea-a3`, with a sampler taking
process counts every ~10s for the full length of the run, 22:32:03 to 22:41:11
PDT. Outcome unchanged:

    bounded-od-byte-check: harness-error - host process or owned daemon
      lifecycle did not complete
    tool_calls 0, successful_tools 0, blocked_tools 0, protocol_errors []
    pass=False merge_qualified=False scenarios=1
    EXIT=1

Every sample, without exception: `bun=0 py=2 omp=1 bunListen=0`.

Process tree from `Win32_Process` during the run:

    PID 8868  ...\hgw-gauntlet\src\.venv\Scripts\python.exe -m ci.gauntlet run ...
              (parent: powershell 6288)
    PID 4352  ...\gauntlet-tools\py312x64\python.exe -m ci.gauntlet run ...
              same args, child of 8868
    PID 6296  omp.exe --model gauntlet-live/agent --cwd ...\case-09\home\project
              child of 4352

The venv python is a uv trampoline stub re-execing the base interpreter. The
`py312x64` path appears only in the driver's `setup-tools.ps1` and
`build-guard.ps1`, never in this repository — another instance of the finding at
the top of this document.

What this establishes, and what it does not. A startup failure raises inside
`validate_ready()` and would abort before any case ran; cases did run, so the
adapter reached READY. Combined with `bun=0` at every sample, the adapter must
have died before the first sample — within roughly the first two minutes, and
consistent with the round-0 `ConnectionResetError`. `bunListen=0` throughout also
rules out an adapter alive but wedged on a different port.

But the sampler holds no sample with `bun=1`, so it did not observe the death
itself. It bounds the death to a window; it does not show the moment or what
closed the handle. The instrumentation did not achieve what it was aimed at, and
catching the transition needs a tighter interval or an event-based watch on
process exit. The job-object hypothesis remains a hypothesis.

Uniformity is worth recording separately: run a1 failed all twelve cases with
byte-identical `outcome`, `reason` and `tool_calls 0` — developer-settings-task,
watch-records-without-pausing, native-sibling-project,
mixed-native-source-secret-read-batch, quoted-unicode-source-reads,
search-pipeline-options, absolute-recursive-source-grep, bounded-stdin-filters,
bounded-od-byte-check, routed-git-and-workspace-writes,
security-documentation-is-data, sibling-project-copy-readback. Nothing here is
scenario-specific.

## The gate is unsatisfiable, not flaky

12/12 and 1/1 both yield `tool_calls 0`. There is no Guard signal in either
direction. This is not a Windows pass and not a Windows failure — it is no
coverage, and `/windows-gauntlet` cannot be satisfied until the adapter stops
dying on first use inside the run.

## The decision this asks for

Whether the code behind a named release gate should remain outside the repository
and outside CI. Options, in rough order of cost:

1. Leave as is. Accept that gate failures are diagnosed by hand each time.
2. Vendor the driver into the repository with unit coverage on the error
   classification and on surfacing adapter stderr for a mid-run death, even
   though its integration path still cannot run in CI.
3. As 2, plus a cheap liveness preflight the gate runs before the catalog: start
   the adapter, assert the port accepts a connection, fail in seconds with a
   truthful reason if it does not.

Option 3 would have turned 90 minutes into under a minute for a startup failure,
but note what it does and does not do here: this adapter passes a liveness check.
It dies on the first real request. A preflight makes a dead-on-arrival adapter
cheap to diagnose; it would not have caught this one. Defect 2 — printing the
stderr of an adapter that dies mid-run — is the change that would actually have
shortened this investigation.

## Bearing on the 3.50.0 release

`/windows-gauntlet` was named as a release gate. As of this writing it cannot
execute, so it cannot be satisfied by waiting or by re-running. The release
therefore faces a choice that is not a technical one:

- Hold 3.50.0 until the driver's adapter lifecycle is repaired and the gate
  runs for real against the shipping head.
- Ship 3.50.0 qualified on macOS alone, with the Windows gate disclosed in the
  release notes as not run — not as passed, and not as waived silently.

Whichever is chosen, the honest claim is that Windows has zero gauntlet coverage
for this release, not that Windows passed.
