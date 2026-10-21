# Harness version coverage

Guard can tell you whether the version of an AI app installed on your machine
has been tested with the Guard release you are running. The dashboard shows
this under **App coverage** and on each app's detail page.

Version coverage is information only. It never changes what Guard allows,
blocks, or asks you to approve, and it never installs, upgrades, or downgrades
an app.

## What the states mean

| State | Meaning |
| --- | --- |
| **Tested version** | Guard has retained evidence that this exact app version passed an eligible suite with this Guard release on your platform. The detail page shows which protection events the evidence covers. **Tested · some events** means the evidence covers only part of what Guard protects for that app. |
| **Untested version** | Guard found an exact version, but it is not in the tested set for this Guard release and platform. Protection still runs; it just has not been verified against that version. Newer, older, and in-between versions are all untested: Guard never infers coverage from a range or from nearby versions. |
| **Untested · acknowledged** | You acknowledged the warning for this exact version and installation. The warning returns automatically when the version, the installation, Guard's coverage data, or the Guard release changes. Use **Show warning again** to clear the acknowledgement yourself. |
| **Version unknown** | Guard could not determine one exact version. Common reasons: the app was not found, its package metadata is missing or malformed, more than one installation reports different versions, the last check is out of date, or the running daemon is too old to report coverage. Unknown versions cannot be acknowledged. |
| **Coverage unavailable** | Guard found a version but has no tested versions recorded for this app on this Guard release and platform. |

Apps that Guard has no reliable version source for do not show a version
label.

## Supported apps

| App | Version source |
| --- | --- |
| Oh My Pi (`omp`) | The `@oh-my-pi/pi-coding-agent` package metadata next to the installed `omp` command. A standalone binary is checked with a bounded `omp --version`. |

A release bundles Oh My Pi coverage records only once evidence is promoted for
it (see below). Until then Oh My Pi shows **Coverage unavailable**.

## How Guard checks the version

- Guard looks at the `omp` command on `PATH` and the usual user install
  locations, follows links to the real install, and skips Guard's own
  launchers.
- It prefers the installed package's metadata. It runs `--version` only for a
  standalone binary, with a fixed argument list, a short timeout, a private
  working directory, and a minimal environment.
- If two installations disagree, the result is **Version unknown** rather than
  the most favorable version.
- Results are cached for a few minutes and refreshed when the installation
  changes, after Guard installs or repairs the app, or when you choose
  **Check again**.
- The dashboard receives the version, its source, and when it was checked. It
  never receives file paths or raw command output.

Acknowledgements are stored locally in
`harness-version-acknowledgements.json` in the Guard home directory.

## Dashboard API

`GET /v1/harnesses` adds a `version_compatibility` object to each item. Older
daemons omit it, and the dashboard renders that as **Version unknown**.

| Route | Purpose |
| --- | --- |
| `POST /v1/harness-versions/refresh` | Re-check one app's version. |
| `POST /v1/harness-versions/acknowledge` | Acknowledge the current untested version. The body must echo the `acknowledgement.key` from the current payload; a stale key returns `409`. |
| `POST /v1/harness-versions/clear-acknowledgement` | Remove the acknowledgement for one app. |

All three require the daemon token or a dashboard session.

## Maintainers: coverage data and evidence promotion

The bundled manifest is
`src/codex_plugin_scanner/guard/schemas/harness_version_coverage_v1.json`
([schema](schemas/harness-version-coverage.v1.schema.json)). The runtime
validator in `codex_plugin_scanner.guard.harness_versions.manifest` is
authoritative; it rejects the whole manifest on any defect, and the dashboard
then shows **Coverage unavailable** for every app whose version Guard detected
(apps without a detected version still show **Version unknown**).

### Eligibility

A record may be added only when all of these hold:

- `harness_version` is one exact version. Ranges, wildcards, and partial
  versions are rejected.
- `guard_version` is the exact Guard release the evidence ran against.
  Records for any other Guard version do not apply at runtime, and the
  release check below fails if one is still bundled.
- `suite.id` is an eligible suite for that harness and `suite.result` is
  `passed`:

  | Suite | Harness | Transport | Events it can claim | Evidence level |
  | --- | --- | --- | --- | --- |
  | `pi-exact-continuation` | `omp` | `managed_extension` | `PreToolUse` | `unit_test` |
  | `guard-gauntlet-full-task` | `omp` | `managed_extension` | `UserPromptSubmit`, `PreToolUse`, `PostToolUse` | `live_block` |

- `events` lists only events the suite exercised and the adapter declares.
- `platforms` lists only the platforms the run covered.
- `evidence_reference` links to the retained run or artifact in this
  repository.

These do **not** establish coverage:

- bumping the SDK pin in `ci/pi-exact-continuation/package.json` or a
  dependency update;
- a passing endpoint or adapter unit test on its own;
- a version observed on a developer machine;
- evidence for a nearby version.

### When promotion happens

Promote on the **release PR** (the Release Please PR), never on a feature
branch. There `__version__` already holds the version being released, and the
promotion command reads it, so the record is bound to the build that ships. A
record promoted earlier names an older Guard version and stops applying at
runtime the moment the version changes.

The harness version to record is the one the release pins: the exact version
the qualifying run exercised.

### What evidence each level needs

| Record | Evidence | Command flags |
| --- | --- | --- |
| `unit_test`, `PreToolUse` only | A green `pi-exact-continuation` run (the `ci/pi-exact-continuation` suite) against the pinned harness version. | `--suite pi-exact-continuation` |
| `live_block`, all three events | A passing full Gauntlet qualification (`guard-gauntlet-full-task`) against the exact harness version, on the release candidate. | `--suite guard-gauntlet-full-task` |

A `unit_test` record never supports a `live_block` claim: the command rejects
events or an evidence level the suite does not reach. List one `--platform` per
platform the run covered, and point `--evidence-reference` at the retained run
or artifact in this repository.

### Promote

1. On the release PR, confirm the run passed and retain its artifact.
2. Run the promotion command, once per exact version:

   ```sh
   python scripts/ci/promote_harness_version_coverage.py \
     --harness omp \
     --harness-version <exact version> \
     --suite guard-gauntlet-full-task \
     --evidence-reference https://github.com/hashgraph-online/hol-guard/actions/runs/<run id> \
     --platform darwin-arm64 --platform linux-x86_64 \
     --prune-stale
   ```

   It reads the Guard version from `codex_plugin_scanner.version.__version__`,
   validates the record with the same code Guard runs at load time, writes it,
   and bumps `revision` (a new revision re-shows the warning for anyone who
   acknowledged an untested version). It refuses an ineligible suite, events or
   evidence level the suite does not support, a reference outside this
   repository, an inexact version, a record over the per-harness limit, or a
   manifest over the size limit, and leaves the file untouched when it does.
   Promoting a version that is already recorded replaces its record.
   `--prune-stale` removes records still bound to an earlier Guard version.
3. Run the checks:

   ```sh
   python scripts/ci/validate_harness_version_coverage.py --release
   python scripts/ci/validate_harness_version_coverage.py --wheel dist/<wheel>.whl
   ```

### Narrow or remove

If a later run fails, or evidence turns out to cover fewer events or platforms
than claimed, remove the affected events, platforms, or the whole record in the
same change that records the finding, and bump `revision`.

### Each release

Records are bound to a Guard version, so a new Guard release starts with no
applicable coverage. `--release` fails while any record names another Guard
version, and it runs in two places: the quality job on the Release Please PR,
and the stable build in `publish.yml`, so a stale record cannot ship even if the
PR check was bypassed. Alpha and canary builds do not run it: their versions
never equal the release a record is promoted for, and an alpha cannot promote
evidence yet. Re-promote each record with fresh evidence for the release, or
remove it.
