# Alpha rollback runbook

Use this when a published main alpha (`X.Y.0aN`) is bad: hooks fail, Core will not start, or
an update strands installs. The goal is to stop new installs and updates from picking the bad
alpha within minutes, then ship a fixed alpha.

On 2026-11-13, alpha 3.60.0a83 closed every hook. The fix (#7674) took about three hours to
reach users. Most of that was the time to diagnose and fix. Withdrawal was not used, and the
publish pipeline itself takes about 30 minutes. This runbook covers both: withdrawal first,
then the fix-forward.

## Who may run it

| Step | Who |
| --- | --- |
| Dispatch **Delete alpha release** | Only the maintainers whose GitHub actor IDs are `6068672` or `301892678`. The workflow refuses anyone else. |
| Yank on PyPI | A PyPI owner or maintainer of the `hol-guard` project, signed in at pypi.org. Trusted publishing tokens cannot yank, and PyPI has no yank API. |
| Ship the fix-forward alpha | Anyone who can dispatch **Release Please** on `main`. |

## 1. Withdraw the alpha (about 5 minutes)

```bash
gh workflow run delete-alpha-release.yml --repo hashgraph-online/hol-guard --ref main -f version=3.60.0a83
```

The workflow runs two jobs.

**`delete`**

1. It checks the actor ID and the `X.Y.0aN` shape.
2. It checks that `alpha/v<version>` is a prerelease cut from `main`. Release-train alphas are
   refused.
3. It deletes the GHCR image tag, then the GitHub prerelease with its Desktop Core sidecars,
   then the tag.

**`restore-alpha-feed`**

1. It finds the newest remaining live main alpha prerelease. This is the fallback.
2. It checks that the fallback carries signed Desktop Core sidecars for both feeds:
   - `hol-guard-core-<v>-aarch64-apple-darwin.attested.json`
   - `hol-guard-core-<v>-x86_64-unknown-linux-gnu.attested.json`
3. If either sidecar is missing, it finds the fallback's successful `publish.yml` dispatch. It
   then dispatches `desktop-core-alpha-feed.yml` and/or `desktop-core-linux-feed.yml` for that
   version, the same way `wake-alpha-core-feed` does after a publish. The feed workflows
   re-verify the publication run, so they refuse a wrong run ID.
4. It reports in the run summary whether the bad version is yanked on PyPI and whether the
   fallback is live. If the bad version is not yanked yet, it raises a warning.

If the fallback has no macOS sidecars and the feed fails at notarization, macOS Desktop's Alpha
channel has nothing to fall back to. This happened after a82 because of the Apple developer
agreement. Fix that first, or ship the fix-forward alpha.

There is no feed pointer to repoint. The Alpha channel always reads the newest live
prerelease, so deleting the bad one is what makes the feed fall back.

## 2. Yank on PyPI (about 1 minute, by hand)

1. Open `https://pypi.org/manage/project/hol-guard/release/<version>/`.
2. Choose **Options → Yank** and give the reason "withdrawn alpha".

Yank right away, even though the tag is already gone. Until the version is yanked:

- `pip install --pre hol-guard`, `uv pip install --prerelease=allow hol-guard` and
  `pipx install --pip-args=--pre hol-guard` still resolve it. These resolvers do not read
  GitHub tags.
- The CLI's Desktop Core updater (`update_desktop_core.py`) picks the newest non-yanked PyPI
  alpha without checking the tag. It then fails to download sidecars from the deleted release,
  instead of falling back.
- `hol-guard update --alpha` checks at most three of the newest alphas for a live tag
  (`MAX_ALPHA_LIVENESS_LOOKUPS`). Yanked versions are dropped before that budget is spent,
  while deleted-but-unyanked versions use it up. Two or three withdrawn alphas in a row that
  are not yanked can therefore hide every good alpha.

## What resolves after withdrawal and yank

| Client | Resolves | Why |
| --- | --- | --- |
| `pip install --pre hol-guard` | the newest non-yanked version | PEP 592: yanked files are ignored unless pinned exactly |
| `pip install hol-guard==3.60.0a83` | the bad version, with a yank warning | an exact `==` pin still matches a yanked file |
| `uv pip install --prerelease=allow hol-guard`, `uvx --prerelease=allow hol-guard` | the newest non-yanked version | uv follows PEP 592 the same way |
| `pipx install --pip-args=--pre hol-guard`, `pipx upgrade --pip-args=--pre hol-guard` | the newest non-yanked version | pipx resolves through pip |
| `hol-guard update --alpha` | the newest stable or live, non-yanked alpha | skips yanked files and alphas whose `alpha/v<v>` tag returns 404 |
| Desktop Alpha channel | the fallback's sidecars | it reads the newest live prerelease |
| CLI Desktop Core update | the newest non-yanked PyPI alpha | needs the yank, see above |

Installs already on the bad alpha are **not** downgraded: `hol-guard update` and the CLI's
Desktop Core updater only move to a newer version (`update_available` and
`_version_is_not_newer`). Those users need the
fix-forward alpha, or a manual pinned reinstall such as
`pipx install --force hol-guard==<fallback>`.

## 3. Ship the fix-forward alpha (about 30 minutes after merge)

1. Merge the fix to `main`.
2. Dispatch **Release Please** on `main`; `alpha_version` defaults to `next`:

   ```bash
   gh workflow run release-please.yml --repo hashgraph-online/hol-guard --ref main
   ```

3. `publish.yml` builds, publishes to PyPI and the prerelease, and wakes both Core feeds.
4. Check with `hol-guard update --alpha` on a machine that was on the bad alpha.

## Publish critical path

Measured on publish run 43435046051 (3.60.0a83, 33.3 minutes from dispatch to the Core feed
dispatch), with minutes counted from dispatch:

| Phase | Start | End |
| --- | --- | --- |
| Build and verify | 0 | 3.7 |
| Compile Windows ARM64 (cross on `windows-latest`) | 0.4 | 18.6 |
| Compile Windows x64 / macOS arm64 / macOS x64 / Linux x64 | 0.4 | 16.6 / 18.2 / 14.2 / 9.7 |
| Linux ARM64 wheel (compiles in-job) | 3.8 | 22.1 |
| Windows ARM64 wheel | 18.7 | 27.4 |
| Assemble, reserve tag, native assets | 27.4 | 30.6 |
| PyPI publish | 30.7 | 32.7 |
| Prerelease, Core feed dispatch | 32.7 | 33.4 |

The critical path is the Windows ARM64 compile, then the Windows ARM64 wheel (8.7 minutes:
3.9 to verify the native command program, 1.6 to verify the source compiler output and 1.7 to
rebuild the base wheel), then a serial tail of about 6 minutes. Eight alpha publishes on
2026-11-12 and 2026-11-13 took 26 to 34 minutes. The Windows ARM64 compile alone ranged from
10.5 to 18.8 minutes for the same work, so runner speed variance is the largest single term.

What was checked, and the result:

- **Thin LTO for alpha: nothing to gain.** Alphas already pass `fast_codegen`, which sets
  `CARGO_PROFILE_RELEASE_LTO=false` and 16 codegen units, and Windows targets also build the
  workspace at opt-level 1. Thin LTO would be slower than what alphas use now. Stable keeps
  `lto = "fat"`, `codegen-units = 1` and `opt-level = "s"` (`rust/Cargo.toml`).
- **Wheel jobs do not recompile.** With `precompiled: true` they install the prepared binaries
  and only verify them. The Linux ARM64 wheel is the one exception: it compiles in-job with the
  full release profile (16.4 minutes). It still finishes at minute 21 to 23 in every measured
  run, 4 to 6 minutes before the Windows ARM64 wheel, so moving it to the prepared matrix would
  not shorten the publish.
- **Native ARM runner for the Windows ARM64 compile: no gain.** Run 43478917203 compiled
  the alpha profile cold, with the same command, on both runners: 655 seconds cross-compiled on
  `windows-latest` and 651 seconds natively on `windows-11-arm`. The leg stays where it is.
- **Dependency cache: saved, then evicted.** The alpha `release-native-v1-fast-*` rust-cache
  entries are saved after each alpha (the post step uploads for 20 to 30 seconds), but none
  survives until the next alpha. The repository holds 11.2 GB of Actions cache across 285
  entries, over the 10 GB default, so LRU eviction removes them within the hour. The restore
  step took about 0.1 minutes in all eight runs, which means it never hit. sccache only wraps
  workspace crates, and those change on every alpha (3 hits and 27 misses in a83).

Proposals, with expected savings:

| Change | Saves on the critical path | Risk |
| --- | --- | --- |
| Withdraw with **Delete alpha release** instead of waiting for a fix | the whole fix-forward (about 30 minutes plus the time to fix) for new installs | none: it already exists, and now also restores the feed |
| Raise the repository's Actions cache limit, or stop caching per-PR keys that are never reused, so `release-native-v1-fast-*` survives between alphas | up to 3 to 4 minutes of dependency compile on each Windows leg; 0 if the cache is still evicted | none to output: rust-cache restores only dependencies |
| Run "Verify native source compiler output" next to the base wheel rebuild in the wheel job | about 1.6 minutes on the Windows ARM64 wheel | low; not done here because it changes the stable wheel job without a measured run |

None of these touch signing, notarization, attestation or the stable release profile.

## Proving an upgrade fix locally

`native-offline-upgrade` (`tests/test_native_pack_offline_upgrade.py`) is the CI job that
proves an installed client can upgrade across native engines without network access. It is the
check most likely to catch another a83. In CI it already reuses a cached build of the pinned
prior client (`native-offline-previous` hits its cache in 0.2–0.4 minutes). It starts as soon
as `native-command-evaluators` finishes (minute 7.2 of PR 7674's run), runs for 1.2 minutes,
and is not on the CI critical path; `macos-gates` is, at about 18 minutes.

So the time to save is the push-and-wait loop, not CI minutes. Run it locally before pushing:

```bash
scripts/ci/run_native_offline_upgrade.sh
```

The script reads `NATIVE_OFFLINE_PREVIOUS_SHA` from `ci.yml` and builds that client once into
`~/.cache/hol-guard/native-offline-previous/<sha>`. Every later run only rebuilds the current
checkout incrementally, then runs the test with the same environment CI uses. Set
`SKIP_CURRENT_BUILD=1` to reuse the current binaries as they are.

The script pins CI's Rust toolchain (`1.89.0` from `.github/actions/setup-rust`), because older
local defaults cannot build the workspace. CI runs this test on Linux. On a loaded macOS
machine (2026-11-13), the script built both clients: the prior one in 11.5 minutes, once, and
the current one in 24 minutes cold. The test then timed out after 180 seconds in the
prior-client step, which takes seconds in CI. If that happens, run the script on a Linux host
or container, or rely on the CI job.
