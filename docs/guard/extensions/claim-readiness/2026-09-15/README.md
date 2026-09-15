# Extension claim readiness — cohort proposals (2026-09-15)

**Status: PROPOSED.** Every sidecar in this directory and in
`contributions/extension-listings/` (as of this change) is a *proposal*. Proposed
IDs are not accepted IDs until the protected source review has approved and
merged them. Pull-request authorship, logins, repository membership, and commit
emails are attribution evidence only and never create publisher authority.

Prepared from Guard `2fbbdb333e625778fb8e5566e7ccf4c08c4abcb5` (main at
preparation time) plus a fresh read-only GitHub scan. All GitHub data below is
public: PR metadata and public numeric account IDs fetched through the GitHub
REST API (`users/<login>` and PR `user.id`).

## Why this exists

All seven published `claimPolicy: provenance` catalog entries had an empty
accepted `maintainerGithubIds` set, so no contributor could pass the claim
server's numeric-ID authority check. Merging the native contribution alone does
not fix this; the accepted mapping must land through a reviewed listing sidecar.

## Inventory method and bounds (read-only)

- Open PRs enumerated with `GET /repos/hashgraph-online/hol-guard/pulls?state=open`
  at up to 5 pages x 100 (bound: 500). Observed: **60 open PRs, not truncated**
  (up from 58 in the 2026-09-14 review sample).
- Every open PR's files enumerated at up to 3 pages x 100 per PR (bound: 300
  files/PR). No PR exceeded the bound; no fetch failed.
- Candidates: PRs touching `contributions/extensions/*.json` (modern format),
  `contributions/mcp-servers/*.json` (MCP), or
  `contributions/extension-listings/*.json` (listing-only). Result: **20
  candidate PRs** = 18 modern-contribution, 2 MCP, 2 listing-bearing (one PR can
  span categories). Older formats: git history shows `contributions/` has only
  ever contained `extensions/` and `mcp-servers/`; no third format exists.
- Proposed contributions (open PRs) are kept distinct from approved cohort
  entries (the seven live catalog entries below).

## Resolution of the four unresolved cases from the 2026-09-14 review

The review could not match two PRs to a catalog entry and got 404s reading the
catalog at two pinned heads. Root causes, verified at the same pinned heads:

| PR | Contribution | Finding at pinned head | Root cause |
|---|---|---|---|
| [#2829](https://github.com/hashgraph-online/hol-guard/pull/2829) | `command.repro-surgeon` | Contribution file present (1476 B); kit adds `command_repro_surgeon_extensions.py` | `docs/guard/extensions/catalog.v1.json` does not exist at the PR head (HTTP 404): the branch predates the catalog's introduction on main (2026-09-07, #2835). Reading the generated catalog at that head 404s; the kit itself is complete. |
| [#2813](https://github.com/hashgraph-online/hol-guard/pull/2813) | `command.dispat` | Contribution file present (1035 B); kit adds `command_dispat_extensions.py` and docs | Same: generated catalog absent at head (HTTP 404). PR opened 2026-09-06, before the catalog existed on main. |
| [#2821](https://github.com/hashgraph-online/hol-guard/pull/2821) | `command.routed` | Contribution file present (1184 B); kit adds `command_routed_extensions.py` | Generated catalog is present at head (69 entries) but does not contain `command.routed`: contributors do not regenerate the catalog. The generated projection is a maintainer/exporter artifact on main. |
| [#2818](https://github.com/hashgraph-online/hol-guard/pull/2818) | `command.rungs` | Contribution file present (1321 B); kit adds `command_rungs_extensions.py` | Same: stale, non-regenerated generated catalog at head (67 entries). |

None of the four is rejected or broken; all four were misreads of the generated
projection at PR heads. All four receive proposals below.

## Live cohort entries (approved, on main) — proposed sidecars

Sidecars live at `contributions/extension-listings/<id>.json`. Regenerating the
catalog through `scripts/export_extension_directory.py` changed exactly six
entries' `maintainerGithubIds` (presentation fields match exporter defaults, so
nothing else moved).

| Entry | Native path (digest at `2fbbdb333e…`) | Merged via | Proposed claimant evidence | Proposed accepted set | Portal / freshness / notice status | Blocker |
|---|---|---|---|---|---|---|
| `command.blitcp` | `contributions/extensions/command.blitcp.json` (`sha256:76de69d3…`) | [#2757](https://github.com/hashgraph-online/hol-guard/pull/2757) | Upstream author `gekap` (github.com/gekap/blitcp), public ID 43109822 | `["43109822"]` | Portal projection on main still shows empty set → `portal_not_ready` until this PR merges and the projection refreshes; notice `no_mapping` today; becomes `eligible_for_notice` on sidecar merge | Protected review + merge of proposal |
| `command.noodle` | `contributions/extensions/command.noodle.json` (`sha256:ddca5224…`) | [#2757](https://github.com/hashgraph-online/hol-guard/pull/2757) | Upstream author `wilfredinni` (github.com/wilfredinni/noodle), public ID 23016174 | `["23016174"]` | same | same |
| `command.probe` | `contributions/extensions/command.probe.json` (`sha256:52d5017a…`) | [#2757](https://github.com/hashgraph-online/hol-guard/pull/2757) | Upstream author `crizant` (github.com/crizant/probe), public ID 8337876 | `["8337876"]` | same | same |
| `command.remote.essh` | `contributions/extensions/command.remote.essh.json` (`sha256:e7cea64f…`) | [#2674](https://github.com/hashgraph-online/hol-guard/pull/2674) | PR author = upstream author `matthart1983` (github.com/matthart1983/essh), public ID 13101478 | `["13101478"]` | same | same |
| `command.repo2nb` | `contributions/extensions/command.repo2nb.json` (`sha256:27ea5b9d…`) | [#2757](https://github.com/hashgraph-online/hol-guard/pull/2757) | Upstream is an org (github.com/repo2nb, ID 319718265); org IDs cannot be claimants and membership was not verified. No individual evidence. | *(empty — no IDs proposed)* | `no_mapping`; sidecar adds presentation only and deliberately leaves the accepted set empty | Reviewed attribution decision (who, individually, may manage this profile) |
| `command.skill-sunset` | `contributions/extensions/command.skill-sunset.json` (`sha256:fcd38eac…`) | [#2757](https://github.com/hashgraph-online/hol-guard/pull/2757) | Upstream author `ooocooc` (github.com/ooocooc/open-skill-sunset), public ID 49831444 | `["49831444"]` | same as live rows above | Protected review + merge of proposal |
| `mcp.filesystem` | `contributions/mcp-servers/mcp.filesystem.json` (`sha256:76029271…`) | [#2783](https://github.com/hashgraph-online/hol-guard/pull/2783) | Upstream is the modelcontextprotocol org; coverage packaged by PR author `kantorcodes`, public ID 6068672 | `["6068672"]` | same as live rows above | Protected review + merge; **explicit operator sign-off required** because the proposed claimant is the repository operator who packaged the coverage (a self-proposal), and org membership in modelcontextprotocol was not verified. If the reviewer declines, drop the ID from the sidecar — the entry then stays `no_mapping` and unclaimable |

## Incoming-PR proposals (staged, move after each PR merges)

Staged at `proposals/<contribution-id>.json`. Because the exporter rejects a
listing without a canonical native contribution on main, these must NOT be
copied into `contributions/extension-listings/` before their contribution PR
merges. After merge: copy the file, run
`uv run python scripts/export_extension_directory.py && … --check`, and the
merge of that listing-only PR triggers the existing claim-notice workflow
(newly added listing on an existing contribution → all its accepted IDs are
eligible).

| PR | Draft | Head SHA (scan) | Contribution ID | Contribution digest at head | Proposed accepted set (author public ID) | Checks / review signals at scan |
|---|---|---|---|---|---|---|
| [#2929](https://github.com/hashgraph-online/hol-guard/pull/2929) | no | `c461af9c79c9ca1b477d4e815f65ac87d8009f12` | `command.syngraphe` | `sha256:cbc2b57c91018…` | `["46894435"]` (`suffro`) | green |
| [#2930](https://github.com/hashgraph-online/hol-guard/pull/2930) | yes | `1ae894dfdc6ef38d8008ccd38e5458c427b90fd7` | `command.simgit` | `sha256:b657c8c904003…` | `["143023108"]` (`abendrothj`) | draft |
| [#2927](https://github.com/hashgraph-online/hol-guard/pull/2927) | yes | `d5626e4b77413a8017ad3ee189e4d7a6d8ffb16d` | `command.shellroute` | `sha256:63c5aba12f517…` | `["100252"]` (`cvl`; upstream is github.com/shellroute, not the author) | draft |
| [#2921](https://github.com/hashgraph-online/hol-guard/pull/2921) | no | `cf6c592ca73ae50b3f8559bcc1bb540d947f4fed` | `command.agi-memory` | `sha256:0032ef8acfe23…` | `["20184673"]` (`kdbhalala`) | review-bot check failing |
| [#2911](https://github.com/hashgraph-online/hol-guard/pull/2911) | no | `9e015ce32005f85440ec2e224e21f9d2b62f2cc8` | `command.codesage` | `sha256:23eb3af607cca…` | `["158724"]` (`iliaal`) | review-bot check failing; PR already carries its own listing proposal |
| [#2899](https://github.com/hashgraph-online/hol-guard/pull/2899) | no | `cd47af2b7dee9a295d36c4161c8166b65c16c677` | `command.errand` | `sha256:873368f266fec…` | `["1649445"]` (`lydakis`) | review-bot check failing |
| [#2895](https://github.com/hashgraph-online/hol-guard/pull/2895) | no | `be84994ee274ac9948c5557a118ef725dff0c6a3` | `command.kim` | `sha256:c0e3b32bccabf…` | `["97722446"]` (`pratikwayal01`) | green; dismissed review on earlier head |
| [#2893](https://github.com/hashgraph-online/hol-guard/pull/2893) | no | `01683f58ce6c5c5ac6666e187616058c78301b27` | `command.librarybridge` | `sha256:6403074e6185a…` | `["241708697"]` (`amcdev7`) | changes requested; review-bot check failing |
| [#2888](https://github.com/hashgraph-online/hol-guard/pull/2888) | no | `887f4dd665346342f1286fb60914449e93f02ca8` | `command.sandbin` | `sha256:afe022d2fc427…` | `["175192368"]` (`ayazdoruck`) | green |
| [#2884](https://github.com/hashgraph-online/hol-guard/pull/2884) | yes | `059ae267960f9cc7a2374be2759eda752b7a19a6` | `command.blaizio` | `sha256:eca7b6707f99f…` | `["52860236"]` (`benolimits`) | draft |
| [#2879](https://github.com/hashgraph-online/hol-guard/pull/2879) | yes | `0967b5f0735f6241e8a089171f2b781c8b1344f9` | `command.codex-migrate` | `sha256:38962fa9ce054…` | `["2702674"]` (`jsegeren`) | draft |
| [#2876](https://github.com/hashgraph-online/hol-guard/pull/2876) | no | `ec42875da5a327fa52484ed94d93d7f8857d54f4` | `command.vttforge` | `sha256:c3251e0559aa5…` | `["7094035"]` (`fcsouza`) | green |
| [#2832](https://github.com/hashgraph-online/hol-guard/pull/2832) | no | `57ec4d8ea18d75f82e9f6ab80ed4eee19c797128` | `command.where-are-we` | `sha256:e3d7116ac8f62…` | `["2298415"]` (`ngavrish`) | green; needs rebase |
| [#2829](https://github.com/hashgraph-online/hol-guard/pull/2829) | no | `2f73130bc0970a9da5ea34a0595962f55282e7fb` | `command.repro-surgeon` | `sha256:522162d690c7e…` | `["77353814"]` (`pavangupta352`) | green; needs rebase (pre-catalog branch) |
| [#2821](https://github.com/hashgraph-online/hol-guard/pull/2821) | no | `45d3cda099847ac1dd4642fc9e5a0c5e44267383` | `command.routed` | `sha256:439e786144750…` | `["202353692"]` (`bshea-1`) | green; needs rebase |
| [#2818](https://github.com/hashgraph-online/hol-guard/pull/2818) | no | `28e3cf77861598e7720d5c07f2d14d3a8de4caa5` | `command.rungs` | `sha256:534a71eeeaade…` | `["22010362"]` (`ThroughTheWind`) | review-bot check failing |
| [#2813](https://github.com/hashgraph-online/hol-guard/pull/2813) | no | `c7e723cbe40bd1273f235d030e8af420e462f5b0` | `command.dispat` | `sha256:bdddea456bf4d…` | `["19752295"]` (`yohimik`) | green; needs rebase |
| [#2804](https://github.com/hashgraph-online/hol-guard/pull/2804) | no | `dd446ec6f0fea060ff03c268c60a57abd05cc0be` | `command.claude-tmux` | `sha256:6eb0b067b6f69…` | `["38042656"]` (`s403o`) | green |
| [#2843](https://github.com/hashgraph-online/hol-guard/pull/2843) | no | `e40d4e64f5b2e69a9c5f5c2036ff75e3ec65b7a8` | `mcp.tether` | `sha256:1e8b8e96a4ada…` | `["20009719"]` (`sidyellur`) | review-bot check failing |
| [#2931](https://github.com/hashgraph-online/hol-guard/pull/2931) | yes | `c0c398cedd4689712f292181e0effc2bda894d3d` | `mcp.instapods` | `sha256:e297e4948c063…` | covered by the listing inside the PR itself | operator-owned draft; no separate proposal staged |

"green" = no failing check runs at the scanned head; "review-bot" failures are
the automated `Kilo Code Review` check, not build failures. Head SHAs advance as
contributors push; re-verify the digest at review time. Digests are the first
12+ hex chars of the SHA-256 computed exactly as the exporter does.

## Suggested pilot five (most merge-ready of the incoming cohort)

1. **#2929 `command.syngraphe`** — not a draft, green checks, no changes
   requested, complete kit (contribution + detector module + tests).
2. **#2876 `command.vttforge`** — not a draft, green checks, no changes
   requested, complete kit, open since 2026-09-10.
3. **#2895 `command.kim`** — not a draft, green checks, no changes requested;
   the earlier dismissal matches a force-push, current head is clean.
4. **#2888 `command.sandbin`** — not a draft, green checks, complete kit.
5. **#2804 `command.claude-tmux`** — not a draft, no failing checks, the oldest
   clean candidate (2026-09-05).

`command.shellroute` (#2927), named in the earlier review, is still a **draft**
PR, so it is pilot-alternate rather than pilot despite its name recognition.
Its proposal is staged and ready either way.

## Validation performed

- All 7 live sidecars and 19 staged proposals validate with the real listing
  validator (`load_listing` / `validate_listing`, schema
  `contracts/extensions/listing.v1.schema.json`): filename identity, field
  bounds, unique decimal-string IDs (≤ 8), public-URL policy, byte budget.
- Negative controls rejected: duplicate IDs, non-ASCII digits, nine IDs,
  sidecar-ID/filename mismatch, orphan listing (exporter).
- No path collisions: every sidecar filename equals its contribution ID; the
  exporter additionally rejects duplicates and orphans.
- `uv run python scripts/export_extension_directory.py` regeneration then
  `--check` (catalog) and `scripts/render_command_extension_directory.py
  --check` (docs) all pass on the prepared tree; the catalog diff is exactly
  the six `maintainerGithubIds` changes.

## Notice dry-run readiness (typed reasons)

`scripts/notify_merged_extension_claimants.py` now reports, distinctly:
`no_mapping`, `not_merged`, `source_not_current`, `portal_not_ready`,
`already_notified`, `eligible_for_notice`, `provider_unavailable`.

- `--report` prints a read-only JSON readiness artifact (`--dry-run` still
  rehearses the comment body without posting). The PR-level `prStatus` always
  agrees with the per-extension entries: it may say `eligible_for_notice` only
  when at least one entry is eligible and the portal check passed; otherwise it
  carries the blocking reason (`no_mapping`, `source_not_current`, …).
- Delayed/backfilled notices re-read the canonical listing at the default
  branch tip and invite only IDs still present: a since-removed identity is
  never re-invited; missing/invalid current listing → `source_not_current`.
- Optional portal projection check: `--portal-readiness-url` (or
  `GUARD_EXTENSION_PORTAL_READINESS_URL`) must return a JSON object affirming
  `"ok": true` (additional fields are allowed; a `{"ready": true}`-style body
  without `ok` is **not** accepted).
  Unreachable → `provider_unavailable`; reachable but not affirming →
  `portal_not_ready`; the send path fails closed when configured and the
  portal is not ready. Unconfigured checks never claim ready.
- New notices use the canonical claim link
  `https://hol.org/guard/extension-studio?claim=<id>&source_surface=github_claim_notice`.
  The portal intent parser (read, not modified) allows `claim=<id>` and the
  `source_surface` value `github_claim_notice`; legacy `?extension=<id>` links
  keep resolving.
- The workflow gained a manual `dry_run` input only; trusted checkout,
  least-scoped token (`contents: read`, `pull-requests: write`), and per-PR
  concurrency are unchanged. No notice was sent during preparation; everything
  here ran with fixtures or `--report`/`--dry-run`.

## Operating notes

- Merge of the live sidecars (this PR) is the authority-bearing step; the
  post-merge workflow will then notify the newly accepted IDs on this PR.
  Use `workflow_dispatch` with `pr_number` (+ `dry_run: true` first) for
  backfills; enable `allow_renames` only after a maintainer-reviewed rename.
- The claim server re-checks current canonical authority at claim time; these
  proposals do not and cannot pre-authorize anyone.
- Prepared by an automated worker under the `kantorcodes` identity; the PR body
  records the identity note for reviewer re-association if required.
