# ADR 0018: Browser protection and provider integration authority

Status: accepted.

## Context

Agents reach browsers through MCP servers, harness built-in tools, shell launches and raw DevTools protocol
connections. Guard classifies a few name-matched browser MCP servers, asks again for every new click target, and has
no site-level grant or denial. One security vendor integration exists (Yanez Pulse, see
[the approval gate guide](../yanez-pulse-approval-gate.md)) and there is no general way to add another.

Many products already sell web protection directly to people and teams: safe browsing, anti-phishing, download
scanning, client-side script protection, privacy governance, enterprise browser policy. None of them can see what an
agent is about to do in a browser, and none has a place to stop it. Guard's hooks fire before the action and its
approval card is where the user decides.

The [browser protection design](../browser-protection-prd.md) describes the full change. This record fixes the
authority rules every phase of it must keep, so that later pull requests argue about implementation, not about who
may decide.

## Decision

**Guard is the integration venue, not the detector.** Guard owns the hooks, the browser action model, the approval
card, grants, key custody and the rules for how outside evidence may change a decision. It does not build site
reputation, script analysis, phishing classification or malware scanning. Providers answer a closed set of questions
(capabilities) about a closed set of facts, through a declarative manifest. A new provider is a manifest, its
fixtures and a review. The account and the key belong to the user, who buys them from the provider directly.

Authority rules:

| Rule | Meaning |
| --- | --- |
| Evidence, not authority | Driver profiles and provider signals contribute facts. They cannot approve, write memory, grant, shorten a review or lower a floor. This extends "Evidence and policy authority" in [the command extension architecture](../command-extension-architecture.md). |
| Tightening only | A provider signal can move `allow` to `review` and add a finding to a review. It becomes a block only through a user or administrator setting. Nothing a provider returns moves a decision toward `allow`. No provider allow exists, including for `browser.site-policy`; an organization's allow list arrives through managed policy, not a provider verdict. |
| Payment independence | Sponsorship affects discovery placement and the disclosure label only. The runtime has no field recording whether a provider pays. The label is shown only while a live, validated placement says so. |
| Fail direction | A provider outage gives exactly the decision Guard would make with no provider, plus a `provider_unavailable` finding. Only a user setting ("Require a fresh check") turns an outage into a review. |
| Closed lists | Capabilities (`browser.origin-reputation`, `browser.script-integrity`, `browser.page-data-risk`, `browser.download-reputation`, `browser.site-policy`) and shareable facts are closed enums. Adding one is a contract change with tests. Loopback, private-range and reserved-suffix origins are never shared. |
| No provider I/O on the decision path | Hook and relay decisions read a local signal cache. A worker fetches signals off the hot path. |
| Quiet by default | A prompt the user did not need is a defect with the same weight as a missed protection. Every browser action is quiet, one card, or protect. Covered actions never ask again. |
| Bounded provider noise | With a provider answering `ok`, `unknown` or failing, every decision equals the no-provider decision. An unverified provider's `caution` is a finding only. Provider-caused `caution` reviews are capped at one per subject per signal version and three per session per provider. The user may lower any provider effect to `observe`, never below Guard's own decision. Several providers on one subject produce at most one review. These caps are constants. |
| Approval invariant | Every browser review offers Allow once and Always allow ([approval invariant](../approval-invariant.md)). Site grants, session-site grants, the durable "Always allow <verb> on <site>" and "Block on this site" are added choices, never replacements. A provider `danger` signal pauses a saved Always allow and shows it as paused; it does not delete it. |

Decisions taken with this record:

- **Shared-profile drivers** get only the narrow `session-site` grant, with the exclusions in section 5.5 of the
  design. Without it the most common drivers stay one prompt per click.
- **"Always allow <verb> on <site>"** is an added durable choice. The exact-action Always allow is unchanged.
- **Loopback development origins** in an isolated or dedicated profile are quiet with no grant, except Guard's own
  origin, local admin ports, recorded debugging ports, sensitive surfaces and shared or remote-debugging profiles.
- **The first navigation to a new public site** is one card with the site grant offered, not quiet.
- **Account sign-in** for providers without API keys comes after key paste, as a new `auth.kind` on the
  [brokered sign-in transport](0016-brokered-sign-in-transport.md).
- **`verified`** is set by maintainers only and needs a calibration report over a public most-visited-sites list
  named by digest. Starting thresholds: `caution` on at most 2% and `danger` on at most 0.2% of that list.
- **The Gauntlet browser lane** is a harness-only profile run as a named release step. `QUALIFYING_LANE` does not
  change.
- **A provider fixture origin** is allowed in release builds, restricted to loopback, to provider ids under the
  reserved `provider.fixture-` prefix, and to the literal fixture key. It is the only test hook in a release build.

## Consequences

Any provider can integrate without Guard writing code for it, and a user can connect several. The platform bounds
how loud a provider can make Guard, because Guard cannot vouch for a provider's false-positive rate.

The cost is that a provider cannot offer an allow or an automatic grant, even a correct one. A provider that wants to
reduce prompts has no lever; only the user's grants and Guard's own rules do that.

The caps and calibration thresholds are first guesses. Each change to them is its own pull request with Gauntlet and
benign-gate cases.

Rollback: `HOL_GUARD_BROWSER_PROTECTION=legacy` returns browser classification and grants to the pre-change tables.
`HOL_GUARD_PROVIDER_INTEGRATIONS=off` makes every integration route answer `provider_capability_unavailable` and makes
the provider decide step a no-op.
