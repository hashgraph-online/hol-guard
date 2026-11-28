# Contribute a provider integration

A provider integration lets a security product the user already uses add evidence to Guard's
browser reviews. The manifest format, file naming and trust binding are described in
[`contributions/provider-integrations/README.md`](../../../contributions/provider-integrations/README.md).
This guide covers what a provider can do to a decision, how Guard keeps a provider from adding
prompts, and what a maintainer needs before marking a publisher `verified`.

Provider integrations are still being built. The rules below are enforced in
`rust/crates/guard-provider-integrations`; the Integrations page and the connect flow are not in a
release yet.

## What a provider can change

A provider adds evidence. It never allows anything: its verdict map has no allow value, and Guard
takes the stronger of its own decision and the provider's.

| Verdict | Effect |
| --- | --- |
| `ok` | A finding on the card or receipt. No decision change. |
| `unknown`, or any answer that is not fresh | No effect. |
| `caution` | A review, within the caps below. From an unverified publisher it is a finding only. |
| `danger` | A review. A block when the user turned on "Enforce provider blocks". Never capped. |

Each provider runs at an effect level the user picks:

- `observe`: `caution` and `danger` write would-have-reviewed receipts and change nothing.
- `tighten` (the default): as in the table above.
- `enforce`: as `tighten`, and `danger` blocks.

## Noise caps

Guard counts the reviews a provider causes, per session:

- A verified `caution` raises at most one review per subject per answer. A new answer about the
  same subject, or a refresh after the old one expired, may ask once more.
- At most three provider-caused `caution` reviews per provider per session. After that the
  provider's `caution` answers are findings, and the Browser area shows one notice that the provider
  is quiet for the rest of the session.
- When Guard reviews an action for its own reasons, the provider row joins that review and is not
  counted.
- With several providers on one subject, the strongest fresh verdict decides and the action is
  reviewed once. The card lists three providers ordered by verdict, then provider id, and folds the
  rest into "N more". A sponsored placement never changes that order.

When a user allows an action through a provider-caused review three times for the same reason code
within seven days, the card offers "Stop asking for this reason from &lt;provider&gt;". Guard never
does this on its own. Accepting it sets that reason code to `observe`; the Integrations page lists
every quieted reason with an undo. Quieting lowers only the provider's effect, so it can never take
a decision below what Guard decides without the provider.

## Check a manifest before you open a pull request

Draft the recorded responses from the manifest instead of writing them by hand:

```bash
hol-guard extensions generate --provider --from manifest \
  --input contributions/provider-integrations/provider.<slug>.json \
  --output tests/fixtures/provider_integrations/<slug>/recordings.json
```

The draft has one answer for every entry of each verdict table, one with a verdict the table does not
list, and the required failures: a refused key, rate limiting, a server error, an oversize body and a
malformed body. Each expectation is what Guard reads from the drafted body. The bodies are
placeholders shaped by the manifest's pointers, so replace each one with a real response from the
provider and keep its expectation true (see the
[provider integrations README](../../../contributions/provider-integrations/README.md#recorded-responses)).
Then run:

```bash
hol-guard extensions validate --provider contributions/provider-integrations/provider.<slug>.json
```

`validate --provider` runs the same checks as
`hol-guard integrations conformance <manifest>` and exits non-zero when one fails.

The five checks are:

1. `compile`: the manifest compiles, including every label.
2. `recordings`: every recording reads as recorded, and each capability has one for every verdict,
   for `unknown`, and for a refused key, rate limiting, an oversize body and a malformed body.
3. `share-set`: the request carries exactly the facts in `shares`.
4. `no-added-prompt`: with the provider answering `ok`, `unknown` or failing, the benign browser
   corpus decides exactly as it does with no provider.
5. `bounded-prompt`: with the provider answering `caution` for everything, the reviews it causes stay
   inside the noise caps.

CI runs the same checks for every manifest in `contributions/provider-integrations/`.

## Verified means calibrated

`provider.publisher.verified` is set by maintainers only. A contributed manifest leaves it `false`,
and an unverified provider's `caution` stays a finding.

To ask for `verified`, attach a calibration report to the pull request. The report measures how
often the provider flags ordinary sites:

```json
{
  "schema": "guard.provider-calibration-report.v1",
  "provider": "provider.exampleshield",
  "manifest_sha256": "<sha256 of the manifest file>",
  "list": {
    "name": "<public most-visited-sites list>",
    "retrieved": "2026-11-01",
    "sha256": "<sha256 of the list file as downloaded>",
    "entries": 10000
  },
  "capability": "url-reputation",
  "counts": { "ok": 9930, "unknown": 52, "caution": 16, "danger": 2 },
  "rates": { "caution": 0.0016, "danger": 0.0002 }
}
```

- Name the list by its public name, the date it was retrieved and its SHA-256. Do not check the list
  in, and do not paste per-site results; only the counts and rates are recorded.
- Run every entry through the capability the manifest declares, with the same request the manifest
  renders. Report one object per capability that can return `caution` or `danger`.
- `rates` are the counts divided by `entries`. An answer that timed out or failed counts as
  `unknown`.

The starting thresholds are:

| Rate | Threshold |
| --- | --- |
| `caution` | at most 2% of the list |
| `danger` | at most 0.2% of the list |

A provider over either threshold for any capability stays unverified. Maintainers will revisit
these numbers once real override counts are available.
