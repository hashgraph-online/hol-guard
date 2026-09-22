# External extension submissions

For changes under `contributions/command-sources/`,
`tests/fixtures/command-source-*.v1.json`, or
`contracts/extensions/trust-class-map.v1.json`, verify that:

- the source, fixture, external trust mapping, generated descriptor, native
  program, catalog, and package-resource updates identify the same extension;
- fixture bindings use the exact canonical source document;
- the extension remains external and opt-in; and
- any optional publisher listing contains public attribution only and does not
  claim authority from a pull request author.

Treat an absent generated projection or a stale source digest as a mechanical
repair. Treat a missing matcher decision, trust decision, safe variant, or
claimant mapping as contributor or maintainer review work.
