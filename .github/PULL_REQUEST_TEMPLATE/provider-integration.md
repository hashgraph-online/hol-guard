## Provider integration contribution

<!-- Use this template for a new or changed integration in contributions/provider-integrations/. Use synthetic sites, origins and identifiers throughout. Provider evidence can only tighten a decision; it never allows anything. -->

### Provider and source

<!-- Name the provider and link the API documentation you used, pinned to a version or date. -->

### Signals and thresholds

<!-- List the signals the integration reads and the threshold each uses before it adds a review. -->

### Regression cases

<!-- See "Browser protection" in ci/gauntlet/README.md. -->

- Gate row ids (`tests/fixtures/benign_false_positive_gate.json`) added or changed:
- Live Gauntlet case ids (`ci/gauntlet/browser.json`) added or changed, including each `browser-quiet-provider-*` case and its no-provider twin:
- Direction check: confirm that every row and case with the provider is at least as strict as without it, and that no quiet case gains a prompt.

### Checklist

- [ ] An unreachable, slow or malformed provider answer leaves the decision as it was without the provider.
- [ ] Every fixture uses synthetic origins and data, and no credential is checked in.
- [ ] I understand that merging does not turn the integration on for anyone.
