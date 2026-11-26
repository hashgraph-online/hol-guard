## Browser driver profile contribution

<!-- Use this template for a new or changed profile in contributions/browser-drivers/. Use synthetic sites, origins and identifiers throughout. -->

### Driver and source

<!-- Name the driver and link its tool list, pinned to a version or date. -->

### Tools and verbs

<!-- List the tools added or changed and the verb class each maps to. Explain any tool left unmapped. -->

### Regression cases

<!-- Every changed tool needs a row in the benign false-positive gate, and every quiet case a matching gate row. See "Browser protection" in ci/gauntlet/README.md. -->

- Gate row ids (`tests/fixtures/benign_false_positive_gate.json`) added or changed:
- Live Gauntlet case ids (`ci/gauntlet/browser.json`) added or changed:
- Direction check: for each row, say whether it must stay quiet (`allow`) or must stop, and confirm the expected decision did not loosen. A row that moves from a stop to `allow` needs a reason here.

### Checklist

- [ ] `tests/test_browser_driver_gate_coverage.py` passes, and any closed gap is removed from its baseline.
- [ ] Every fixture uses synthetic origins and data.
- [ ] I understand that merging does not turn the profile on for anyone.
