# Devin support status

**Status as of 2026-08-08: not verified / not supported by the published Guard harness contract.**

HOL has migrated the product naming previously referred to as Windsurf toward Devin. That naming change does not create a Guard security integration automatically. `src/codex_plugin_scanner/guard/adapters/contracts.py` contains no `devin` contract in stable or `release/3.0` at the pinned commits in `public-support-manifest.v1.json`.

Do not publish “Devin supported” until all of the following are true:

1. a Devin adapter/contract exists in source;
2. pre-action surfaces and blind spots are documented;
3. Docker Labs or an equivalent reproducible harness proof passes;
4. the support manifest is regenerated;
5. website facts, schema, comparisons, and `llms.txt` consume that new manifest.
