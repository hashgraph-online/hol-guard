# Browser driver profiles

Each file here is a browser driver profile: it tells Guard which MCP server, package or harness
tool is a browser driver and maps that driver's tools to Guard's closed list of browser verbs
(`Navigate`, `Click`, `Type`, `Evaluate` and so on). Guard uses the profile to show a readable
browser review card and to scope approvals to an origin instead of a raw argument hash.

A profile only describes a driver. It cannot allow anything, lower a review, or add a verb.

## Files

- Name the file `<id>.json`, for example `browser.example-pilot.json`.
- `id` is `browser.<slug>`: lowercase letters, digits and hyphens.
- The file must validate against
  `contracts/browser-drivers/driver.v1.schema.json`.
- Match lists hold literal lowercase names. Regular expressions are not accepted.
- Profiles that are not publisher-verified cannot claim generic names such as `browser`,
  `chrome`, `playwright`, shells or interpreters.
- Use invented names in examples and fixtures.

## Trust

Every profile needs a trust binding in `contracts/extensions/trust/<id>.v1.json`. Run:

```bash
python scripts/refresh_extension_artifacts.py --trust-only
```

New profiles are bound as `external`, so they stay off until a user turns them on. Include the new
binding file in the same pull request. `python scripts/refresh_extension_artifacts.py --check-trust`
fails when a profile has no binding.

## Packaging

This directory ships in the wheel under
`codex_plugin_scanner/guard/contracts/data/browser_drivers/contributions`.
