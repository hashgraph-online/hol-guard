# Extension contributions

Community command-safety extensions are **external**. They stay off until a user turns them on for this device. HOL floors and HOL-curated libraries (AWS, Azure, Git, Kubernetes, Docker, and other mapped tools) stay on.

## Trust classes

- **first-party** — HOL floors. On by default. Required items cannot be turned off.
- **trusted-library** — HOL-curated protection for widely used tools. On by default.
- **external** — contributed tools. Listed as External. Off until you turn them on.

Turning off a first-party or trusted-library extension blocks that capability. Turning off an external extension returns it to inert: Guard does not apply that contribution, and first-party floors still apply.

## How to contribute

1. Add an in-tree detector module under `src/codex_plugin_scanner/guard/runtime/`.
2. Add a contribution file under `contributions/extensions/command.<name>.json`.
3. Add the id to the `external` list in `contracts/extensions/trust-class-map.v1.json`.
4. Do not put the id in `first-party` or `trusted-library`. Contribution files cannot self-declare those classes.

The schema is `contracts/extensions/contribution.v1.schema.json`. Required metadata: id, name, description, publisher, icon, executables, risk classes, action classes, and an in-tree `python-module` detector.

Icons must use an allowlisted `react-icon` name or `kind: none`. Remote icon URLs are rejected.

## Review bar

- The detector must live in this repository. Guard does not download contribution code.
- New catalog ids default to external unless the trust-class map is updated in the same change.
- Tests must prove the contribution stays inert until a local-admin enable layer exists.
