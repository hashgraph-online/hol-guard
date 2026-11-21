# Package review settings

Guard records every package install it sees. By default it pauses an install
only when it has evidence of risk, so day-to-day dependency work stays quiet.

## What pauses an install by default

These signals stop or pause an install under the default `balanced` level,
whatever your other settings say:

- A known vulnerability or advisory on the package or one of its dependencies.
  Live advisory and reputation data comes from Guard Cloud. Without Guard Cloud,
  Guard uses only the advisories already cached on this device.
- Malware or a blocked package in a policy bundle.
- An integrity failure, such as a lockfile hash that does not match.
- An install of Guard's own PyPI distribution from anywhere other than the
  registry. A direct-source install could replace Guard itself, so no setting
  relaxes this review.

Everything else is recorded, and Guard keeps watching it for new intelligence.
This includes a package Guard cannot identify, a lockfile that does not pin a
manifest dependency yet, a direct source and a custom registry.

## Stricter opt-ins

Each signal has a risk action. You can change it on the settings page of the
Guard dashboard, or under `[risk_actions]` in `config.toml`:

```toml
[risk_actions]
package_install = "require-reapproval"
```

| Risk key | Dashboard label | What it reviews | balanced | strict | paranoid |
| --- | --- | --- | --- | --- | --- |
| `package_unknown` | Unrecognized packages | Packages Guard cannot identify or find reputation for, including unreadable lockfiles | allow | block | block |
| `package_lockfile_drift` | Lockfile bumps | Manifest dependencies the lockfile does not pin yet | allow | require-reapproval | block |
| `package_direct_source` | Direct package sources | Git, URL, archive, local-path and replaced sources | allow | require-reapproval | block |
| `package_custom_registry` | Custom registries | Installs that use a non-default package index or registry | allow | allow | block |
| `package_script` | Package scripts | Lifecycle scripts such as `postinstall` | warn | require-reapproval | block |
| `package_install` | Every package install | Every install or update, even with no risk signal | allow | allow | block |

`allow` records the install and does not pause it. A package exception you have
saved also answers the `package_install` and `package_custom_registry` opt-ins.

## Low HOL Registry trust scores

When Guard first sees a skill, MCP server or plugin, or sees it change, Guard
looks up its public HOL Registry trust score. A score below 80 raises the
artifact to the `low_trust_artifact` action, which is `require-reapproval` under
`balanced`. The lookup sends only the artifact's kind and public name.

- A missing score never triggers a review. This covers an unknown artifact, an
  unreachable registry, an ambiguous match or a kind the registry cannot score
  yet.
- An artifact you have configured, or one that is unchanged since you decided
  it, is not scored again. A saved Always allow still applies.
- Plugin scores are live. Skill and MCP server scores apply once the registry
  serves them.
- To turn the check off, set `low_trust_artifact = "allow"` or
  `HOL_GUARD_REGISTRY_TRUST=off`.

Every review these settings add still offers Allow once and Always allow. See
[approval-invariant.md](approval-invariant.md).
