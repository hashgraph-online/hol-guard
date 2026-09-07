# Using Dispat as an agent

Use Dispat's official guide for command usage, configuration, testing, release stages, and recovery.
Discover the guide through the installed binary rather than a fixed URL:

```sh
dispat --version
dispat --help
```

Open the agent-guide URL printed by top-level help, including its stderr output. Follow that guide's
instructions for selecting compatible guide updates, and use the configuration and API references
provided by the installed binary. If no guide link is available, report the limitation and verify
compatible upstream documentation before relying on it. Do not substitute a link to `main` or assume
another version's commands apply.

Keep these Guard workflow rules:

- **Release only through the repository's established CI/CD workflow.** Agents prepare changes, run
  non-publishing checks, and monitor results. Do not execute releases or retries locally, or bypass
  the pipeline through script helpers, manual publishing, release tags, or release records.
- **Change Dispat configuration only when directly instructed.** Inspection or a release request
  does not itself authorize changes to scripts, hooks, credentials, lock settings, or release
  policy.
- **Use explicit help for discovery.** Bare `dispat` starts a release; use `dispat status` to
  inspect the plan. Check what configured scripts do before executing them.

See [Dispat release protection](dispat.md) for Guard's command coverage. Guard approval does not
replace the CI/CD requirement; the extension itself does not enforce a CI-only execution policy.
