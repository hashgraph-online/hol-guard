# Opt-in gog command risk rules

`command.google-workspace.gog` is an external, default-off command contribution
for gog v0.43.0, source `3b5122f4c81c5df6df38ee48e01327f1034364ee`.
It uses exported command and ancestor aliases rather than inventing CLI routes.
Six rule families review finite Gmail delivery, Drive sharing, Calendar changes,
Drive downloads, generic API/batch/raw/MCP launchers and explicit account,
client, home or access-token overrides. Auth/config commands also require review.

Each route uses its exported value and boolean option kinds. Caller flags such
as `--gmail-no-send`, `--readonly` and `--dry-run` do not suppress Guard review
or mint an allow grant. Literal help can clear a contribution observation;
help used as payload, or after `--`, is not a safety flag. Required short value
options are recognized without treating consumed data as an option. A known
value option without an operand cannot establish a required-option proof.

This contribution targets native enforcement. The retained historical Python
option vectors remain regression inputs, not a production fallback or a promise
of current Python matcher parity. Standalone legacy Python matcher behavior is
not qualified for this contribution; it supplies no provider execution authority.

Ordinary selected read and draft routes have no delivery observation. The
unverified offline Bash context retains the native review floor, including when
the contribution is disabled. Compound destructive commands retain their
first-party block. These fixtures execute no provider commands and do not prove
quiet-task acceptance or a protected account journey.

Reviewing an override does not authenticate the effective principal. Environment,
stored credentials, application-default credentials, wrappers, runtime discovery
and services outside the finite route list remain unqualified. MCP launcher
classification does not protect subsequent protocol calls. Payload inspection,
immutable managed requests, isolated token custody, budgets, provider dispatch,
setup UI and live mode/version/OS qualification remain separate requirements.

Canonical source, portable fixtures and external trust-map entry are authoring
inputs. Contribution tooling generates descriptor/catalog projections; generated
outputs are not hand-authored or included in the contribution diff.
