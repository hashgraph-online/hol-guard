# Opt-in gws command risk rules

`command.google-workspace.gws` is an external command contribution for the
Google Workspace CLI v0.22.5 source commit
`705fb0ecac6f4249679958f6325b809b63fdde17`. It classifies finite Gmail delivery
and destructive routes, Drive permission changes, Calendar event changes and
authentication/credential-export operations.
Gmail delivery includes `+send`, `+reply`, `+reply-all` and `+forward` helpers.
Destructive routes include Drive `files emptyTrash` and `drives delete`. The
sharing rule covers Drive permissions, Calendar `acl insert`, `update`, `patch`
and `delete`, and the Gmail settings that redirect or expose mail:
`forwardingAddresses create`, `updateAutoForwarding`, `filters create` and
`delegates create`.
The CLI is a community project, not an officially supported Google product.

Discovery routes also match the explicit `gmail:v1`, `drive:v3`, `drive:v2` and
`calendar:v3` service tokens. Gmail `+` helpers such as `+send` and `+forward`
are matched only under the bare `gmail` service; this extension does not cover
them with a versioned service token. Drive v2 method names (`permissions insert`/`patch`, `files trash`) are
covered whether v2 is selected by `drive:v2` or by `--api-version v2`, and
`teamdrives delete` is reviewed with shared drive deletion.
Inline credential or configuration overrides, such as
`GOOGLE_WORKSPACE_CLI_CONFIG_DIR=... gws ...`, `GOOGLE_WORKSPACE_CLI_TOKEN`,
`GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE`, `GOOGLE_APPLICATION_CREDENTIALS` or the
`env` wrapper form, stay under the inherited environment-prefix block. The
fixtures record that block as evidence.

The contribution is inert until the existing local-admin activation enables it.
Permissions use a review baseline; activation never grants a send or waives a
first-party floor. The portable fixtures include inactive contribution cases
and compound commands that retain the destructive-operation block.

Literal help suppresses this contribution's route observation. A value such as
`--body '--help'` does not count as a help flag, nor does a flag after `--`.
Dry-run and draft flags do not mint authority or suppress review: creating
drafts can already transmit data. Supported scalar option
values are skipped while matching the route, including interspersed JSON
parameters and the pinned `-o` alias.

The authentication family reviews pinned `auth login`, `setup`, `export` and
`logout` routes. Credential export is reviewed with or without `--unmasked`.
`--readonly` scope selection does not authorize a connection or provider action.
Auth status emits no contribution observation. The parser skips pinned scope,
service, project and API-version option values; help used as one of those values
cannot suppress the observation. Environment tokens, credential-file overrides,
encrypted/plaintext configuration and application-default credentials remain
unresolved identity sources, not authenticated account evidence.

The offline Bash fixture context has no authenticated executable/account or
benign-command proof. Its overall native minimum remains review even when this
contribution emits no observations for help, reads or draft creation. These are
inherited native floors, not successful quiet-task acceptance results. The pack
does not add an allow grant or lower that boundary to make fixtures pass.

This contribution does not authenticate the application account, inspect every
payload, freeze files, isolate credentials or mediate provider dispatch. It does
not cover every CLI service, custom discovery document, wrapper, alias, generic
API fallback, remote connector or agent mode. In particular, the route list does
not cover a service token with a version that discovery does not publish (for
example, one served from a planted discovery cache under the default
configuration directory). It also does not cover a credential or configuration
variable exported in an earlier command or inherited from the parent
environment, because the matcher sees only inline assignments. The finite route list is reviewable
source classification, not a protected Google Workspace journey. Account-bound
managed dispatch, cumulative budgets, setup UI and live mode/version/OS evidence
remain separate requirements. No business mode is qualified by these fixtures.

Canonical authoring inputs are the source JSON, portable fixture and external
trust-class entry. The existing preparation command generates the descriptor
and directory catalog projections; none are hand-authored.
