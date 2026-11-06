# Runtime credential access

`RUNTIME_CREDENTIAL_ACCESS` records a supported shell assignment that reads a
credential-related environment variable or requests a token with
`gcloud auth [application-default] print-access-token`.

The default severity is **low**: accessing credentials is a capability to review,
not proof of an embedded secret, a credential leak or successful execution. The
scanner does not know the runtime identity's permissions or the token's scope.
Review those before letting an agent execute the skill. A project or configuration
flag, or documentation describing an audit as read-only, does not prove least
privilege.

The finding includes the file and line, without copying a token, command or
environment value. Restrict shell access and identity grants to the work required,
and check that credentials will not be logged or sent to unintended destinations.

## Detection boundary

Recognition uses the same bounded parser as the embedded-secret exemption:
complete, double-quoted assignments containing one supported `printenv` or gcloud
read, in `.sh`/`.bash` files or closed shell-tagged Markdown fences (`.md`, `.mdx`,
`.markdown`). Literal prefixes, suffixes, command chains and unsupported syntax
keep their existing secret-detection behavior. This is static analysis; it never
executes the input.

For `printenv`, a credential-shaped source or destination identifier is required,
such as `GRAFANA_TOKEN`, `PASSWORD` or `API_KEY`. Neutral names like `PATH`, names
like `TOKENIZER`, and static metadata names like `TOKEN_NAME` do not establish
credential access. A credential-shaped indirect name such as `$TOKEN_VAR` remains
a possible credential lookup. Any generic secret match exempted by the supported
runtime assignment also retains a capability finding, including `authToken` and
`clientSecret` destinations. Gcloud token requests are reported regardless of the
destination variable's name.

The parser does not follow sourced credential files, resolve dynamic variable
values or inventory every shell command. No finding does not prove no access.
Provider-secret detectors still inspect the same content, and adjacent embedded
secrets retain their findings.

## Scores and policy

The existing **No hardcoded secrets** check retains its literal findings and
quality-score points. A separate **Runtime credential access** check carries
the capability findings with zero additional quality-score weight. Both use the
same bounded file scan. This separation preserves score accounting when a user
suppresses a literal finding while retaining the capability finding.

JSON, Markdown and SARIF keep the capabilities, and severity-based policies still
evaluate them. A perfect quality score is not a declaration of credential
isolation. An incomplete file scan also marks the runtime check incomplete.

Explicit service-account impersonation uses the more specific
[GCLOUD_SERVICE_ACCOUNT_IMPERSONATION](gcloud-service-account-impersonation.md)
finding instead of duplicating the ordinary access finding for that assignment.
