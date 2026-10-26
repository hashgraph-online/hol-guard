# Gcloud service-account impersonation

`GCLOUD_SERVICE_ACCOUNT_IMPERSONATION` records an explicit
`--impersonate-service-account` option on a supported gcloud access-token request.
It uses **medium** severity because the command requests a token for another
identity. The caller must possess impersonation permissions; detection does not
prove those permissions exist, that the request succeeds or that the target
identity has greater privileges.

Review the caller's identity grants, the target service account's permissions,
token handling and the agent's shell access. Neither a `--project` option nor a
read-only description establishes the token's effective scope.

The finding carries a file and line without including credentials or the command
text. It remains visible even when the runtime expression has no embedded secret.
The same supported assignment grammar, file boundaries and reporting behavior as
[runtime credential access](runtime-credential-access.md) apply. An impersonation
mention in a comment or an unrelated option value does not trigger this rule.

This is an explicit-option detector. It does not resolve gcloud configuration,
environment defaults, IAM policy or sourced files. Absence of this finding does
not prove that impersonation is unavailable at runtime.
