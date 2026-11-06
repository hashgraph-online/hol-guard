# Explicit Google project-grant disconnect

`GoogleSendAccount.disconnect_and_revoke_project_grant()` consumes the worker's
account owner. It first waits for any admitted bounded send and revokes every
pending input's local lease. It then makes one HTTPS POST to the fixed
`https://oauth2.googleapis.com/revoke` endpoint, carrying the private refresh
token (or access token when no refresh token exists) in the form body. The
existing client disables environment proxies and redirects and bounds headers
and elapsed time. No token is returned or put in a query string, result or log.

This is an explicit project-grant action. Google documents that it removes the
account's granted scopes and invalidates tokens for all clients registered under
the OAuth project. It may therefore affect other integrations using that project.
Local `revoke()` and `Drop` never perform this provider operation.
See [Google's revocation documentation](https://developers.google.com/identity/protocols/oauth2/web-server#tokenrevoke).

`Acknowledged` means Google returned HTTP 200; propagation may still be pending.
Every other status or transport failure returns `Unconfirmed`, including a lost
response after a possible successful provider revocation. The owner is consumed
and its credentials zeroized on every path. Pending input copies remain locally
revoked. There is no retry, automatic reconnect or business send. An expired or
locally revoked account can still request explicit provider disconnect.

Synthetic in-memory HTTP tests cover fixed request/token selection, failures,
redirect refusal, expiry, invalid tokens, pending-input invalidation and waiting
for an admitted send. They perform no DNS, socket, TLS handshake or Google call.
Persistent enrollment cleanup, operator confirmation UI, authenticated worker
custody and live provider verification remain unfinished; no route is enabled.
