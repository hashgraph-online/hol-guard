# Owned Gmail send transport

This transport is for a registered native worker. It grants no business
permission. Before calling it, the worker must consume the existing native
single-use decision, enforce current policy and budgets, and journal the attempt.
No worker endpoint, account enrollment, refresh/session lifecycle or protected
business mode is enabled by this library API.

`PreparedGoogleBusinessRequest::dispatch_owned` consumes the prepared request
and supplied frozen input. Their bindings and exact JSON bytes must match;
attachments and expired provider evidence refuse before transport. The prepared
tool identity commits the complete fixed POST endpoint, including the fixed
response projection. The worker never executes the original shell command.

The transport owns the send credential, allows one POST to Gmail `users/me`,
and retains the existing HTTPS-only, no-proxy, no-redirect, bounded-header and
five-second settings. A fresh connection pool avoids reusing an old connection.
Request bytes remain the original validated Gmail JSON body. Private headers,
tokens, body and provider IDs are unavailable in transport result metadata.
HTTP/TLS buffers can contain transient copies; this is not a complete memory
erasure or process-isolation claim.

A valid bounded JSON acknowledgement yields an account/namespace-bound message
fingerprint. It reports API acceptance, not inbox delivery. A connection error,
unexpected status, missing fields, duplicate fields, extra fields or oversized
response yields an unconfirmed attempt. The effect might have occurred; no retry
is performed. The native worker must retain the spent approval and persist the
outcome before presenting a result. Both grants are consumed by this transport;
registry persistence and renewal remain separate unfinished work.

Tests inject private synthetic transport callbacks. They prove source ownership,
fixed operation, pre-attempt refusal and response classification; they are not
live-account evidence or Gauntlet qualification.

Primary reference: [Gmail users.messages.send](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/send).
