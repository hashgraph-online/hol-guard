# Waiting for an approval decision

A held package request or a bound hook review includes its request ID and a
read-only wait command:

```sh
hol-guard approvals wait <request-id> --json
```

The command waits up to 120 seconds. Use `--timeout <seconds>` to select a
bound between 0 and 600 seconds; 0 checks the decision immediately.

Exit status 0 means an allow decision was observed, 1 means the request was
blocked or was not found, and 2 means the wait timed out. A timeout leaves the
request pending and is never approval. An agent can continue other permitted
work and wait again later.

A removed request returns `not_found` immediately. A store outage returns
`approval_store_unavailable` with exit status 3 and an unknown decision.
Neither result authorizes a retry.

For a custom Guard home the printed command includes `--home <configured-home>`
so it reads the database that queued the request. Home overrides keep Guard's
existing inspection review; they do not gain a new automatic allow.

After an allow decision, retry the identical action through Guard. Waiting
does not approve, consume approval, or execute the action. Guard revalidates
the retry against its normal command and artifact binding. A changed command
or artifact may need a fresh review.

Hook responses also include `approval_resume.request_id` and the local
`approval_resume.poll_path` for integrations that can watch a request. The
human-readable wait command reaches Claude Code and Codex even when their
hook protocol discards extra fields. Oh My Pi continues to watch the handle
through its extension. Reviews without a usable one-time retry binding keep
their existing recovery guidance instead of advertising automatic retry.
