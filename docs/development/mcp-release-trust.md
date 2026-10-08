# MCP release source verification

MCP Registry and MCPB publishing still follow the completed `Publish to PyPI`
workflow. They no longer accept `workflow_run.head_sha` as a checkout instruction.

Both consumers first call `verify-mcp-release-source.yml`. That gate has only
`actions: read` and `contents: read`. It checks out `github.sha`, the trusted
**default-branch** commit for a `workflow_run` event, and runs the verifier with
Python's isolated, no-site-packages flags. It does not check out or execute the
candidate release commit while deciding whether to trust it.

The verifier independently reads the canonical `publish.yml` workflow and the
originating run through GitHub's API. It requires matching repository names and
numeric IDs, the canonical workflow ID and path, a successful completed first
attempt, and a `push` or `workflow_dispatch` on `main` or `release/3.0`. The event
and live run must agree on the immutable source SHA, branch, and event type.
The release-skip marker remains authoritative.

A branch name in a run payload is not enough. GitHub's compare API must show that
the exact SHA is an ancestor of, or identical to, the named release branch. A
fork, unmerged commit, rewritten-away commit, other workflow, rerun, malformed
response, API error, or missing evidence stops the gate without emitting outputs.
Redirects are rejected rather than forwarding credentials. This trust policy
relies on write access to the two allowlisted release branches being restricted
to trusted maintainers; it does not replace branch protection or code review.

The three release checkouts depend on the successful gate and consume only its
validated outputs. They do not fall back to event data or the latest branch tip.
Tag lookup, version stamping, exact PyPI availability checks, publisher pins,
bundle checksums, and existing publication conditions are retained. The
release commits are still executed in publishing jobs, but only after their
canonical provenance and branch membership have been proved.

Unmerged MCP bundles retain their own read-only `pull_request` validation in
`mcpb-validation.yml`, separate from workflows with privileged triggers. A PR's
successful validation cannot grant publication authority.

`MCP release trust` tests the verifier's rejection cases and the workflow wiring.
It also runs checksum-pinned OpenSSF Scorecard against the checked-out source and
requires both `Dangerous-Workflow` and `Token-Permissions` to score 10. The actual
JSON reports are retained as an Actions artifact. Existing runtime, package,
release, and security tests remain enabled.

References:

- [GitHub workflow_run event and security warning](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run)
- [GitHub compare commits API](https://docs.github.com/en/rest/commits/commits#compare-two-commits)
- [OpenSSF Dangerous-Workflow check](https://github.com/ossf/scorecard/blob/main/docs/checks.md#dangerous-workflow)
