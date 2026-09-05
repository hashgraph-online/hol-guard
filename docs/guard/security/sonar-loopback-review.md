# Authenticated Claude loopback transport review

Reviewed source: `5baa16260049dffe518e5d0409d218d942ac61b1`,
`src/codex_plugin_scanner/guard/adapters/claude_daemon_hook_transport.py`.
Git blob: `82b08a68987e9e4c586aee6b5674bf9a0ace945e`.

The following Sonar findings were individually reviewed as false positives:

| Finding | Rule | Reason |
| --- | --- | --- |
| `AaBurY7LOEl4G0YgTSvh` | `python:S5332` | Authenticated local-only HTTP IPC, not an external cleartext endpoint. |
| `AaBurY7LOEl4G0YgTSvi` | `python:S5332` | Same local-only transport; no reusable Claude bearer token is transmitted. |
| `AaBurY7LOEl4G0YgTSvj` | `pythonsecurity:S5144` | Host and port come from validated, authenticated daemon state, not an arbitrary destination. |

`_authenticated_state` verifies owner-only signed discovery state and restricts
the host to exact loopback names with a valid port. Before transmitting hook
data, the client verifies a fresh nonce-bound daemon proof and an unchanged
daemon generation. The hook request uses that same connection. The transport
does not follow HTTP redirects.

The review checked the analyzed source against the Git blob, allowing only
Sonar's extra final blank line. The existing Claude bridge, path-authority, and
lifecycle edge-case suites passed: **51 tests**. Sonar recorded all three
individual dispositions and reported the PR quality gate as **OK**, including
89.9% new-code coverage against the unchanged 80% requirement.

Evidence: GitHub Actions run `33932582275`, artifact `sonar-loopback-review`.
The artifact includes the reviewed and analyzed source, rule definitions,
per-issue API responses, and the resulting quality gate. The one-time review
workflow was removed after these results were verified.

Re-review these dispositions if destination validation, state authentication,
the same-connection challenge, redirect behavior, or token handling changes.
