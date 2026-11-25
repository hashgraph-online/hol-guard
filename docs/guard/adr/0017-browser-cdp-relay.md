# ADR 0017: Browser DevTools protocol relay

Status: proposed. This is a design gate. No relay code lands until this record is accepted.

## Context

Some browser drivers are invisible to Guard's tool-call layer: scripts, command-line tools and hosted sessions that
speak the DevTools protocol (CDP) directly to a browser's debugging endpoint. Guard can classify the shell launch that
opens a debugging port, and it can classify a driver's `cdpPassthrough` tool through the method table, but it cannot
see the individual protocol commands those drivers send. A cookie read and a screenshot look the same from outside.

The [browser protection design](../browser-protection-prd.md), section 5.6, proposes a Guard-owned loopback relay
between such a driver and the browser. This record decides whether and how to build it.

## Threat model

- The agent controls the driver and can choose any endpoint it can reach. A relay only governs connections that go
  through it. Managed mode (rewriting a recognized driver's endpoint flag at MCP admission) and the launch-layer rule
  that reviews unrelayed debugging ports are what route traffic to it.
- Frames arrive from the agent side and are untrusted: oversize frames, malformed JSON, unknown methods, interleaved
  sessions, and floods meant to exhaust memory or the approval queue.
- The browser side is trusted for transport but its events can carry page-controlled strings (URLs, titles). Those
  are facts for display, never instructions.
- The relay listens on loopback only and must not become an open proxy for other local processes. Each listening
  socket is bound to one upstream endpoint and one Guard session, and only the client that session launched may use
  it.

## Decision

Build the relay as a new crate, `rust/crates/guard-browser-relay`, owning WebSocket framing, discovery endpoint
rewriting (`/json/version`, `/json/list`) and target tracking (`Target.attachedToTarget`, `Page.frameNavigated`) so
each command has a current origin. Every decision is delegated to `guard-runtime` through the same browser action
model as the tool-call layer. Nothing in this layer is Python.

- Command frames (`id`, `method`, `params`, `sessionId`) are classified through
  `contracts/browser-drivers/cdp-methods.v1.json`. An unknown method is `Other`, intent `browser.privileged`.
- An allowed frame is forwarded unchanged. A held or denied frame is answered with
  `{"id": <id>, "error": {"code": -32000, "message": "Held by HOL Guard: <short reason>"}}`.
- Events are forwarded untouched. Only the fields needed for target tracking are read.
- Client authentication: each listener mints a random capability of at least 128 bits. Discovery endpoints and the
  WebSocket upgrade are served only under a path containing it; anything else is refused before a frame is read.
  Managed mode hands the capability to the one driver it launches through the driver's endpoint flag, and manual mode
  prints it once to the invoking terminal. One client connection at a time per listener. Where the platform reports
  the peer's user, a different user's connection is refused. Limit: a process of the same user can read another
  process's arguments, so the capability keeps out other users and sandboxed processes, not same-user code, which can
  already drive the browser without the relay.
- Origins are tracked per target and per frame. URL-bearing commands (`Page.navigate`, `Target.createTarget` with a
  URL) are classified and decided on their destination origin before they are forwarded. While a navigation is in
  flight on a target, or when a command's frame has no known origin, the command has no site and no grant covers it,
  so it is reviewed.
- Bounds: frame size cap, per-connection memory cap, command queue cap. Screenshots and response bodies are forwarded,
  never stored.
- Budget: routine verbs under a live grant are answered from memory, p95 under 1 ms per forwarded frame.
- Fail direction: relay failure closes the connection. It never falls through to an unproxied connection.
- The relay ships behind a flag, off by default. Managed mode is a separate opt-in setting.

### WebSocket implementation

The resident is synchronous and has no async runtime. Adding one for the relay would change the resident's failure
and resource model. Options to review before acceptance:

| Option | Notes |
| --- | --- |
| A small synchronous WebSocket library over `std::net` | Fits the resident model. Needs a dependency review: license, size, maintenance, `unsafe` use, frame-size limits, permessage-deflate handling (refuse it). |
| A minimal in-tree implementation of the RFC 6455 subset the relay needs | No new dependency. Needs fuzz tests for the frame parser and a review of masking, fragmentation and close handling. |
| An async library with its own runtime | Rejected unless the other two fail review: it adds a runtime to a process that has none. |

The accepted version of this record names the chosen option and links its dependency review.

## Consequences

Drivers that only speak the protocol become governable per message, and the page script set becomes available as a
fact for providers that answer `browser.script-integrity`.

The relay adds a long-lived listener and a per-frame decision path. It must meet the frame budget, and its soak and
latency evidence is part of the phase that ships it.

Open before acceptance: the WebSocket option, the exact caps, and how a hosted browser session that requires its own
authentication header is relayed without the relay ever storing that credential.
