# Root-owned Native relay feasibility

The current PID-1 SDK tap child forwards Native MCP bytes and reports them
to Root. Root can reparse the report but cannot prove that the child actually
sent those bytes. A separate Linux ARM64 Root test exercised the proposed
next boundary: a short-lived UID/GID-10001 connector opened a real Unix
Native socket, passed the connected descriptor to Root through the existing
one-use `SCM_RIGHTS` reader, then exited. Root alone forwarded the SDK
request and Native response through that descriptor. The Native listener's
`SO_PEERCRED` reported the connector's original UID/GID and PID, while the
Root relay observed the exact two frames and one completed `tools/call`.
[Linux `unix(7)`](https://man7.org/linux/man-pages/man7/unix.7.html) specifies
that these peer credentials are fixed at connection time; the live test
confirmed that behavior on this VM after descriptor transfer and connector
exit.

The test binary SHA-256 was
`2a24b08e35dbc3fa8306133bae2d832fbe629e903ae5284154c69278d01e954d`.
The ignored Root test
`sdk_wire_fd_handoff::tests::root_can_forward_after_unprivileged_connector_exits_with_original_peer_credentials`
passed on the dedicated ARM64 VM. It checked one descriptor, the accepted
Native socket's UID/GID/PID, byte-identical request and result delivery, and
Root's two-frame observation. The guest test copy was removed after its
SHA-matched run.

This is a feasibility test, not a live Gauntlet route. The connector in this
test is an unprivileged Python process outside a private PID namespace; the
live staging tap still forwards from its PID-1 child. The subsequent
[Root PID-namespace relay probe](gauntlet-rust-root-pidns-relay-probe-proof.md)
uses a pinned PID-1 connector and checks both peers before each Root write.
Its journal/reader version and six-role candidate suite remain open. Even
that transport would not independently attribute Guard or product-side
physical effects. No eligibility or gate changed.
