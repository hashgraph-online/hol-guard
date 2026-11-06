# Main-branch native extension verification

These are local Linux installed-wheel observations, not a cross-platform release
qualification. They use the implementation source checkpoint recorded by the
extension probe and the matching native rule digest. That checkpoint is a local
Git object, not a claim that the same commit is already published on GitHub.
The production runtime source and its compiled command program are captured by
the rule digest; hosted CI must separately test the final PR head.

The baseline is `main` at `05fa4760df8401b9710bf098adb4fbb2dc4ff389`.
The compiled catalog preserves its 70 extension IDs, 234 rule IDs and 247
permission IDs. Of those extensions, 61 own command rules, eight delegate
package inspection and one describes an MCP server. The native gate preserves
Package Firewall scanning rather than claiming a new Rust implementation of
all package/advisory services.

The installed candidate exercised 21 existing harness ingress paths, all using
the native resident with 21 persisted receipts. A separate 19-case probe covers
Ollama activation/deactivation, a disabled permission, safe-variant isolation,
restart persistence, each delegated package permission, MCP defaults and marker
tampering. It persisted all 19 native receipts with matching program/control
bindings. Test command strings were evaluated but never executed. The headless
authority fixture uses generated production keys; it does not test interactive
terminal enrollment.

The unchanged first-party catalog remains active on a genuinely never-enrolled
installation. That exception requires the initial zero-key epoch, zero local and
managed revisions, and no control layers. Once protected authority has existed,
a retained durable native floor rejects a return to initial defaults, including
after resident restart.

Python remains the reviewed contribution authoring format. The compiler rejects
unknown matcher types and serializes explicit operations. Hook-time command
matching, safe variants, control floors and evidence execute in Rust. The
checked CPython 3.12 / Unicode 15 differential corpus contains 546 cases. It is
not a claim of complete behavioral equivalence to every Python Unicode version.
Native intrinsic floors and unknown-command review are retained.
