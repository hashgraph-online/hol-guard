# Held Native frontdoor directory for the SDK tap

Code pin `cd6d3907` adds an ineligible Rust opener for the one-use staging
controller's existing `/home/hx-<run-id>/<role>/front` directory. It accepts
only a 16-hex run ID and a fixed staging role. It walks Root-owned directories
without symlinks, requires the state and role directories to be mode 0700,
the Native frontdoor to be Root-owned/group-10001 mode 0710, and both fixed
docs/mail sockets to be Root-owned/group-10001 mode 0660 with one link. It
holds the state, role and frontdoor descriptors, compares their visible
inodes and socket metadata before duplicating the frontdoor descriptor for
the future UID-10001 tap child, and refuses changed metadata.

The SHA-matched ARM64 VM test binary was
`b5185f18559aa6b5de478df379fe67f2389d92b6a6394e0f809d0e7292074e6b`,
Root-owned mode 0500 with one link. A Root-only test built a synthetic
controller state and real Unix docs/mail sockets, opened and duplicated the
fixed frontdoor, then changed the mail socket mode and observed refusal. The
explicit test passed; the full worker library suite passed 92 tests, with ten
intentional ignores and no failures. ARM64 warnings-denied Clippy, Rustfmt
and `git diff --check` passed. The guest transfer inbox was removed; free VM
disk was 8,676,966,400 bytes, above the 8-GiB floor.

This only pins socket files. The Rust staging worker has not yet waited for
the live Native frontdoor, passed its descriptor to the tap child, compared
the server's PID/start tick to the controller, or recorded SDK frames in a
terminal-bound journal. The test used synthetic sockets; it establishes no
live Guard effect or conformance eligibility.
