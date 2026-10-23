# Read-only Rust status command proof

`gauntlet-status --state ABSOLUTE_STATE_DIRECTORY` reads only the existing public snapshot directory through the Rust dashboard's bounded no-symlink reader. It prints the same pretty JSON projection as Python `status`, including collector age and stale/unavailable handling. It does not read private jobs, own the observer lease, publish a snapshot, start a VM job or change the PR gate.

On 2026-10-21, the uninstalled native macOS Rust command and Python `ci.gauntlet.control_plane.server.snapshot` read the same live public directory seconds apart. Their parsed JSON values were identical after excluding only `collector_age_seconds`; both sampled ages rounded to 2.9 seconds, both reported `collector_status: online`, and both showed 26 jobs. The full `gauntlet-dashboard` test suite passed (four tests), as did warnings-denied native dashboard and ARM64 workspace Clippy.

This proves the read-only `status` projection on the current public snapshot. It does not port `up`, `doctor`, `hold`, `resume`, `down`, `reconcile` or `repair`, and it does not establish a Rust observer or controlled cutover.
