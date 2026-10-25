"""How long a harness gives one ``hol-guard-runtime resident-stop`` process."""

from __future__ import annotations

# The runtime bounds its shutdown and containment work by MANAGED_STOP_TIMEOUT
# (2 s, rust/crates/guard-runtime/src/managed_resident.rs), and a successful
# Unix stop can spend that whole bound waiting for the supervisor's last
# writes. A Windows stop then also waits up to SUPERVISOR_QUIESCE_TIMEOUT
# (5 s, managed_resident_exit.rs) for the supervisor to leave the scope.
# Process start and the runtime self-digest come before either bound, so a
# caller timeout equal to the runtime's bound kills healthy stops on slow
# runners. This outer bound still fails a stop that hangs.
RESIDENT_STOP_TIMEOUT_SECONDS = 10.0

__all__ = ["RESIDENT_STOP_TIMEOUT_SECONDS"]
