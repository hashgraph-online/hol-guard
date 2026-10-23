# Rust dashboard handoff proof

The Rust dashboard HTTP service can replace the Python HTTP listener without taking the Python observer lease, changing its jobs, installing a VM controller, or enabling a PR gate. The command builds the image first, checks that port 8791 belongs to the saved Gauntlet instance, stops only the PID-file-bound Python server, starts the Rust container on loopback, and checks the same instance identity before recording Rust mode. The Docker project and image tag derive from the resolved state path, so an isolated state cannot replace or stop the active state's container. The reverse command stops the Rust container and starts the Python server from the same source bytes. An interrupted Rust startup attempts container cleanup and Python restart; a failed Python restore attempts to bring Rust back. The operator must reconcile either explicitly reported rollback failure before assuming service ownership.

Commands run from this branch:

```sh
PYTHONPATH=. .venv/bin/python -m ci.gauntlet.control_plane.cli \
  --state /Users/construct/Documents/projects/hol-guard-refinement/workflow-benchmark-implementation/.gauntlet-ops \
  dashboard-rust-up --docker-context colima

PYTHONPATH=. .venv/bin/python -m ci.gauntlet.control_plane.cli \
  --state /Users/construct/Documents/projects/hol-guard-refinement/workflow-benchmark-implementation/.gauntlet-ops \
  dashboard-rust-restore
```

On 2026-10-21/22, the same `dashboard-rust-up` command first built and launched an isolated state on port 8794. Its `/healthz` instance ID exactly matched that state's `public/dashboard-id.json`; `/api/status` correctly reported an unavailable collector because the isolated state had no snapshot. The live 8791 command then succeeded, with a successful Python restore and repeat Rust switch. The state-keyed build was exercised with both states running concurrently: each reported its own instance ID, and stopping the 8794 state left 8791 online. After each live handoff, `/healthz` reported the saved instance ID `82640901df6605bf42cb4b85ed740b34`, `server: online`, and `collector: online`; `/api/status` retained 26 visible jobs, observer PID 93818, zero active jobs, and `gate.required: false`. The Rust status response equaled the Python `snapshot()` projection of the same public files apart from the sampled `collector_age_seconds`. The Python server file in both checkouts had SHA-256 `2ef544c9bd6ef17d9f5cb01317a36b01b296e0ac3c0c1a4df0be0c1b0039f53e`. The observer PID remained alive and unchanged through both directions.

`tests.test_gauntlet_operations` includes build-before-stop, wrong-service health rollback, build-failure no-stop, failed Python-restore Rust restart, fixed Docker context and public mount, independent observer cases, and a simulated SIGTERM after the Python listener stops. The handoff turns one SIGTERM into a caught interruption, restores the previous service and then restores the prior signal handler; Ctrl+C follows the same rollback path. All 39 tests passed locally. Failure cases are controlled tests; the live proof exercised the normal reverse handoff, not a deliberately failed 8791 startup. The container mounts only the public snapshot tree and has no VM, provider, GitHub or job-writing capability. Rust observer ownership, model-backed qualification and gate activation remain separate unchecked migration exits.
