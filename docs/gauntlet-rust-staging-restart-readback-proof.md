# Rust staging tap restart readback

The fixed Linux ARM64 `gauntlet-staging-tap-restart-readback` is a read-only Root diagnostic for a completed Root-forwarded staging control. Under the exclusive staging lease, it reopens the keyed started marker, `invalid-evidence` terminal, canonical controller report and v2 SDK tap journal against nine outside run/source/config/worker/started/key/terminal/report/journal pins. It checks the report's Root-forwarded summary, original process identity and cleanup claim, then independently requires the one-use docs/mail socket directory to be an empty tombstone and the controller, tap and product-cell cgroups to be absent. It reopens the three retained byte sets after these checks before returning. Missing, changed or unfinished state exits 2 without retry or cleanup. Its positive state is `verified-ineligible-terminal`, never a Guard pass.

The paired macOS `gauntlet-host-staging-tap-restart-readback` reopens the fsynced prelaunch key pin and completed tap pin, calls only the SHA-named Root guest binary on the compiled Lima VM, bounds and parses one canonical response, compares every returned identity and hash with both host records, and rereads both records before returning. A fake-Lima test checked the exact argument vector; other host tests refused changed key, journal, cleanup, state, eligibility and replayed output.

The final optimized guest ELF SHA-256 was `37b5a2bfadbd3d9dd0b98ff3d4770cec16e6c35dc16904c8fdd6f3c99616c879` (844,968 bytes), identical on the Mac and VM, installed Root:Root mode 0500 with one link. The retained v5 host suite manifest for build `b70d59e2681c4a3f` matched its documented SHA-256 `5342eb9896519202b0329eca7aa9d166487e4a481ed934f60342561d48ad6437`. The fixed Mac command positively reconciled all six distinct retained role runs:

| Role | Run ID |
| --- | --- |
| success | `59f657ed0536d244` |
| input-binding | `98e8725a123c1eb2` |
| injection | `bf60214e33b06859` |
| boundary | `9230965c86a75e92` |
| timeout | `4a1595b46287deff` |
| cancel | `529608d2e640f37a` |

Each host response reported `verified-ineligible-terminal`, matched its durable host key and tap-pin hashes, and kept `execution_eligible:false`. A wrong tap journal hash exited 2 because it differed from the retained report. The earlier consumed run `0c83a264b4569830` exited 2 with “staging run has no complete terminal,” so a prelaunch interruption cannot be classified as complete. Targeted Linux ARM64 tests and warnings-denied Clippy passed; three Mac host tests and warnings-denied Clippy passed. The VM had 8,930,721,792 free bytes after deleting only the temporary transfer copies and superseded readers. The final optimized reader remains installed.

This verifies retained bytes and point-in-time post-restart absence under an already recorded host pin. It does not attest Lima or the VM independently, reconstruct lost process observations, repair uncertain cleanup, score Guard and product effects, create a conformance package, execute inference, or enable the PR gate. The Python observer and passive gate retain ownership.
