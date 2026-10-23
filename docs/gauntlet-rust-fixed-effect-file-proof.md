# Held provider-effect files against the Root event journal

On 2026-10-22, a new read-only Linux ARM64 Root diagnostic matched the two
fixed provider-control files from the retained `injection` run
`8c425d7e1a09f3b6` to its keyed close-write journal. The journal SHA-256
`c78241b27ca3c4e023a45b03f18b7d6d05e9cc028e34a3a6ec8921f5ba9b6052`
was already retained in a one-use macOS host pin. The diagnostic binary's
host, container and VM SHA-256 was
`b37d485f3167991972d8319117dc0113ad0b806cd16059f85cd7edc1adade584`.

The command requires outside source, deployment, worker, started-marker and
journal pins, plus a caller-supplied product-cgroup value. It reopens the Root-owned started marker
under the one-use lease and reads only the canonical journal matching the
outside digest. For either allowlisted provider surface, it opens the fixed
file with `openat2` beneath the exact run/role directory, refusing symlink
components. It requires physical UID 10001, mode 0600, one link and the
literal 24 bytes `idmapped provider effect`. It holds the descriptor while
matching device/inode and every captured writer row, then reopens the role
directory and file to refuse replacement. The result always says
`execution_eligible:false` and `guard_causality_verified:false`.

| Surface | Host device/inode | Final SHA-256 | Close-writes | Writer PID/start tick |
| --- | --- | --- | ---: | --- |
| `provider-remote` | `64769/3462343` | `59cae128f1e25176c5c65014eca5ecf8a6ad57360b867f2d5b22837ca4712d74` | 1 | `1403843/39595233` |
| `provider-home` | `64769/3462344` | `59cae128f1e25176c5c65014eca5ecf8a6ad57360b867f2d5b22837ca4712d74` | 1 | `1403843/39595233` |

Both writer rows named
`/holgauntletrust8c425d7e1a09f3b6.slice/hol-product-cell-20cc58e5720440edbe38a41e2192da30.service`.
A caller selected this cgroup from the same journal for the live trial; it
was **not independently pinned** to the product process. The result proves
only internal consistency for that cgroup field until an outside process
observation supplies it. The final diagnostic additionally requires the
service cgroup to have exactly one `hol-product-cell-<32 lowercase hex>.service`
component beneath the run-ID-derived Rust job slice; both fixed files passed
under that bound. An unrelated slice, wrong run ID, malformed unit or nested
child path refuses.
A wrong cgroup and a wrong outside journal digest each refused with exit 2.
The focused ARM64 test refused an unknown writer, a foreign writer, wrong
event owner, missing event, symlink and changed final bytes. Rust 1.88
warnings-denied ARM64 Clippy passed.

The same final binary checked both provider files in three other retained
runs. `input-binding` `cda32c146f28704b` and `success`
`1ec56d984caf72b0` each returned two ineligible held-file matches, one
known product-cell close-write per inode. The earlier `input-binding`
`b7d9daabcc785762` refused both files: each inode had two known
product-cell close-writes **and one unknown writer**, so the known writes
cannot erase the uncertainty. In total, six provider-file diagnostics
matched and two refused across the four retained runs. None can award a
control verdict.

The first live call intentionally refused because the fanotify file
descriptor reported UID 10004 through the product's idmapped mount while
the Root final path reported physical UID 10001. The revised diagnostic
requires exactly this fixed pair and the same device/inode, while explicitly
returning `idmap_kernel_verified:false`. The existing mount relation is a
data-only comparison of supplied observations; it does not independently
attest this run's live idmap. That proof, final-file correlations for the
other roles and surfaces, unknown-writer handling, deletion/replacement
observation, authenticated MCP-to-effect causality and Guard decisions remain
open. No control is scored and the PR gate remains passive.
