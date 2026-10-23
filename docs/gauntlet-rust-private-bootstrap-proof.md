# Private bridge bootstrap parsing proof

Code pin `64471ed4` adds a bounded Rust reader for the initial private
length-prefixed bootstrap and a key-bearing parser for the VM and product-cell
frame dialects. The parser takes the local kernel boot ID and, for the VM
collector, the five expected Python source hashes from outside the incoming
bootstrap. It requires exact schema fields, canonical UUIDs, lowercase
32-byte key encoding, the correct role/boot relationship and the exact
outside source map. Duplicate-key and malformed JSON refuse before identity
use. The VM authentication fingerprint matches Python's one-way digest; no
error text includes the key. The parsed key can construct only the selected
frame dialect.

The Python-frozen synthetic fixture pins `vm_bridge_control.py` at SHA-256
`7565a4c0b3d763ba8bf5bb2d5ebbd0b2f6d804dee53dd2fdce2f4c1d34a05057`
and `product_cell_protocol.py` at
`3813d609e3b08f949747810c6fec46db5797a113d20fb87ac2f8c5654bdc021c`.
Four Rust tests passed on macOS and offline Linux ARM64 Rust 1.88. They cover
both VM roles, both cell roles, exact Python fingerprint, wrong boot/source/
key/fields, duplicate JSON, a real bounded socket read, oversized announced
length, truncation, deadline, cancellation and wrong descriptor. The full
macOS bridge crate suite, workspace Rustfmt, focused warnings-denied Clippy
and the Python fixture generator's Ruff check passed.

This is a synthetic bootstrap parser and private I/O primitive. A production
caller must authenticate the inherited descriptor, obtain an independently
observed kernel boot ID and reviewed source pins, generate and deliver a fresh
private key, and close the session on uncertain failure. It does not run a
collector, actor, model or Guard and grants no benchmark eligibility.

Code pin `8021a101` adds the outbound half. Rust now generates a fresh random
32-byte key and v4 session UUID, constructs the exact Python canonical
bootstrap bytes, validates them against the same outside pins, and consumes
the one-use object when delivering the length-prefixed body over a bounded
management descriptor. Invalid codec bounds refuse before any write; a
failed or partial write cannot retry the same object. Synthetic supplied
material matches Python's exact VM and cell bootstrap bytes. On macOS, two
new process tests delivered fresh Rust keys to the pinned Python VM collector
and product-cell actor over real Unix sockets, then completed an authenticated
`hello` RPC in each realm. The Rust 1.88 Linux ARM64 container passed the
non-Python tests; its Python-process tests skipped because that offline image
lacks Python. The isolated ARM64 CI job includes Python and runs them.

The live interop uses synthetic boot IDs and reviewed-in-test source hashes.
It does not attest a production child process, VM boot, executable, private
descriptor ancestry, or effect. Those are required before execution
admission or a benchmark verdict.
