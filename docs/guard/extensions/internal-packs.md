# Internal extension pack format

The offline `guard-command-source compile-packs` operation generates immutable
policy objects from the existing command and MCP sources and reviewed trust
bindings. It does not enable extensions or admit filesystem policy for execution.
Contributor schemas, public records, portable fixtures and commands are unchanged.

The input starts with `HGPS` and byte `01`. Each frame is a four-byte big-endian
length followed by that many bytes. A bounded header declares
`guard.command-pack-source-stream.v1` and the source count. Each source has one
metadata frame (`kind` and its single-extension trust map), then one original
source frame. The native strict decoder sees duplicates and depth before
normalization. Early EOF, surplus frames, unknown fields, missing trust, duplicate
IDs, invalid ownership, dependency cycles and missing relationships fail the build.
Global MCP endpoint/package/alias ownership and the complete native compatibility
inventory remain mandatory. Global checks run before object output.

Each pack owns one extension. Its bounded program is checked by the existing
native admission logic with the globally validated extension/permission interface.
Other extensions' matcher payloads are not copied into dependency packs. Global
relationships do not relax the per-source, per-program or matcher budgets.
Partial compatibility inventory validation is internal to per-pack admission;
an executable collection still requires the complete compatibility inventory.

Output is newline-delimited object records followed by one release root record.
Object records contain SHA-256, exact byte length and base64 data. Stored objects
are uncompressed and at most 64 KiB. Larger JSON values use bounded concatenation
trees; an assembled value is at most 8 MiB. Matcher nodes retain their existing
content identity and are stored independently so packs can share them. The program
skeleton, catalog metadata and public descriptors have separate references.

A pack manifest binds its extension ID, source digest, trust digest, native program
digest, engine implementation, semantic profile and related source interfaces.
An internal build key covers the validated source/trust input, conservative engine
identity, semantic profile and related interfaces. It does not replace public
contribution identity or grant authority to cached output.

The release root commits to a complete hash-trie index. Leaves contain at most
64 sorted unique entries; branches contain at most 16 non-overlapping SHA-256
prefixes. Adding a source changes its path rather than shifting subsequent pages.
Lookup verifies object length/digest, prefix routing, ordering and declared counts
on its path. Missing or corrupt data returns an error. The fixed format budgets
are recorded in `contracts/catalog-delivery/packs.v1.json`.

`scripts/build_native_command_packs.py` stages these outputs. It verifies emitted
object bytes, rejects poisoned cached objects, and atomically replaces the root
only after successful compiler completion. Interrupted builds may leave
unreferenced immutable objects. Every build still decodes all original sources
and validates global ownership and relationships.

The maintainer-only `guard-pack-compiler` builds the same native implementation
without an embedded catalog. The script builds this tool automatically when
`--compiler` is omitted. Contribution changes do not invalidate its Cargo inputs.
It cannot export or evaluate a packaged program.

For a sequence of builds, `PackCompilerSession` retains one native process. Each
request starts with an eight-byte big-endian stream length followed by the HGPS
stream; individual records keep their original limits. Object records and a
compilation-count record precede the unchanged release root. Closing stdin drops
the process and all cached values. Truncated or invalid requests end the session.
One request owns the entire build transaction. Concurrent use is rejected; a
failure closes the session so unread output cannot be consumed by a later build.

Only results compiled by that process may enter its cache. A hit requires the
current native source/trust/interface build key after global validation. The cache
retains at most 64 MiB of encoded projections; this is not a measurement of heap
use. Larger working sets compile normally with partial reuse. Storage reuse alone
does not prove compilation reuse.

Publication builds using `--reuse-current` can also reuse compiled IR across
fresh processes. The publisher first authenticates the selected release with
production Sigstore/TUF, then materializes its bounded Merkle index and policy
objects. A different engine starts a cold compilation. The native maintainer
operation `compile-packs-reuse <cache-directory> <authenticated-root-digest>`
checks the root bytes against the separately supplied digest and proves each
requested pack through that root. The digest must come from the verified
publication; a cache cannot supply its own authority. Supply a canonical cache
directory: symlinked paths are rejected, consistently with the existing stager.
The benchmark resolves its own temporary directory before passing it to native
code, including system temporary-directory aliases.

Every build still strictly decodes the current raw sources and validates all
global relationships before reuse. Native-computed source, trust, interface,
engine and semantic-profile keys select matching packs. Referenced objects,
catalog identities and native program admission are checked again. Changed
keys compile from current sources; corrupt proofs or matching-key payloads fail
closed. The one-shot path retains no compiled-IR cache between packs. The
publication build writes `compilation-report.json` with compiled/reused counts.

`scripts/benchmark_pack_compiler_reuse.py` compares cold and fresh-process
builds at 1x, 10x and 100x using valid unique source fixtures. It checks complete
byte-identical outputs for unchanged inputs and a single edit, and reports each
compiler process's elapsed time and peak RSS. Its locally generated unsigned
roots are benchmark inputs only, never authenticated publication or runtime proof.

Integrity is not publisher authority. A root must be bound to an authenticated
release before runtime use; an arbitrary directory or a matching hash alone is
insufficient. This offline format does not add a downloader or activation path.
The legacy aggregate compiler, release packaging and contribution commands remain
available while their consumers migrate.

Native collection construction can read a selected dependency closure through
`NativeCommandProgram::from_integrity_bound_packs`. The caller supplies exact root
bytes, a separately authenticated digest, selected IDs and a bounded object
fetcher. An explicit `PackAdmissionBudget` limits selected pack count, cumulative
serialized program bytes, and pre-interning rule/node counts. Programs are
admitted one at a time; the entire selected JSON inventory is never retained.
Only selected pack manifests and their referenced payloads are read.
Missing selected data, corrupt proofs, incompatible engines, duplicate owners,
incomplete dependencies and incomplete compatibility inventory return errors.
The collection also rechecks MCP executable ownership across selected packs.

The internal `combine_admitted_packs` composes native indexes directly and interns
shared matcher nodes by their verified content identity. Each pack keeps the
existing program bounds; the collection needs no aggregate program JSON. Its
identity binds the engine and ordered selected pack identities. Discovery roots
and unselected packs do not enter that identity. Fetching completes before the
collection can evaluate commands.

These constructors do not authenticate a publisher, authorize an extension,
persist controls or activate policy. The resident continues to use its packaged
program until the authenticated transactional activation path is implemented.
