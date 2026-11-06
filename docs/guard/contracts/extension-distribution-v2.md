# Extension distribution v2

Contributors keep the existing command/MCP JSON, public record, listing,
trust binding, portable fixtures and Builder commands. Maintainer publication
derives the delivery representations after merge.

The `guard.extension-distribution.v2` root binds a reviewed source commit,
native implementation digest, publication ID, validity interval, authority
epoch, complete policy index, default selection, revocation index and public
directory. Public directory entries and claim-invitation records use separate
bounded indexes. Reading this metadata does not download matcher programs or
enable an extension. External extensions remain opt-in.

Each root is an immutable GitHub release asset with a GitHub Actions Sigstore
bundle. Verification uses the production Sigstore/TUF trust implementation,
the repository and owner numeric identities, the publication workflow on
`refs/heads/main`, the exact source digest and the attested asset digest.
An object hash or JSON field cannot grant publisher authority. Metadata
expires after at most seven days. A scheduled publication can renew it using
a new publication ID without changing contribution sources.

The separate `extension-distribution-current` branch contains only
`extension-distribution-current.json`, an advisory pointer to an immutable
root and its digest. The publisher checks source ancestry and numeric
publication ordering, then advances the branch by fast-forward only. A
concurrent publication cannot overwrite a newer pointer. Clients still
authenticate the referenced root; branch contents alone grant no authority.

The native pack format keeps its 64 KiB object, 8 MiB assembled blob and
bounded index contracts. Public metadata objects have the same byte bounds.
Transfer containers group at most 256 members, with an 8 MiB metadata limit
or 32 MiB policy limit. They use stored ZIP members and bounded central
directories. Every selected member retains its own root-bound SHA-256 and
length. Containers carry bytes; they do not expand policy authority. A
maximal valid policy archive can remain a standalone 32 MiB asset.

The publisher validates the entire reachable graph against fresh native
compiler output and reviewed contribution inputs before uploading. Each new
container must contain exactly its bound public members. Existing immutable
locations can be reused after authenticating the prior root. The publisher
checks their availability without downloading all inactive policy; clients
verify each selected member before use. Public browsing downloads metadata
containers only. Transfer caching is untrusted and grants no activation
authority.

All data and compatibility assets finish publication before the root, and
the root finishes before its pointer advances. Released assets are never
overwritten. Separate publication attempts use separate immutable locations.
The original v1 budgets remain unchanged. Where the complete legacy
representation fits, publication continues to produce the existing archive
and claim metadata. A specifically identified representation limit produces
an authenticated `unsupported-oversize` status and a source-bound, attested
unavailability marker on the corresponding legacy release. That release
contains no partial catalog or fabricated legacy archive. Other compiler, ownership,
trust and integrity failures abort publication.

Renewals reuse the authenticated immutable legacy snapshot for the same source
commit. Mutable account display names can update in v2 metadata without
rewriting that snapshot. The publisher reports whether its root was selected.

The data-free maintainer compiler can also generate bounded legacy outputs.
Its native receipt binds the exact original source/trust stream hash and
length before Python stages those outputs. Legacy compilers retain their
embedded-output and trust-map checks. No serialized cache object is accepted
as a compiled program by this path.

These publication contracts do not themselves activate policy. Activation
must additionally authenticate its release, check engine compatibility,
revocations and device rollback state, admit the selected compiled closure,
and commit a complete authenticated policy snapshot. Command decisions must
perform no delivery network requests.
