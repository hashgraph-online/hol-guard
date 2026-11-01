# CIGAR evidence receipts

`receipts.json` is the index of captured evidence. Each entry names one captured run, its result, and `captured_record_sha256`, the SHA-256 of the original captured record. Top-level SHA-256 fields from that record are copied beside it. The raw record is not in git, except for the two release qualification receipts described below.

`logs` lists each removed log by filename, byte length, and SHA-256. Raw logs are not stored in this tree.

`qualification/` holds the exact bytes of the two maintainer qualification receipts whose SHA-256 the bundled release catalog carries as `qualification_receipt_sha256`. They are stored unmodified (no trailing newline; `.gitattributes` pins line endings) because the catalog digest binds those bytes. They contain only run facts and temporary scratch paths, no user names or home directories. A Rust test in `guard-cigar-release` checks that each file hashes to the digest in the catalog.

Dashboard checks read the observations under `dashboard/src/context-assistance/fixtures/`.
