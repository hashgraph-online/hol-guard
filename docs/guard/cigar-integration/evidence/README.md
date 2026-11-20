# CIGAR evidence receipts

`receipts.json` is the only evidence file in this directory. Each entry names one captured run, its result, and `captured_record_sha256`, the SHA-256 of the original captured record. Top-level SHA-256 fields from that record are copied beside it. The raw record is not in git.

`logs` lists each removed log by filename, byte length, and SHA-256. Raw logs are not stored in this tree.

Dashboard checks read the observations under `dashboard/src/context-assistance/fixtures/`.
