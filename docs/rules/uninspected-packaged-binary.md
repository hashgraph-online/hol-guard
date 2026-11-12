# Uninspected packaged binary

`UNINSPECTED_PACKAGED_BINARY` records a packaged executable that the scanner
recognized by its headers and did **not** read. It appears in the check
**Packaged binaries not inspected**, which is marked as not passed and carries no
points. It is **low** severity because it states a coverage gap, not a defect. The
gap is real: nothing was learned about what the executable does.

## What is skipped, and only that

A file is skipped only when all of these hold:

- it is larger than the 16 MiB per-file scan limit, so it could not be scanned as text;
- it is a regular file inside the plugin, not a symlink;
- its headers identify a Mach-O executable, dylib or bundle (thin or universal, 32 or
  64-bit, either byte order), the load commands parse exactly, and the segments and
  code-signature data declare continuous coverage of every byte of each slice.
  Universal slices may have zero-filled alignment padding of at most 64 KiB per gap;
  alignments above 64 KiB are conservatively rejected.

Recognition reads bounded headers and alignment padding and ignores the file name
and extension. Truncated or malformed headers, undeclared bytes after the image,
gaps within a slice, nonzero universal padding, and oversized text without recognized
headers still stop the scan with `SCAN_RESOURCE_BUDGET_EXCEEDED`. Header declarations
can be forged: text inside declared binary regions is not inspected either.

## What stays covered

Every other file is scanned as usual, so findings in scripts, source, manifests and
configuration remain visible. The per-file, total-byte, entry, depth, file-count and
symlink limits are unchanged, and at most 64 binaries may be skipped in one scan.
When binaries are skipped, the "No hardcoded secrets" message says so.

## What is not covered

The scanner makes no claim about a skipped binary: not that it is free of secrets,
malware or network behavior, not that it matches any source, and not that it is safe
because it is signed. A code-signature load command is reported as context only;
the signature and signer are not verified. Smaller binaries and executables in other
formats (ELF, PE, scripts without extensions) are read as text, as before.
Executables built by tools that append a payload after the Mach-O image are not
recognized, because the appended bytes cannot be accounted for.

## What to submit when a plugin bundles executables

1. Keep the source of the executable in the repository, or link the public repository
   and the exact tag or commit it was built from.
2. Document a reproducible build: toolchain versions and the commands that produce the
   file.
3. Publish a SHA-256 checksum for each shipped executable, and a provenance
   attestation (for example GitHub artifact attestations) where available.
4. Say how users can build and run the plugin without the bundled executable, if they
   prefer to.
5. Expect reviewers to treat the finding as open until a person has compared the
   artifact with its source or provenance. The scanner does not do that comparison.

There is no per-repository exemption and the size limit is not raised.

## Example: shipping signed per-platform executables

Keep `src/` (the TypeScript or other source) beside `binary/tool-darwin-arm64` and
`binary/tool-darwin-x64`, and add `docs/BUILD.md` with the build steps and checksums.
The scan reports each binary as uninspected, still scans `src/`, and the finding
points reviewers to the evidence above.
