# Owned-VM executor only; original agent/MCP image and production CI are unchanged.
# The local build context supplies the SHA-verified Bubblewrap 0.11.0 binary.
# Expected SHA256: a524f7613e4467041d3155c30df873d84766220b91f5aa373611eeea714a043a
FROM 827eaec482942aa5805beac1a75afd755b0daebade43024883b7d1637c27e52d
COPY bwrap /usr/bin/bwrap
USER 65532:65532
