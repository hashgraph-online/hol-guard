# Compile reviewed allocator policy only, as the disposable build UID.
FROM sha256:c7ff4bba9bca12e2c2ff9623e5a1678a7d4217c493016823b090556f9bddf05a AS compiler
USER 65532:65532
WORKDIR /tmp
COPY --chmod=0444 malloc_policy.c /tmp/malloc_policy.c
RUN ["/usr/bin/cc", "-shared", "-fPIC", "-O2", "-Wl,-z,relro,-z,now", "-o", "/tmp/libmalloc-policy.so", "/tmp/malloc_policy.c"]
FROM sha256:e43d3b4e594a7c2992ba184b330e0f1206fdc1b7d57c47d4dbff8d7d959dcfa1
COPY --from=compiler --chown=0:0 --chmod=0444 /tmp/libmalloc-policy.so /usr/lib/hol-gauntlet/libmalloc-policy.so
COPY --chown=0:0 --chmod=0444 malloc.preload /etc/ld.so.preload
