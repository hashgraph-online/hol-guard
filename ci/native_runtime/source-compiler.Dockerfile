# Only the static native executable is present: no shell, Python or package tools.
FROM scratch
COPY guard-command-source /guard-command-source
USER 65534:65534
ENTRYPOINT ["/guard-command-source"]
