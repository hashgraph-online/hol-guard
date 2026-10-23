# Captured official Ubuntu OCI index digest; builds occur only in the owned VM.
FROM docker.io/library/ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-cryptography python3-jsonschema python3-referencing git ca-certificates && rm -rf /var/lib/apt/lists/*
COPY node /opt/node
RUN ln -s /opt/node/bin/node /usr/bin/node && ln -s /opt/node/bin/npm /usr/bin/npm && mkdir -p /candidate/project /candidate/source /candidate/home /candidate/npm-cache /trusted && chmod 1777 /candidate/home /candidate/npm-cache
ENV PYTHONPATH=/trusted/package
ENTRYPOINT ["/usr/bin/python3", "/trusted/probes/linux_worker_bootstrap.py"]
USER 65532:65532
