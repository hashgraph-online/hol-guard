# Full-task Gauntlet image: the agent and the policy gateway run from this one image.
# Everything is pinned: base images by digest, gh and Bun by checksum, Oh My Pi by the
# repository lockfile in ci/pi-exact-continuation. Guard itself is supplied at run time.
FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS node

FROM python:3.12-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
ARG TARGETARCH
ARG GH_VERSION=2.102.0
ARG GH_SHA256_AMD64=7e54a307f90afdc59796c325ec0c49fb09e6c18537727207a8ac7513584ea5b0
ARG GH_SHA256_ARM64=5006962696f01e1624b3fcf1f9d8e1a11547f24bf067dd2a0371b7b421945237
ARG BUN_VERSION=1.3.14
# The amd64 build uses the baseline Bun, which runs under emulation without AVX2.
ARG BUN_SHA256_AMD64=a063908ae08b7852ca10939bbdc6ceed3ddabce8fb9402dce83d65d73b36e6c7
ARG BUN_SHA256_ARM64=a27ffb63a8310375836e0d6f668ae17fa8d8d18b88c37c821c65331973a19a3b

# Bubblewrap runs Guard's Linux workspace containment. Its overlay mounts need
# bubblewrap 0.10 or newer, which is why the base is trixie rather than bookworm.
RUN apt-get update \
 && apt-get install -y --no-install-recommends bubblewrap ca-certificates curl git openssl unzip \
 && rm -rf /var/lib/apt/lists/*
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx
RUN case "${TARGETARCH}" in \
      amd64) GH_SHA256="${GH_SHA256_AMD64}"; BUN_SHA256="${BUN_SHA256_AMD64}"; BUN_ASSET=bun-linux-x64-baseline ;; \
      arm64) GH_SHA256="${GH_SHA256_ARM64}"; BUN_SHA256="${BUN_SHA256_ARM64}"; BUN_ASSET=bun-linux-aarch64 ;; \
      *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/gh.deb "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${TARGETARCH}.deb" \
 && echo "${GH_SHA256}  /tmp/gh.deb" | sha256sum -c - \
 && apt-get update && apt-get install -y --no-install-recommends /tmp/gh.deb \
 && rm -rf /tmp/gh.deb /var/lib/apt/lists/* \
 && curl -fsSL -o /tmp/bun.zip "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/${BUN_ASSET}.zip" \
 && echo "${BUN_SHA256}  /tmp/bun.zip" | sha256sum -c - \
 && unzip -q /tmp/bun.zip -d /tmp/bun \
 && install -m 0755 "/tmp/bun/${BUN_ASSET}/bun" /usr/local/bin/bun \
 && rm -rf /tmp/bun /tmp/bun.zip
COPY --from=pin package.json package-lock.json /opt/omp/
RUN cd /opt/omp && npm ci --no-audit --no-fund && chmod -R a+rX /opt/omp
COPY entrypoint.sh /opt/ft/entrypoint.sh
RUN chmod 0755 /opt/ft/entrypoint.sh \
 && useradd --uid 10001 --create-home --shell /bin/bash ft \
 && mkdir -p /work && chown ft /work
USER ft
WORKDIR /work
ENV PATH=/opt/omp/node_modules/.bin:/usr/local/bin:/usr/bin:/bin \
    GH_NO_UPDATE_NOTIFIER=1 GH_PROMPT_DISABLED=1 GH_TELEMETRY=false DO_NOT_TRACK=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
