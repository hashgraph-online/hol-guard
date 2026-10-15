#!/usr/bin/env bash
# Install bubblewrap with overlay support (0.10 or newer) at /usr/bin/bwrap on
# an Ubuntu runner. The Linux workspace sandbox mounts an overlay over the
# workspace, and Ubuntu 24.04 ships bubblewrap 0.9, which has no --overlay, so
# the sandbox would report the host as unavailable and every command it would
# contain would fall back to review.
set -euo pipefail

version=0.11.0
sha256=988fd6b232dafa04b8b8198723efeaccdb3c6aa9c1c7936219d5791a8b7a8646

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  apparmor libcap-dev meson ninja-build pkg-config

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/bubblewrap.tar.xz" \
  "https://github.com/containers/bubblewrap/releases/download/v${version}/bubblewrap-${version}.tar.xz"
echo "${sha256}  $work/bubblewrap.tar.xz" | sha256sum -c -
tar -xJf "$work/bubblewrap.tar.xz" -C "$work"
meson setup "$work/build" "$work/bubblewrap-${version}" \
  --prefix=/usr -Dman=disabled -Dtests=false -Dselinux=disabled \
  -Dbash_completion=disabled -Dzsh_completion=disabled
ninja -C "$work/build"
sudo ninja -C "$work/build" install

sudo tee /etc/apparmor.d/hol-guard-bwrap <<'EOF'
abi <abi/4.0>,
include <tunables/global>
/usr/bin/bwrap flags=(unconfined) {
  userns,
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/hol-guard-bwrap
/usr/bin/bwrap --version
