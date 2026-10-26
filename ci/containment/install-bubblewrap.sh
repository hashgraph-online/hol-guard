#!/usr/bin/env bash
# Install bubblewrap with overlay support (0.10 or newer) at /usr/bin/bwrap on
# an Ubuntu runner. The Linux workspace sandbox mounts an overlay over the
# workspace, and Ubuntu 24.04 ships bubblewrap 0.9, which has no --overlay, so
# the sandbox would report the host as unavailable and every command it would
# contain would fall back to review.
set -euo pipefail

version=0.11.0
sha256=988fd6b232dafa04b8b8198723efeaccdb3c6aa9c1c7936219d5791a8b7a8646
cache_dir="${BWRAP_BUILD_CACHE_DIR:-}"
if [[ -n "$cache_dir" ]]; then
  test ! -L "$cache_dir"
fi
if [[ "${BWRAP_BUILD_CACHE_HIT:-false}" == true ]]; then
  # Exact cache entries are immutable: do not silently rebuild an incomplete
  # hit that cannot subsequently be repaired under the same cache key.
  test -n "$cache_dir"
  test -f "$cache_dir/bwrap"
  test -f "$cache_dir/bwrap.sha256"
fi

if [[ -n "$cache_dir" && ( -e "$cache_dir/bwrap" || -L "$cache_dir/bwrap" ) ]]; then
  # The image/source-keyed cache is written only by trusted main builds.
  # Verify its contents before installing; corrupt entries must not pass CI.
  test -f "$cache_dir/bwrap" && test ! -L "$cache_dir/bwrap"
  test -f "$cache_dir/bwrap.sha256" && test ! -L "$cache_dir/bwrap.sha256"
  expected="$(<"$cache_dir/bwrap.sha256")"
  [[ "$expected" =~ ^[a-f0-9]{64}$ ]]
  actual="$(sha256sum "$cache_dir/bwrap")"
  test "${actual%% *}" = "$expected"
  test "$("$cache_dir/bwrap" --version)" = "bubblewrap $version"
  if ! command -v apparmor_parser >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends apparmor
  fi
  sudo install -m 0755 "$cache_dir/bwrap" /usr/bin/bwrap
else
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
  if [[ -n "$cache_dir" ]]; then
    mkdir -p "$cache_dir"
    install -m 0755 /usr/bin/bwrap "$cache_dir/bwrap"
    digest="$(sha256sum "$cache_dir/bwrap")"
    printf '%s\n' "${digest%% *}" > "$cache_dir/bwrap.sha256"
  fi
fi

sudo tee /etc/apparmor.d/hol-guard-bwrap <<'EOF'
abi <abi/4.0>,
include <tunables/global>
/usr/bin/bwrap flags=(unconfined) {
  userns,
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/hol-guard-bwrap
installed_version="$(/usr/bin/bwrap --version)"
test "$installed_version" = "bubblewrap $version"
printf '%s\n' "$installed_version"
help="$(/usr/bin/bwrap --help)"
grep -q -- '--overlay' <<< "$help"
