#!/usr/bin/env bash
set -euo pipefail

# HOL Guard DevContainer Feature
# Installs HOL Guard into a dev container for AI agent security

VERSION="${VERSION:-latest}"
INIT_HARNESS="${INITHARNESS:-auto}"
STRICT_MODE="${STRICTMODE:-false}"

echo "================================================"
echo "  HOL Guard DevContainer Feature"
echo "  https://hol.org/guard"
echo "================================================"

# Ensure Python is available
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: Python 3.10+ is required. Please install the Python feature first."
    echo "  Add to devcontainer.json: \"ghcr.io/devcontainers/features/python\""
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Detected Python: ${PY_VERSION}"

# Check minimum version (3.10+)
MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [ "$MAJOR" -lt 3 ] || { [ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 10 ]; }; then
    echo "ERROR: HOL Guard requires Python 3.10+. Found ${PY_VERSION}."
    exit 1
fi

# Validate VERSION to prevent shell injection via su -c.
# Allow "latest" or PEP 440 version specifiers: digits, dots, and
# pre/post/dev segments (e.g. 2.1, 2.0.1004, 2.0.1004.post1, 2.0.0a1,
# 2.0.0rc1). Reject shell metacharacters, spaces, or path separators.
if [ "$VERSION" != "latest" ]; then
    if ! echo "$VERSION" | grep -qE '^[0-9]+(\.[0-9]+)*((a|b|rc|c|\.post|\.dev)[0-9]*)?$'; then
        echo "ERROR: Invalid version '${VERSION}'. Use 'latest' or a PEP 440 version like '2.0.1004'."
        exit 1
    fi
fi

# Determine the target non-root user (devcontainer provides these env vars)
USERNAME="${_REMOTE_USER:-${_CONTAINER_USER:-auto}}"
if [ "${USERNAME}" = "auto" ] || [ "${USERNAME}" = "root" ]; then
    for u in vscode node codespace; do
        if id "$u" >/dev/null 2>&1; then
            USERNAME="$u"
            break
        fi
    done
fi
if [ "${USERNAME}" = "auto" ]; then
    USERNAME="root"
fi

# Resolve the user's home directory; never guess /home/root.
if [ "${USERNAME}" = "root" ]; then
    USER_HOME="/root"
else
    USER_HOME=$(getent passwd "${USERNAME}" 2>/dev/null | cut -d: -f6 || true)
    if [ -z "$USER_HOME" ]; then
        USER_HOME="/home/${USERNAME}"
    fi
fi
echo "Installing for user: ${USERNAME} (${USER_HOME})"

# Run a command as the target user. Uses exec for root (no shell overhead)
# and su for non-root. The command argument must be a pre-validated argv
# string — never interpolate untrusted input.
run_as_user() {
    if [ "${USERNAME}" = "root" ]; then
        "$@"
    else
        su "${USERNAME}" -c "$*"
    fi
}

# Check if a binary is available in the target user's PATH.
user_has() {
    if [ "${USERNAME}" = "root" ]; then
        command -v "$1" >/dev/null 2>&1
    else
        su "${USERNAME}" -c "command -v $1" >/dev/null 2>&1
    fi
}

# Install pipx if not present in the target user's PATH (PEP 668-safe).
if ! user_has pipx; then
    echo "Installing pipx..."
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update && apt-get install -y pipx
        apt-get clean && rm -rf /var/lib/apt/lists/*
    elif command -v apk >/dev/null 2>&1; then
        apk add pipx
        rm -rf /var/cache/apk/*
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y pipx
        dnf clean all
    else
        # Fallback: install into the user's site-packages.
        # --user lands in a writable directory for non-root users.
        # --break-system-packages bypasses PEP 668 (externally-managed-environment)
        # on distros where it applies. Both flags together are correct:
        # --user controls the install location, --break-system-packages
        # bypasses the externally-managed guard.
        run_as_user python3 -m pip install --user --break-system-packages pipx
    fi
fi

# Ensure pipx is in the user's PATH
run_as_user pipx ensurepath >/dev/null 2>&1 || true

# Determine pipx binary path
PIPX_BIN="pipx"
if ! user_has pipx; then
    PIPX_BIN="${USER_HOME}/.local/bin/pipx"
fi

# Install hol-guard (--force for idempotent re-runs)
if [ "$VERSION" = "latest" ]; then
    echo "Installing HOL Guard (latest)..."
    run_as_user "${PIPX_BIN}" install --force hol-guard
else
    echo "Installing HOL Guard v${VERSION}..."
    run_as_user "${PIPX_BIN}" install --force "hol-guard==${VERSION}"
fi

# Determine hol-guard binary path
GUARD_BIN="hol-guard"
if ! user_has hol-guard; then
    GUARD_BIN="${USER_HOME}/.local/bin/hol-guard"
fi

# Initialize for harness if requested.
# The Guard CLI auto-detects installed harnesses via `init --yes`.
# A specific harness name is informational only — it does not change
# the init command, since the CLI has no --harness flag. The harness
# will be configured automatically if it is installed in the container.
if [ "$INIT_HARNESS" != "none" ]; then
    echo ""
    echo "Initializing HOL Guard (harness: ${INIT_HARNESS})..."
    run_as_user "${GUARD_BIN}" init --yes

    if [ "$STRICT_MODE" = "true" ]; then
        echo "Enabling strict mode..."
        run_as_user "${GUARD_BIN}" settings set security-level strict
    fi
fi

echo ""
echo "HOL Guard installed successfully."
echo "  Docs: https://hol.org/guard"
echo "  CLI:  hol-guard --help"
echo "================================================"
